package chriscordbot

// callkeys_test.go — the bot's call keys as members come and go from the
// signed member list, and the list itself staying current.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// callHarness is a bot's callCrypto with a recording transport, in a call
// in "voice" with alice.
type callHarness struct {
	t     *testing.T
	c     *callCrypto
	mu    sync.Mutex
	sent  []map[string]interface{}
	alice textIdentity
	aEph  [32]byte
	aPub  [32]byte
}

func newCallHarness(t *testing.T, s *rosterSync, alice textIdentity) *callHarness {
	h := &callHarness{t: t, alice: alice}
	bot := testIdentity(70, "Music")
	h.c = newCallCrypto(bot.idPriv, func(v interface{}) error {
		h.mu.Lock()
		h.sent = append(h.sent, v.(map[string]interface{}))
		h.mu.Unlock()
		return nil
	}, t.Logf)
	h.c.signed = s
	h.c.updateRoster(map[string][]string{"voice": {"Music", "alice"}})
	h.c.begin("voice", "Music")
	var err error
	h.aEph, h.aPub, err = newEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.c.end)
	return h
}

// hello delivers alice's hello to the bot.
func (h *callHarness) hello(reply bool) {
	sig := ed25519.Sign(h.alice.idPriv, helloMessage("voice", "alice", h.aPub[:]))
	m := map[string]interface{}{
		"board_id": "voice", "from": "alice", "from_key": h.alice.idHex,
		"data": map[string]interface{}{"t": "hello", "reply": reply,
			"eph": base64.StdEncoding.EncodeToString(h.aPub[:]), "sig": base64.StdEncoding.EncodeToString(sig)},
	}
	raw, _ := json.Marshal(m)
	h.c.handleMessage(raw)
}

// take returns and forgets what the bot has sent so far: (type, to, kid).
func (h *callHarness) take() (hellos []string, keys map[string][]uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	keys = map[string][]uint32{}
	for _, v := range h.sent {
		data := v["data"].(map[string]interface{})
		to, _ := v["to"].(string)
		switch data["t"] {
		case "hello":
			hellos = append(hellos, to)
		case "key":
			keys[to] = append(keys[to], data["kid"].(uint32))
		}
	}
	h.sent = nil
	return
}

func activeList(t *testing.T, owner textIdentity, members []RosterMember) (*rosterSync, []RosterEntry) {
	start := newRosterOp("", owner.idHex, opStart)
	start.Policy = &RosterPolicy{Approvers: "owner", Need: "1"}
	start.Members = members
	start.Access = []RosterAccess{{Board: "voice", All: true}}
	e0, err := makeRosterEntry(start, owner.idPriv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := BuildRoster([]RosterEntry{e0})
	if err != nil {
		t.Fatal(err)
	}
	return &rosterSync{state: rosterActive, r: r, rotate: map[string]bool{}, logf: t.Logf}, []RosterEntry{e0}
}

// Joining a call: the bot hasn't sent anything yet, so a member gets the
// key it's about to use straight away, not one that only takes over a
// second later (the first second of music went out on a key nobody had).
func TestCallKeyOnFirstJoin(t *testing.T) {
	owner, alice := testIdentity(71, "owner"), testIdentity(72, "alice")
	s, _ := activeList(t, owner, []RosterMember{{Key: alice.idHex, Kind: kindMember}})
	h := newCallHarness(t, s, alice)
	h.take() // the bot's hello to the call
	h.hello(true)
	_, keys := h.take()
	if got := keys["alice"]; len(got) != 1 || got[0] != 1 {
		t.Fatalf("alice got keys %v, want the current one (1) at once", got)
	}
	time.Sleep(rotateDebounce + 100*time.Millisecond)
	if _, keys := h.take(); len(keys) != 0 {
		t.Fatalf("no new key needed for a first join, sent %v", keys)
	}

	// Once the bot has played something, someone new gets a new key, never
	// the one in use before they came.
	h.c.seal(kindAudio, []byte{1, 2, 3})
	h.c.mu.Lock()
	unused := h.c.curUnusedLocked()
	h.c.mu.Unlock()
	if unused {
		t.Fatal("a key that has sealed a frame isn't unused")
	}
}

// Losing access to the channel in the signed list means a new call key
// that they don't get — not waiting for the next join or leave.
func TestCallKeyRotatesOnListChange(t *testing.T) {
	owner, alice := testIdentity(74, "owner"), testIdentity(75, "alice")
	s, _ := activeList(t, owner, []RosterMember{{Key: alice.idHex, Kind: kindMember}})
	h := newCallHarness(t, s, alice)
	h.hello(true)
	h.c.seal(kindAudio, []byte{1})
	time.Sleep(rotateDebounce + 100*time.Millisecond) // anything already on its way
	h.take()
	h.c.mu.Lock()
	before := h.c.lastKID
	h.c.mu.Unlock()

	// alice is taken off the list.
	rm := newRosterOp(s.r.ID, owner.idHex, opRemove)
	rm.Key = alice.idHex
	e, err := makeRosterEntry(rm, owner.idPriv)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.applyLocked([]RosterEntry{e}, true)
	s.mu.Unlock()
	if s.allowsCall(alice.idHex, "voice") {
		t.Fatal("alice should have lost access")
	}
	h.c.rosterChanged()
	time.Sleep(rotateDebounce + 100*time.Millisecond)
	h.c.mu.Lock()
	next := h.c.next
	h.c.mu.Unlock()
	if next == nil || next.kid != before+1 {
		t.Fatal("no new call key after alice lost access")
	}
	if _, keys := h.take(); len(keys["alice"]) != 0 {
		t.Fatalf("alice was given the new key %v after losing access", keys["alice"])
	}
}

// Members never give the bot their call key, so the bot mustn't keep
// chasing them for it: once alice's hello is in, no more hellos to her.
func TestBotResyncStopsOnceHelloIn(t *testing.T) {
	owner, alice := testIdentity(76, "owner"), testIdentity(77, "alice")
	s, _ := activeList(t, owner, []RosterMember{{Key: alice.idHex, Kind: kindMember}})
	h := newCallHarness(t, s, alice)
	h.hello(true)
	h.take()
	time.Sleep(2*resyncEvery + 200*time.Millisecond)
	if hellos, keys := h.take(); len(hellos) != 0 || len(keys) != 0 {
		t.Fatalf("resync kept going: hellos to %v, keys %v", hellos, keys)
	}
}

// A change that arrives while the list is being fetched isn't lost: the
// fetch that's running fetches again.
func TestRosterRefreshDuringRefresh(t *testing.T) {
	owner, alice := testIdentity(78, "owner"), testIdentity(79, "alice")
	_, entries := activeList(t, owner, nil)
	op0, _ := entries[0].op()
	add := newRosterOp(op0.ID, owner.idHex, opAdd)
	add.Key, add.Kind = alice.idHex, kindMember
	e1, err := makeRosterEntry(add, owner.idPriv)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	served := entries
	first := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		list := served
		mu.Unlock()
		if n == 1 {
			close(first)
			<-release // the list changes while this answer is on its way
		}
		var after int64
		json.Unmarshal([]byte(r.URL.Query().Get("after")), &after)
		var es []RosterEntry
		for i, e := range list {
			if int64(i+1) > after {
				e.Seq = int64(i + 1)
				es = append(es, e)
			}
		}
		out(w, map[string]interface{}{"id": op0.ID, "entries": es, "more": false})
	}))
	defer srv.Close()

	s := newRosterSync(newAPI(srv.URL, nil), "", t.Logf)
	done := make(chan error, 1)
	go func() { done <- s.refresh() }()
	<-first
	mu.Lock()
	served = append(append([]RosterEntry(nil), entries...), e1)
	mu.Unlock()
	if err := s.refresh(); err != nil { // roster_changed, while the first is running
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !s.allowsCall(alice.idHex, "voice") {
		t.Fatal("the change that came during a fetch was dropped: alice isn't on the bot's list")
	}
}

// Plugins never get the presence key (as in the app).
func TestPresenceKeyNotForPlugins(t *testing.T) {
	owner, alice, plug := testIdentity(80, "owner"), testIdentity(81, "alice"), testIdentity(82, "plug")
	s, _ := activeList(t, owner, []RosterMember{{Key: alice.idHex, Kind: kindMember}, {Key: plug.idHex, Kind: kindPlugin}})
	if !s.allows(alice.idHex, presenceKeyID) || s.allows(plug.idHex, presenceKeyID) {
		t.Fatal("presence key: members and bots, never plugins")
	}
}
