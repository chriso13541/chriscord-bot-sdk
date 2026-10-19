package chriscordbot

// bot_test.go — the bot against a stand-in server: signing in with its
// certificate, publishing its key, encrypted chat both ways with a
// pretend member, keeping to the message limit, and reconnecting.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type fakeServer struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	nonces   map[string]string
	joins    []map[string]interface{}
	encKey   *textMember // the bot's, once published
	alice    textMember
	latest   map[string]int
	boxes    map[string]map[int]map[string]string // board → gen → recipient → box
	conns    []*websocket.Conn
	sent     chan map[string]interface{} // what the bot sends on its connection
	refuseWS bool
	roster   []RosterEntry // the signed member list (nil: the server has none)
	extra    []textMember  // members the server lists besides alice and the bot
}

func newFakeServer(t *testing.T, alice textIdentity) *fakeServer {
	f := &fakeServer{t: t, nonces: map[string]string{}, latest: map[string]int{}, boxes: map[string]map[int]map[string]string{}, sent: make(chan map[string]interface{}, 100)}
	enc := hex.EncodeToString(alice.encPub[:])
	sig := hex.EncodeToString(ed25519.Sign(alice.idPriv, encKeyMessage(alice.encPub[:])))
	f.alice = textMember{Username: "alice", PublicKey: alice.idHex, EncKey: &enc, Sig: &sig}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/challenge", f.challenge)
	mux.HandleFunc("POST /api/join", f.join)
	mux.HandleFunc("PUT /api/e2ee/enc-key", f.putEncKey)
	mux.HandleFunc("GET /api/boards/{b}/keys", f.getKeys)
	mux.HandleFunc("POST /api/boards/{b}/keys", f.postKeys)
	mux.HandleFunc("GET /api/e2ee/pending", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"pending":[]}`)) })
	mux.HandleFunc("GET /api/roster", f.getRoster)
	mux.HandleFunc("/ws", f.ws)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func out(w http.ResponseWriter, v interface{}) { json.NewEncoder(w).Encode(v) }

func (f *fakeServer) challenge(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PublicKey string `json:"public_key"`
	}
	json.NewDecoder(r.Body).Decode(&b)
	n := make([]byte, 32)
	rand.Read(n)
	f.mu.Lock()
	f.nonces[hex.EncodeToString(n)] = b.PublicKey
	f.mu.Unlock()
	out(w, map[string]string{"nonce": hex.EncodeToString(n)})
}

// join checks what the real server checks of a bot.
func (f *fakeServer) join(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username, Nonce, Signature, Client string
		PublicKey                          string   `json:"public_key"`
		Bot                                *BotCert `json:"bot"`
	}
	var m json.RawMessage
	json.NewDecoder(r.Body).Decode(&m)
	raw := map[string]interface{}{}
	json.Unmarshal(m, &b)
	json.Unmarshal(m, &raw)
	f.mu.Lock()
	want := f.nonces[b.Nonce]
	delete(f.nonces, b.Nonce)
	f.joins = append(f.joins, raw)
	f.mu.Unlock()
	pub, _ := hex.DecodeString(b.PublicKey)
	nonce, _ := hex.DecodeString(b.Nonce)
	sig, _ := hex.DecodeString(b.Signature)
	switch {
	case want == "" || want != b.PublicKey || len(pub) != 32 || !ed25519.Verify(pub, nonce, sig):
		w.WriteHeader(401)
		out(w, map[string]string{"error": "bad signature"})
	case b.Bot == nil || b.Bot.Check() != nil || b.Bot.BotKey != b.PublicKey:
		w.WriteHeader(401)
		out(w, map[string]string{"error": "bad certificate"})
	case b.Client == "":
		w.WriteHeader(400)
		out(w, map[string]string{"error": "say what you are"})
	default:
		out(w, map[string]interface{}{"token": "tok-" + b.Nonce[:8], "username": "Music", "encrypted_presence": true, "bot": true})
	}
}

func (f *fakeServer) putEncKey(w http.ResponseWriter, r *http.Request) {
	var b struct{ EncKey, Sig string }
	var m map[string]string
	json.NewDecoder(r.Body).Decode(&m)
	b.EncKey, b.Sig = m["enc_key"], m["sig"]
	f.mu.Lock()
	f.encKey = &textMember{Username: "Music", EncKey: &b.EncKey, Sig: &b.Sig}
	f.mu.Unlock()
	out(w, map[string]bool{"ok": true})
}

func (f *fakeServer) members(botKey string) []textMember {
	ms := append([]textMember{f.alice}, f.extra...)
	if f.encKey != nil {
		m := *f.encKey
		m.PublicKey = botKey
		ms = append(ms, m)
	}
	return ms
}

var testBotKey string

func (f *fakeServer) getKeys(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	type box struct {
		Generation int        `json:"generation"`
		Box        string     `json:"box"`
		Sender     textMember `json:"sender"`
	}
	var boxes []box
	members := f.members(testBotKey)
	board := r.PathValue("b")
	for g, byRecipient := range f.boxes[board] {
		if b, ok := byRecipient[testBotKey]; ok {
			boxes = append(boxes, box{g, b, members[len(members)-1]})
		}
	}
	out(w, map[string]interface{}{"latest": f.latest[board], "rotate": false, "boxes": boxes, "members": members})
}

func (f *fakeServer) postKeys(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Generation int `json:"generation"`
		Boxes      []struct{ Recipient, Box string }
	}
	json.NewDecoder(r.Body).Decode(&b)
	f.mu.Lock()
	defer f.mu.Unlock()
	board := r.PathValue("b")
	if b.Generation != f.latest[board]+1 {
		w.WriteHeader(409)
		out(w, map[string]string{"error": "conflict"})
		return
	}
	f.latest[board] = b.Generation
	if f.boxes[board] == nil {
		f.boxes[board] = map[int]map[string]string{}
	}
	f.boxes[board][b.Generation] = map[string]string{}
	for _, x := range b.Boxes {
		f.boxes[board][b.Generation][x.Recipient] = x.Box
	}
	out(w, map[string]bool{"ok": true})
}

func (f *fakeServer) ws(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	refuse := f.refuseWS
	f.mu.Unlock()
	if refuse || !strings.HasPrefix(r.URL.Query().Get("token"), "tok-") {
		http.Error(w, "no", 401)
		return
	}
	c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.conns = append(f.conns, c)
	f.mu.Unlock()
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		var m map[string]interface{}
		if json.Unmarshal(data, &m) == nil {
			f.sent <- m
		}
	}
}

func (f *fakeServer) push(v interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, _ := json.Marshal(v)
	c := f.conns[len(f.conns)-1]
	c.WriteMessage(websocket.TextMessage, data)
}

func (f *fakeServer) next(t *testing.T, typ string) map[string]interface{} {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case m := <-f.sent:
			if m["type"] == typ {
				return m
			}
		case <-deadline:
			t.Fatalf("no %q from the bot", typ)
		}
	}
}

func testIdentity(b byte, name string) textIdentity {
	k := fixedKey(b)
	id := textIdentity{idPriv: k, idHex: hex.EncodeToString(k.Public().(ed25519.PublicKey)), me: name}
	id.encPriv, id.encPub = encKeyFromSeed(k.Seed())
	return id
}

func TestBotChat(t *testing.T) {
	maker, botKey := fixedKey(11), fixedKey(12)
	cert, _ := NewBotCert(maker, botKey.Public().(ed25519.PublicKey), "Music", "Plays music", 1)
	token, _ := EncodeBotToken(botKey, cert)
	testBotKey = cert.BotKey
	alice := testIdentity(13, "alice")
	f := newFakeServer(t, alice)

	if _, err := New(Options{Server: f.srv.URL, Token: token}); err == nil {
		t.Fatal("no Client accepted")
	}
	if _, err := New(Options{Server: f.srv.URL, Token: "ccbot_1_nope", Client: "x/1"}); err == nil {
		t.Fatal("bad token accepted")
	}
	b, err := New(Options{Server: f.srv.URL, Token: token, Client: "testbot/1.0", Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *Message, 10)
	b.OnMessage = func(m *Message) { got <- m }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	// Signed in as a bot, saying what it is.
	f.next(t, "presence") // (its status goes out once it's connected and has keys)
	f.mu.Lock()
	j := f.joins[0]
	f.mu.Unlock()
	if j["client"] != "testbot/1.0 chriscordbot/"+Version || j["bot"] == nil || b.Username() != "Music" {
		t.Fatalf("join: %v / %q", j, b.Username())
	}

	// The bot says something: alice can read it with the key it gave her.
	if err := b.Send("general", "hello from the bot"); err != nil {
		t.Fatal(err)
	}
	m := f.next(t, "message")
	content := m["content"].(string)
	gen, blob, ok := parseText(content)
	if !ok {
		t.Fatalf("not encrypted: %q", content)
	}
	f.mu.Lock()
	box := f.boxes["general"][gen][alice.idHex]
	f.mu.Unlock()
	botEnc := textIdentity{}
	botEnc.encPriv, botEnc.encPub = encKeyFromSeed(botKey.Seed())
	key, err := openBox(alice, cert.BotKey, botEnc.encPub, "general", gen, box)
	if err != nil {
		t.Fatal("alice can't open her key:", err)
	}
	p, err := openText(key, "general", gen, blob)
	if err != nil || p.T != "hello from the bot" || p.U != "Music" {
		t.Fatalf("alice reads %+v %v", p, err)
	}

	// Alice says something: the bot gets it decrypted, and not its own.
	sealed, _ := sealPlain(key, "general", gen, textPlain{U: "alice", T: "!ping"})
	f.push(map[string]interface{}{"type": "message", "data": map[string]interface{}{"id": "m1", "board_id": "general", "username": "Music", "content": content}})
	f.push(map[string]interface{}{"type": "message", "data": map[string]interface{}{"id": "m2", "board_id": "general", "username": "alice", "content": sealed, "reply_to": "m1"}})
	select {
	case msg := <-got:
		if msg.Text != "!ping" || msg.Author != "alice" || msg.ID != "m2" || msg.ReplyTo != "m1" {
			t.Fatalf("got %+v", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("message not delivered")
	}
	// Someone claiming to be alice inside a message from bob is dropped.
	forged, _ := sealPlain(key, "general", gen, textPlain{U: "alice", T: "forged"})
	f.push(map[string]interface{}{"type": "message", "data": map[string]interface{}{"id": "m3", "board_id": "general", "username": "bob", "content": forged}})
	select {
	case msg := <-got:
		t.Fatalf("forged message delivered: %+v", msg)
	case <-time.After(300 * time.Millisecond):
	}

	// The message limit: the sixth within the window waits.
	messageWindow = 700 * time.Millisecond
	defer func() { messageWindow = 5 * time.Second }()
	start := time.Now()
	for i := 0; i < 6; i++ {
		if err := b.Send("general", "spam"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 6; i++ {
		f.next(t, "message")
	}
	if el := time.Since(start); el < 600*time.Millisecond {
		t.Fatalf("six messages in %v — no waiting", el)
	}

	// Dropped: it comes back after a second or more, and signs in again
	// when its session is refused.
	f.mu.Lock()
	f.refuseWS = true
	c := f.conns[len(f.conns)-1]
	f.mu.Unlock()
	dropped := time.Now()
	c.Close()
	time.Sleep(1500 * time.Millisecond)
	f.mu.Lock()
	f.refuseWS = false
	nConns := len(f.conns)
	f.mu.Unlock()
	if nConns != 1 {
		t.Fatalf("reconnected while refused: %d", nConns)
	}
	waitUntil(t, "reconnect", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return len(f.conns) == 2 })
	if el := time.Since(dropped); el < MinBackoff {
		t.Fatalf("reconnected after %v", el)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for " + what)
}

func (f *fakeServer) getRoster(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.roster == nil {
		w.WriteHeader(404)
		out(w, map[string]string{"error": "not found"})
		return
	}
	var after int64
	json.Unmarshal([]byte(r.URL.Query().Get("after")), &after)
	var es []RosterEntry
	for i, e := range f.roster {
		if int64(i+1) > after {
			e.Seq = int64(i + 1)
			es = append(es, e)
		}
	}
	id := ""
	if len(f.roster) > 0 {
		op, _ := f.roster[0].op()
		id = op.ID
	}
	out(w, map[string]interface{}{"id": id, "entries": es, "more": false})
}

// On a server with a signed member list, the bot gives keys only to the
// people it allows — not to someone the server slips in — and makes a new
// key once someone loses access.
func TestBotFollowsSignedList(t *testing.T) {
	maker, botKey := fixedKey(21), fixedKey(22)
	cert, _ := NewBotCert(maker, botKey.Public().(ed25519.PublicKey), "Music", "Plays music", 1)
	token, _ := EncodeBotToken(botKey, cert)
	testBotKey = cert.BotKey
	alice, eve, owner := testIdentity(23, "alice"), testIdentity(24, "eve"), testIdentity(25, "owner")
	f := newFakeServer(t, alice)
	enc := hex.EncodeToString(eve.encPub[:])
	sig := hex.EncodeToString(ed25519.Sign(eve.idPriv, encKeyMessage(eve.encPub[:])))
	f.extra = []textMember{{Username: "eve", PublicKey: eve.idHex, EncKey: &enc, Sig: &sig}}
	// The owner's list: alice and the bot read #general; eve isn't on it.
	start := newRosterOp("", owner.idHex, opStart)
	start.Policy = &RosterPolicy{Approvers: "owner", Need: "1"}
	start.Members = []RosterMember{{Key: alice.idHex, Kind: kindMember}, {Key: cert.BotKey, Kind: kindBot}}
	start.Access = []RosterAccess{{Board: "general", All: true, Readers: []string{cert.BotKey}}}
	e0, _ := makeRosterEntry(start, owner.idPriv)
	f.roster = []RosterEntry{e0}

	b, err := New(Options{Server: f.srv.URL, Token: token, Client: "testbot/1.0", Logf: t.Logf, RosterFile: t.TempDir() + "/roster.json"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)
	f.next(t, "presence")
	if st := b.RosterState(); st != rosterActive {
		t.Fatalf("state %q", st)
	}
	if err := b.Send("general", "hi"); err != nil {
		t.Fatal(err)
	}
	f.next(t, "message")
	f.mu.Lock()
	gen := f.latest["general"]
	got := f.boxes["general"][gen]
	f.mu.Unlock()
	if got[alice.idHex] == "" || got[cert.BotKey] == "" || got[eve.idHex] != "" {
		t.Fatalf("boxes went to %v", keysOf(got))
	}

	// The owner takes alice off #general: the bot's next message is under
	// a new key alice doesn't get.
	off := newRosterOp(start.ID, owner.idHex, opAccess)
	off.Board, off.All = "general", new(bool)
	e1, _ := makeRosterEntry(off, owner.idPriv)
	f.mu.Lock()
	f.roster = append(f.roster, e1)
	f.mu.Unlock()
	f.push(map[string]interface{}{"type": "roster_changed"})
	time.Sleep(500 * time.Millisecond)
	if err := b.Send("general", "after"); err != nil {
		t.Fatal(err)
	}
	f.next(t, "message")
	f.mu.Lock()
	gen2 := f.latest["general"]
	got = f.boxes["general"][gen2]
	f.mu.Unlock()
	if gen2 != gen+1 || got[alice.idHex] != "" || got[cert.BotKey] == "" {
		t.Fatalf("generation %d → %d, boxes %v", gen, gen2, keysOf(got))
	}

	// The server drops the list: the bot remembers it, and gives nobody keys.
	f.mu.Lock()
	f.roster = []RosterEntry{}
	f.mu.Unlock()
	f.push(map[string]interface{}{"type": "roster_changed"})
	time.Sleep(500 * time.Millisecond)
	if st := b.RosterState(); st != rosterReplaced || b.roster.allows(alice.idHex, presenceKeyID) {
		t.Fatalf("dropped list: state %q", st)
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k[:8])
	}
	return out
}
