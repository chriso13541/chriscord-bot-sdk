package chriscordbot

// rosterpin_test.go — what the bot remembers of the signed member list
// between runs (Options.RosterFile): written whole or not at all, and a
// server that rolls the list back or alters it isn't trusted.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// listServer serves a member list that the test can change.
type listServer struct {
	mu      sync.Mutex
	id      string
	entries []RosterEntry
}

func (l *listServer) set(es []RosterEntry) { l.mu.Lock(); l.entries = es; l.mu.Unlock() }

func (l *listServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	list := l.entries
	l.mu.Unlock()
	var after int64
	json.Unmarshal([]byte(r.URL.Query().Get("after")), &after)
	var es []RosterEntry
	for i, e := range list {
		if int64(i+1) > after {
			e.Seq = int64(i + 1)
			es = append(es, e)
		}
	}
	out(w, map[string]interface{}{"id": l.id, "entries": es, "more": false})
}

func pinTestList(t *testing.T) (owner, alice textIdentity, entries []RosterEntry) {
	owner, alice = testIdentity(90, "owner"), testIdentity(91, "alice")
	_, start := activeList(t, owner, nil)
	op0, _ := start[0].op()
	add := newRosterOp(op0.ID, owner.idHex, opAdd)
	add.Key, add.Kind = alice.idHex, kindMember
	e1, err := makeRosterEntry(add, owner.idPriv)
	if err != nil {
		t.Fatal(err)
	}
	return owner, alice, append(start, e1)
}

// The bot saw two entries; after a restart the server has only the first
// (a removal hidden, a backup restored): no keys to anyone.
func TestRosterRollbackNoticed(t *testing.T) {
	_, alice, entries := pinTestList(t)
	op0, _ := entries[0].op()
	ls := &listServer{id: op0.ID, entries: entries}
	srv := httptest.NewServer(ls)
	defer srv.Close()
	pin := filepath.Join(t.TempDir(), "roster.json")

	s := newRosterSync(newAPI(srv.URL, nil), pin, t.Logf)
	if err := s.refresh(); err != nil || s.State() != rosterActive || !s.allowsCall(alice.idHex, "voice") {
		t.Fatalf("first run: %v %s", err, s.State())
	}
	ls.set(entries[:1])
	s = newRosterSync(newAPI(srv.URL, nil), pin, t.Logf) // restarted
	s.refresh()
	if s.State() != rosterReplaced {
		t.Fatalf("a rolled-back list was taken as %s", s.State())
	}
}

// A channel that needs a new key still does after a restart.
func TestRosterRotateSurvivesRestart(t *testing.T) {
	owner, alice, entries := pinTestList(t)
	op0, _ := entries[0].op()
	ls := &listServer{id: op0.ID, entries: entries}
	srv := httptest.NewServer(ls)
	defer srv.Close()
	pin := filepath.Join(t.TempDir(), "roster.json")
	s := newRosterSync(newAPI(srv.URL, nil), pin, t.Logf)
	if err := s.refresh(); err != nil {
		t.Fatal(err)
	}
	rm := newRosterOp(op0.ID, owner.idHex, opRemove)
	rm.Key = alice.idHex
	e2, _ := makeRosterEntry(rm, owner.idPriv)
	ls.set(append(append([]RosterEntry(nil), entries...), e2))
	if err := s.refresh(); err != nil || !s.needsNewKey("voice") {
		t.Fatalf("removal not noticed: %v", err)
	}
	s = newRosterSync(newAPI(srv.URL, nil), pin, t.Logf) // restarted before posting
	if !s.needsNewKey("voice") {
		t.Fatal("forgot the channel needs a new key")
	}
	s.madeNewKey("voice")
	s = newRosterSync(newAPI(srv.URL, nil), pin, t.Logf)
	if s.needsNewKey("voice") {
		t.Fatal("a new key was made, but it's still marked")
	}
}

// A damaged pin file is moved aside (not silently written over), and no
// temporary files are left behind by saving.
func TestRosterPinDamaged(t *testing.T) {
	_, _, entries := pinTestList(t)
	op0, _ := entries[0].op()
	srv := httptest.NewServer(&listServer{id: op0.ID, entries: entries})
	defer srv.Close()
	dir := t.TempDir()
	pin := filepath.Join(dir, "roster.json")
	os.WriteFile(pin, []byte(`{"id": "abc", "appl`), 0600) // cut off
	s := newRosterSync(newAPI(srv.URL, nil), pin, t.Logf)
	if err := s.refresh(); err != nil {
		t.Fatal(err)
	}
	names, _ := os.ReadDir(dir)
	var corrupt, tmp int
	for _, n := range names {
		switch {
		case strings.Contains(n.Name(), ".corrupt-"):
			corrupt++
		case strings.Contains(n.Name(), ".tmp-"):
			tmp++
		}
	}
	data, _ := os.ReadFile(pin)
	var p rosterPinFile
	if corrupt != 1 || tmp != 0 || json.Unmarshal(data, &p) != nil || p.ID != op0.ID || p.Head == "" {
		t.Fatalf("corrupt %d, tmp %d, pin %s", corrupt, tmp, data)
	}
}
