package chriscordbot

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The lane's own rules: both sides get the same keys, nothing opens out
// of place, a hello can't be redirected or forged.
func TestLaneCrypto(t *testing.T) {
	plugin, member, other := testIdentity(31, "Music"), testIdentity(32, "alice"), testIdentity(33, "eve")
	k, eph, hello, err := laneOpenFromApp(plugin.idHex, plugin.encPub, member.idPriv, "alice")
	if err != nil {
		t.Fatal(err)
	}
	pk, h, err := laneAcceptAtPlugin(plugin.idHex, plugin.encPriv, eph, hello, time.Now())
	if err != nil || h.Key != member.idHex || h.Name != "alice" || pk.SID != k.SID {
		t.Fatalf("accept: %v %+v", err, h)
	}
	// Another plugin can't open it; nor with the hello redirected to it.
	if _, _, err := laneAcceptAtPlugin(other.idHex, other.encPriv, eph, hello, time.Now()); err == nil {
		t.Fatal("another plugin opened the hello")
	}
	if _, _, err := laneAcceptAtPlugin(other.idHex, plugin.encPriv, eph, hello, time.Now()); err == nil {
		t.Fatal("a hello for one plugin was taken by another")
	}
	// Too old.
	if _, _, err := laneAcceptAtPlugin(plugin.idHex, plugin.encPriv, eph, hello, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("an hour-old hello")
	}
	// Both ways.
	n, data := k.seal(laneToPlugin, []byte(`{"t":"command"}`))
	if got, err := pk.open(laneToPlugin, n, data); err != nil || string(got) != `{"t":"command"}` {
		t.Fatalf("to the plugin: %s %v", got, err)
	}
	if _, err := pk.open(laneToPlugin, n, data); err == nil {
		t.Fatal("a replay opened")
	}
	n2, data2 := pk.seal(laneFromPlugin, []byte(`{"t":"panel"}`))
	if got, err := k.open(laneFromPlugin, n2, data2); err != nil || string(got) != `{"t":"panel"}` {
		t.Fatalf("from the plugin: %s %v", got, err)
	}
	// A message from the plugin sent back to it as if from the member: no.
	n3, data3 := pk.seal(laneFromPlugin, []byte(`x`))
	if _, err := pk.open(laneToPlugin, n3+10, data3); err == nil {
		t.Fatal("a reflected message opened")
	}
	// A forged hello: someone else's signature.
	k2, eph2, _, _ := laneOpenFromApp(plugin.idHex, plugin.encPub, other.idPriv, "eve")
	fake := laneHello{V: 1, Plugin: plugin.idHex, Key: member.idHex, Name: "alice", At: time.Now().Unix()}
	fake.Sig = hex.EncodeToString(ed25519.Sign(other.idPriv, laneHelloMessage(k2.SID, plugin.idHex, fake.At)))
	plain, _ := json.Marshal(fake)
	k2.sentN = 0
	_, forged := k2.seal(laneToPlugin, plain)
	if _, _, err := laneAcceptAtPlugin(plugin.idHex, plugin.encPriv, eph2, forged, time.Now()); err == nil {
		t.Fatal("a hello claiming to be alice, signed by eve")
	}
}

// A bot taking lanes from the server: opening one, answering on it, the
// server not knowing a lane, and (with a signed member list) members only.
func TestBotLanes(t *testing.T) {
	maker, botKey := fixedKey(41), fixedKey(42)
	cert, _ := NewBotCert(maker, botKey.Public().(ed25519.PublicKey), "Music", "Plays music", 1)
	token, _ := EncodeBotToken(botKey, cert)
	testBotKey = cert.BotKey
	alice := testIdentity(43, "alice")
	f := newFakeServer(t, alice)
	b, err := New(Options{Server: f.srv.URL, Token: token, Client: "testbot/1.0", Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 10)
	b.OnLaneOpen = func(s *LaneSession) { s.Send(map[string]string{"t": "welcome", "to": s.Name}) }
	b.OnLane = func(s *LaneSession, m json.RawMessage) {
		got <- string(m)
		s.Send(map[string]string{"t": "reply"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)
	f.next(t, "presence")
	botEnc := testIdentity(42, "")
	k, eph, hello, err := laneOpenFromApp(cert.BotKey, botEnc.encPub, alice.idPriv, "alice")
	if err != nil {
		t.Fatal(err)
	}
	f.push(map[string]interface{}{"type": "plugin_lane", "from": "alice", "sid": k.SID, "n": 0, "eph": eph, "data": hello})
	m := f.next(t, "plugin_lane")
	if m["to"] != "alice" || m["sid"] != k.SID {
		t.Fatalf("answer: %v", m)
	}
	plain, err := k.open(laneFromPlugin, uint64(m["n"].(float64)), m["data"].(string))
	if err != nil || !strings.Contains(string(plain), `"welcome"`) {
		t.Fatalf("welcome: %s %v", plain, err)
	}
	n, data := k.seal(laneToPlugin, []byte(`{"t":"command","command":"play"}`))
	f.push(map[string]interface{}{"type": "plugin_lane", "from": "alice", "sid": k.SID, "n": n, "data": data})
	select {
	case s := <-got:
		if s != `{"t":"command","command":"play"}` {
			t.Fatalf("got %s", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the command didn't arrive")
	}
	m = f.next(t, "plugin_lane")
	if plain, err := k.open(laneFromPlugin, uint64(m["n"].(float64)), m["data"].(string)); err != nil || string(plain) != `{"t":"reply"}` {
		t.Fatalf("reply: %s %v", plain, err)
	}
	// The same command again (replayed by the server): ignored.
	f.push(map[string]interface{}{"type": "plugin_lane", "from": "alice", "sid": k.SID, "n": n, "data": data})
	select {
	case s := <-got:
		t.Fatalf("a replay was delivered: %s", s)
	case <-time.After(400 * time.Millisecond):
	}
	// A lane it doesn't know: it says so.
	f.push(map[string]interface{}{"type": "plugin_lane", "from": "alice", "sid": strings.Repeat("ab", 16), "n": 3, "data": data})
	if m := f.next(t, "plugin_lane_gone"); m["sid"] != strings.Repeat("ab", 16) || m["to"] != "alice" {
		t.Fatalf("gone: %v", m)
	}
	if len(b.LaneSessions()) != 1 || b.LaneSessions()[0].Key != alice.idHex {
		t.Fatal("one lane, alice's")
	}
	// An announcement: to alice (she may read #general), not to #secret.
	b.Announce("secret", "not for alice")
	b.Announce("general", "Now playing: something")
	m = f.next(t, "plugin_lane")
	if plain, err := k.open(laneFromPlugin, uint64(m["n"].(float64)), m["data"].(string)); err != nil ||
		!strings.Contains(string(plain), `"public":true`) || !strings.Contains(string(plain), "Now playing") {
		t.Fatalf("announcement: %s %v", plain, err)
	}
	// A lane opened later gets it too.
	k2, eph2, hello2, _ := laneOpenFromApp(cert.BotKey, botEnc.encPub, alice.idPriv, "alice")
	f.push(map[string]interface{}{"type": "plugin_lane", "from": "alice", "sid": k2.SID, "n": 0, "eph": eph2, "data": hello2})
	for i := 0; i < 2; i++ { // the announcement and the welcome
		m = f.next(t, "plugin_lane")
		plain, err := k2.open(laneFromPlugin, uint64(m["n"].(float64)), m["data"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && !strings.Contains(string(plain), "Now playing") {
			t.Fatalf("replayed: %s", plain)
		}
	}

	// With a signed member list that doesn't have eve: her lane is refused.
	owner, eve := testIdentity(44, "owner"), testIdentity(45, "eve")
	start := newRosterOp("", owner.idHex, opStart)
	start.Policy = &RosterPolicy{Approvers: "owner", Need: "1"}
	start.Members = []RosterMember{{Key: alice.idHex, Kind: kindMember}, {Key: cert.BotKey, Kind: kindPlugin}}
	e0, _ := makeRosterEntry(start, owner.idPriv)
	f.mu.Lock()
	f.roster = []RosterEntry{e0}
	f.mu.Unlock()
	f.push(map[string]interface{}{"type": "roster_changed"})
	time.Sleep(400 * time.Millisecond)
	ke, ephE, helloE, _ := laneOpenFromApp(cert.BotKey, botEnc.encPub, eve.idPriv, "eve")
	f.push(map[string]interface{}{"type": "plugin_lane", "from": "eve", "sid": ke.SID, "n": 0, "eph": ephE, "data": helloE})
	if m := f.next(t, "plugin_lane_gone"); m["to"] != "eve" {
		t.Fatalf("eve: %v", m)
	}
	if len(b.LaneSessions()) != 2 {
		t.Fatal("eve's lane shouldn't be open")
	}
}
