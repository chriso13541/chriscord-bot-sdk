package chriscordbot

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

// Someone joining the bot's call while it's playing gets its speaking ring
// (the server only passes on changes); not once it has stopped.
func TestSpeakingToNewcomers(t *testing.T) {
	maker, botKey := fixedKey(31), fixedKey(32)
	cert, _ := NewBotCert(maker, botKey.Public().(ed25519.PublicKey), "Music", "Plays music", 1)
	token, _ := EncodeBotToken(botKey, cert)
	testBotKey = cert.BotKey
	f := newFakeServer(t, testIdentity(33, "alice"))
	b, err := New(Options{Server: f.srv.URL, Token: token, Client: "testbot/1.0", Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)
	f.next(t, "presence")

	// In a call with alice, playing (as if JoinVoice and a track had started).
	b.mu.Lock()
	b.voiceBoard = "v"
	b.mu.Unlock()
	f.push(map[string]interface{}{"type": "voice_state", "channels": map[string][]string{"v": {"Music", "alice"}}})
	waitUntil(t, "alice in the call", func() bool { return len(b.OthersIn("v")) == 1 })
	b.SetSpeaking(true)
	f.next(t, "speaking")

	// alice leaves and comes back: she's told it's speaking.
	f.push(map[string]interface{}{"type": "voice_state", "channels": map[string][]string{"v": {"Music"}}})
	f.push(map[string]interface{}{"type": "voice_state", "channels": map[string][]string{"v": {"Music", "alice"}}})
	if m := f.next(t, "speaking"); m["speaking"] != true || m["board_id"] != "v" {
		t.Fatalf("got %v", m)
	}

	// Stopped: nobody new is told it's speaking.
	b.SetSpeaking(false)
	f.next(t, "speaking")
	f.push(map[string]interface{}{"type": "voice_state", "channels": map[string][]string{"v": {"Music", "alice", "bob"}}})
	deadline := time.After(2500 * time.Millisecond)
	for {
		select {
		case m := <-f.sent:
			if m["type"] == "speaking" {
				t.Fatalf("said it is speaking after stopping: %v", m)
			}
		case <-deadline:
			return
		}
	}
}
