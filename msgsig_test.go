package chriscordbot

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// A message's signature: made over what it says, checked against the key
// the server lists its writer with; a forged one isn't let through.
func TestMessageSignatures(t *testing.T) {
	alice, eve := testIdentity(61, "alice"), testIdentity(62, "eve")
	tc := newTextCrypto(nil, alice.idPriv, t.Logf)
	tc.setUsername("alice")
	key := make([]byte, 32)
	tc.boards["general"] = &boardKeys{keys: map[int][]byte{1: key}, latest: 1,
		members: []textMember{{Username: "alice", PublicKey: alice.idHex}, {Username: "eve", PublicKey: eve.idHex}}}

	p := textPlain{U: "alice", T: "hi", L: []byte(`{"u":"https://x.example","t":"X"}`)}
	signPlain(&p, "general", 1, tc.identity())
	sealed, _ := sealPlain(key, "general", 1, p)
	if text, signed, ok := tc.openSigned("general", "alice", sealed); !ok || !signed || text != "hi" {
		t.Fatalf("alice's own: %q %v %v", text, signed, ok)
	}
	// Changed after signing (another preview): no.
	q := p
	q.L = []byte(`{"u":"https://evil.example","t":"X"}`)
	sealed, _ = sealPlain(key, "general", 1, q)
	if _, _, ok := tc.openSigned("general", "alice", sealed); ok {
		t.Fatal("a changed message passed")
	}
	// Eve, writing as alice, signing with her own key: no.
	f := textPlain{U: "alice", T: "send me your password", K: eve.idHex}
	files, preview, _ := msgSigOf(f)
	f.S = hex.EncodeToString(ed25519.Sign(eve.idPriv, msgSigMessage("general", 1, f.U, f.T, files, preview)))
	sealed, _ = sealPlain(key, "general", 1, f)
	if _, _, ok := tc.openSigned("general", "alice", sealed); ok {
		t.Fatal("eve passed as alice")
	}
	// Unsigned: let through, but not as signed.
	sealed, _ = sealPlain(key, "general", 1, textPlain{U: "alice", T: "old app"})
	if _, signed, ok := tc.openSigned("general", "alice", sealed); !ok || signed {
		t.Fatalf("unsigned: %v %v", signed, ok)
	}
}
