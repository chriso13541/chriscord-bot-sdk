package chriscordbot

// msgsig.go — who wrote a message (the same as the app's msgsig.go, up to
// its own message contents below: keep them in step).
//
// A channel's key is shared by everyone who may read it, so it can't say
// who wrote a message: anyone with it (a bot or plugin the channel was
// given to, say) could seal one claiming to be someone else. So each
// message also carries its writer's identity key (K) and their signature
// (S) over what it says. The app checks the signature, that the key is the
// one the writer is known by, and (on the signed member list) what they
// are — so a bot's or plugin's message is always marked as one, whatever
// the server says, and can't pass for a person's.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

const msgSigContext = "chriscord-e2ee-v1/msg-sig\x00"

// msgSigFile and msgSigPreview are what's signed of an attachment and a
// link preview.
type msgSigFile struct {
	URL, Name, Mime string
	Size            int64
	Key             string
	Spoiler, Gone   bool
}

// msgSigMessage is what a message's writer signs: the channel, the key
// generation, who they say they are, the text, its attachments (each one's
// file and key) and its link preview.
func msgSigMessage(board string, gen int, user, text string, files []msgSigFile, preview []string) []byte {
	var b strings.Builder
	b.WriteString(msgSigContext)
	for _, s := range []string{board, strconv.Itoa(gen), user, text, strconv.Itoa(len(files))} {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	for _, f := range files {
		for _, s := range []string{f.URL, f.Name, f.Mime, strconv.FormatInt(f.Size, 10), f.Key, strconv.FormatBool(f.Spoiler), strconv.FormatBool(f.Gone)} {
			b.WriteString(strconv.Itoa(len(s)))
			b.WriteByte(':')
			b.WriteString(s)
		}
	}
	b.WriteString(strconv.Itoa(len(preview)))
	for _, s := range preview {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	return []byte(b.String())
}

// msgSigCheck: whether sigHex is keyHex's signature over msg.
func msgSigCheck(keyHex, sigHex string, msg []byte) bool {
	k, err1 := hex.DecodeString(keyHex)
	s, err2 := hex.DecodeString(sigHex)
	return err1 == nil && err2 == nil && len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, s)
}

// ── The bot's message contents ───────────────────────────────────────────────

// msgSigFileJSON is an attachment as the app writes it (fileMeta).
type msgSigFileJSON struct {
	URL     string `json:"u"`
	Name    string `json:"n"`
	Mime    string `json:"m"`
	Size    int64  `json:"z"`
	Key     string `json:"k"`
	Spoiler bool   `json:"s,omitempty"`
	Missing bool   `json:"x,omitempty"`
}

// msgSigOf: what's signed of p's attachments and link preview (kept raw).
func msgSigOf(p textPlain) ([]msgSigFile, []string, bool) {
	var files []msgSigFile
	if len(p.A) > 0 {
		var fs []msgSigFileJSON
		if json.Unmarshal(p.A, &fs) != nil {
			return nil, nil, false
		}
		for _, f := range fs {
			files = append(files, msgSigFile{URL: f.URL, Name: f.Name, Mime: f.Mime, Size: f.Size, Key: f.Key, Spoiler: f.Spoiler, Gone: f.Missing})
		}
	}
	var preview []string
	if len(p.L) > 0 && string(p.L) != "null" {
		var l map[string]string
		if json.Unmarshal(p.L, &l) != nil {
			return nil, nil, false
		}
		preview = []string{l["u"], l["t"], l["d"], l["s"], l["k"], l["v"], l["i"]}
	}
	return files, preview, true
}

// signPlain signs p as written by this bot.
func signPlain(p *textPlain, board string, gen int, id textIdentity) {
	files, preview, _ := msgSigOf(*p)
	p.K = id.idHex
	p.S = hex.EncodeToString(ed25519.Sign(id.idPriv, msgSigMessage(board, gen, p.U, p.T, files, preview)))
}

// checkWriter: whether p's signature checks out — by the key it carries,
// that key the one the server lists its writer with in board. signed is
// false for an unsigned message (an app from before signatures, or someone
// with the channel's key writing as someone else).
func (t *textCrypto) checkWriter(board string, gen int, p textPlain) (signed, ok bool) {
	if p.S == "" || p.K == "" {
		return false, true
	}
	files, preview, readable := msgSigOf(p)
	if !readable || !msgSigCheck(p.K, p.S, msgSigMessage(board, gen, p.U, p.T, files, preview)) {
		return true, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if bk := t.boards[board]; bk != nil {
		for _, m := range bk.members {
			if m.Username == p.U && !strings.EqualFold(m.PublicKey, p.K) {
				return true, false
			}
		}
	}
	return true, true
}
