package chriscordbot

// rostersync.go — the server's signed member list (roster.go), as a bot
// follows it: who the bot may give channel keys and its call key to.
//
// A bot holds the keys to its channels, so it has to be as careful as the
// app about whom it shares them with. On a server with a signed member
// list, the bot only gives keys to people the list allows — whatever the
// server says — exactly like the app:
//
//   - new channel keys are sealed only for readers the list allows;
//   - keys newcomers are waiting for go only to people the list allows;
//   - the bot's call key goes only to listeners the list allows;
//   - someone losing access means a new key before the bot next posts.
//
// Until the list has been fetched and checked, the bot gives keys to
// nobody. Set Options.RosterFile so the bot remembers the list between
// runs: then a server that drops the list (or starts a different one) is
// noticed, and the bot keeps its keys to itself until you look into it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	rosterLoading  = "loading"
	rosterNone     = "none"
	rosterActive   = "active"
	rosterReplaced = "replaced"
)

type rosterPinFile struct {
	ID      string `json:"id"`
	Applied int    `json:"applied"`
	// Head: the list's head after those entries (first 16 characters), so
	// a list that was rolled back or altered isn't taken as the same one.
	Head string `json:"head,omitempty"`
	// Rotate: channels that need a new key because someone lost access
	// (kept, so a restart before the bot's next message doesn't forget).
	Rotate map[string]bool `json:"rotate,omitempty"`
}

type rosterSync struct {
	api     *api
	logf    func(string, ...interface{})
	pinPath string

	mu      sync.Mutex
	entries []RosterEntry
	lastSeq int64
	r       *Roster
	state   string
	pin     *rosterPinFile
	rotate  map[string]bool
	loading bool
	again   bool // a change arrived while loading: fetch once more after
}

func newRosterSync(a *api, pinPath string, logf func(string, ...interface{})) *rosterSync {
	s := &rosterSync{api: a, logf: logf, pinPath: pinPath, state: rosterLoading, rotate: map[string]bool{}}
	if pinPath != "" {
		data, err := os.ReadFile(pinPath)
		switch {
		case err == nil:
			var p rosterPinFile
			if err := json.Unmarshal(data, &p); err != nil {
				// Damaged (written by an older version that could be cut
				// off part-way): moved aside, not silently taken as "never
				// seen a list" and then written over.
				to := fmt.Sprintf("%s.corrupt-%s", pinPath, time.Now().Format("20060102-150405"))
				os.Rename(pinPath, to)
				logf("chriscordbot: WARNING: %s is damaged (%v) — moved to %s; the member list will be checked from scratch", pinPath, err, to)
			} else if p.ID != "" {
				s.pin = &p
				for b := range p.Rotate {
					s.rotate[b] = true
				}
			}
		case !os.IsNotExist(err):
			logf("chriscordbot: reading %s: %v", pinPath, err)
		}
	}
	return s
}

// savePin replaces the pin file in one go: written next to it, flushed,
// then renamed over it — a crash or SIGTERM part-way leaves the old one.
func (s *rosterSync) savePin() {
	if s.pinPath == "" || s.pin == nil {
		return
	}
	s.pin.Rotate = nil
	if len(s.rotate) > 0 {
		s.pin.Rotate = map[string]bool{}
		for b := range s.rotate {
			s.pin.Rotate[b] = true
		}
	}
	data, err := json.MarshalIndent(s.pin, "", "  ")
	if err == nil {
		err = writeFileAtomic(s.pinPath, data, 0600)
	}
	if err != nil {
		s.logf("chriscordbot: WARNING: remembering the member list (%s): %v", s.pinPath, err)
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if runtime.GOOS != "windows" {
		if d, err := os.Open(dir); err == nil {
			d.Sync()
			d.Close()
		}
	}
	return nil
}

type rosterResp struct {
	ID      string        `json:"id"`
	Entries []RosterEntry `json:"entries"`
	More    bool          `json:"more"`
}

// refresh fetches what's new in the list and works it in.
func (s *rosterSync) refresh() error {
	s.mu.Lock()
	if s.loading {
		// Already fetching — but that fetch may have started before this
		// change was stored, so the one running fetches again when done
		// (like the app's rosterClient). Dropping it left the bot on an
		// old list until the next change: a newly approved member got no
		// keys, and a removal wasn't noticed.
		s.again = true
		s.mu.Unlock()
		return nil
	}
	s.loading = true
	after, known := s.lastSeq, s.r
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.loading = false
		again := s.again
		s.again = false
		s.mu.Unlock()
		if again {
			if err := s.refresh(); err != nil {
				s.logf("chriscordbot: the signed member list: %v", err)
			}
		}
	}()

	var fresh []RosterEntry
	restart := false
	for page := 0; page < 100; page++ {
		var resp rosterResp
		if err := s.api.call("GET", fmt.Sprintf("/api/roster?after=%d", after), nil, &resp); err != nil {
			var h *HTTPError
			if !errors.As(err, &h) || h.Code != 404 {
				return err
			}
			resp = rosterResp{} // a server from before member lists
		}
		if known != nil && resp.ID != known.ID && !restart {
			restart, after, fresh, known = true, 0, nil, nil
			page = -1
			continue
		}
		fresh = append(fresh, resp.Entries...)
		if len(resp.Entries) > 0 {
			after = resp.Entries[len(resp.Entries)-1].Seq
		}
		if !resp.More {
			break
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if restart {
		s.entries, s.r = nil, nil
	}
	s.entries = append(s.entries, fresh...)
	s.lastSeq = after
	if len(s.entries) == 0 {
		s.r = nil
		if s.pin != nil {
			s.state = rosterReplaced
			s.logf("chriscordbot: WARNING: this server's signed member list is gone — giving keys to nobody (delete %s if the owner really started over)", s.pinPath)
		} else {
			s.state = rosterNone
		}
		return nil
	}
	if s.r == nil {
		k := len(s.entries)
		if s.pin != nil && s.pin.Applied > 0 && s.pin.Applied < k {
			k = s.pin.Applied
		}
		r, err := BuildRoster(s.entries[:k])
		if err != nil {
			s.state = rosterReplaced
			return fmt.Errorf("the member list doesn't check out: %w", err)
		}
		if s.pin != nil && s.pin.ID == r.ID && s.pin.Applied > 0 {
			// The same list has to hold what the bot already worked
			// through, the same way: fewer entries means the server lost
			// or is hiding some (a removal, say); another head, altered.
			why := ""
			switch {
			case s.pin.Applied > len(s.entries):
				why = fmt.Sprintf("is missing changes the bot had already seen (%d of %d)", len(s.entries), s.pin.Applied)
			case s.pin.Head != "" && headPrefix(r.Head) != s.pin.Head:
				why = "was altered since the bot last saw it"
			}
			if why != "" {
				s.entries, s.lastSeq, s.r = nil, 0, nil
				s.state = rosterReplaced
				s.logf("chriscordbot: WARNING: this server's signed member list %s — giving keys to nobody (delete %s if that's expected)", why, s.pinPath)
				return nil
			}
		}
		s.r = r
		s.applyLocked(s.entries[k:], s.pin != nil && s.pin.ID == r.ID)
	} else {
		s.applyLocked(fresh, true)
	}
	switch {
	case s.pin == nil:
		s.pin = &rosterPinFile{ID: s.r.ID}
		s.state = rosterActive
	case s.pin.ID != s.r.ID:
		s.state = rosterReplaced
		s.logf("chriscordbot: WARNING: this server's signed member list was started over — giving keys to nobody (delete %s if the owner really did)", s.pinPath)
		return nil
	default:
		s.state = rosterActive
	}
	s.pin.Applied = s.r.Applied + len(s.r.Rejected)
	s.pin.Head = headPrefix(s.r.Head)
	s.savePin()
	return nil
}

// applyLocked applies entries; with notice, a removal marks the channels it
// affects as needing a new key.
func (s *rosterSync) applyLocked(es []RosterEntry, notice bool) {
	r := s.r
	for _, e := range es {
		var losing []string
		if op, err := e.op(); err == nil && notice {
			switch op.Op {
			case opRemove:
				losing = append(r.Boards(), presenceKeyID)
			case opAccess:
				if all, _ := r.Access(op.Board); len(op.Remove) > 0 || (op.All != nil && !*op.All && all) {
					losing = []string{op.Board}
				}
			}
		}
		if err := r.Apply(e); err != nil {
			r.Rejected = append(r.Rejected, RosterRejected{Index: r.Applied + len(r.Rejected), Why: err.Error()})
			continue
		}
		for _, b := range losing {
			s.rotate[b] = true
		}
	}
}

// allows: whether key may be given board's keys. Only ever by the signed
// member list: on a server without one, nobody gets keys (the list is
// required, as in the app).
func (s *rosterSync) allows(key, board string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case rosterActive:
		if board == presenceKeyID {
			// Members and bots, never plugins (as in the app): a plugin
			// runs on the server's machine, so giving it the presence key
			// would hand everyone's status to whoever runs the server.
			m, ok := s.r.Members[key]
			return ok && m.Kind != kindPlugin
		}
		return s.r.CanRead(key, board)
	}
	return false
}

// allowsCall: whether key may be given this bot's call keys in board — a
// member (never a bot or plugin) the list lets into that channel.
func (s *rosterSync) allowsCall(key, board string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != rosterActive {
		return false
	}
	m, ok := s.r.Members[key]
	return ok && m.Kind == kindMember && s.r.CanRead(key, board)
}

func (s *rosterSync) needsNewKey(board string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotate[board]
}

func (s *rosterSync) madeNewKey(board string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.rotate[board] {
		delete(s.rotate, board)
		s.savePin()
	}
	s.mu.Unlock()
}

// RosterState says where the bot stands with the server's signed member
// list: "loading" (not checked yet: no keys to anyone), "none" (the server
// has none: keys go to whoever the server says), "active", or "replaced"
// (it was dropped or started over since the bot last saw it: no keys to
// anyone).
func (b *Bot) RosterState() string { return b.roster.State() }

// State: "loading", "none", "active" or "replaced".
func (s *rosterSync) State() string {
	if s == nil {
		return rosterNone
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// headPrefix: a list head as the pin keeps it (its first 16 characters).
func headPrefix(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
