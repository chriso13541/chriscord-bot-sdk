package chriscordbot

// lanes.go — a plugin's end of its lanes (lane.go): members' apps open one
// each, to send the plugin commands and clicks, and get its answers and
// panel back, end-to-end encrypted. The server only passes them along.
//
//	b.OnLaneOpen = func(s *chriscordbot.LaneSession) { s.Send(myPanel) }
//	b.OnLane = func(s *chriscordbot.LaneSession, msg json.RawMessage) { … s.Send(answer) }
//
// s.Key is the member's identity key (they signed the lane open with it),
// s.Name their name. On a server with a signed member list, only its
// members can open one, and s.MayRead(channel) says whether they may read
// a channel (a voice channel's panel, say).

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	laneIdle    = 2 * time.Hour // a lane nobody's used this long is forgotten
	laneMaxOpen = 2000
)

// LaneSession is one member's lane to this bot.
type LaneSession struct {
	b    *Bot
	ID   string
	Key  string // their identity key, hex
	Name string // their name on the server (they signed it; the server agrees)
	user string // their name on the server, where the server sends answers

	mu sync.Mutex
	k  *laneKeys
}

// Send seals v (as JSON) for this member alone, and sends it.
func (s *LaneSession) Send(v interface{}) error {
	plain, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	n, data := s.k.seal(laneFromPlugin, plain)
	s.mu.Unlock()
	return s.b.SendRaw(map[string]interface{}{"type": "plugin_lane", "to": s.user, "sid": s.ID, "n": n, "data": data})
}

// MayRead: whether this member may read board, as the server's signed
// member list has it (with no list: as the server says, from the channel's
// member list, looked at again after a minute).
func (s *LaneSession) MayRead(board string) bool {
	if s.b.roster.listed() {
		return s.b.roster.allows(s.Key, board)
	}
	return s.b.text.serverSays(s.Key, board)
}

// serverSays: whether the server lists key as a member of board.
func (t *textCrypto) serverSays(key, board string) bool {
	if board == "" {
		return true
	}
	t.mu.Lock()
	bk := t.boards[board]
	t.mu.Unlock()
	if bk == nil || time.Since(bk.fetchedAt) > time.Minute {
		var err error
		if bk, err = t.fetch(board); err != nil {
			return false
		}
	}
	for _, m := range bk.members {
		if strings.EqualFold(m.PublicKey, key) {
			return true
		}
	}
	return false
}

// LaneSessions: the lanes open now, oldest first.
func (b *Bot) LaneSessions() []*LaneSession {
	b.lanesMu.Lock()
	defer b.lanesMu.Unlock()
	out := make([]*LaneSession, 0, len(b.lanes))
	for _, s := range b.lanes {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].k.created.Before(out[j].k.created) })
	return out
}

type laneEvent struct {
	From string `json:"from"`
	SID  string `json:"sid"`
	N    uint64 `json:"n"`
	Eph  string `json:"eph"`
	Data string `json:"data"`
}

// onLane: a lane message from a member's app (the server's plugin_lane).
func (b *Bot) onLane(raw []byte) {
	var ev laneEvent
	if json.Unmarshal(raw, &ev) != nil || ev.From == "" || ev.SID == "" {
		return
	}
	if ev.Eph != "" && ev.N == 0 {
		b.laneHello(ev)
		return
	}
	b.lanesMu.Lock()
	s := b.lanes[ev.SID]
	b.lanesMu.Unlock()
	if s == nil {
		// Forgotten (this bot restarted, say): their app opens a new one.
		b.SendRaw(map[string]interface{}{"type": "plugin_lane_gone", "to": ev.From, "sid": ev.SID})
		return
	}
	s.mu.Lock()
	plain, err := s.k.open(laneToPlugin, ev.N, ev.Data)
	s.mu.Unlock()
	if err != nil {
		b.logf("chriscordbot: a lane message from %s: %v", s.Name, err)
		return
	}
	if f := b.OnLane; f != nil {
		go f(s, json.RawMessage(plain))
	}
}

func (b *Bot) laneHello(ev laneEvent) {
	encPriv := b.text.identity().encPriv
	k, h, err := laneAcceptAtPlugin(b.PublicKey(), encPriv, ev.Eph, ev.Data, time.Now())
	if err != nil {
		b.logf("chriscordbot: a lane from %s refused: %v", ev.From, err)
		b.SendRaw(map[string]interface{}{"type": "plugin_lane_gone", "to": ev.From, "sid": ev.SID})
		return
	}
	if k.SID != ev.SID {
		return
	}
	// The name they signed is the one the server says the lane is from
	// (otherwise one of them isn't telling the truth).
	if h.Name != ev.From {
		b.logf("chriscordbot: a lane from %s refused: it says it's from %s", ev.From, h.Name)
		b.SendRaw(map[string]interface{}{"type": "plugin_lane_gone", "to": ev.From, "sid": ev.SID})
		return
	}
	// On a server with a signed member list: its members only.
	if !b.roster.isMember(h.Key) {
		b.logf("chriscordbot: a lane from %s refused: not on the server's signed member list", h.Name)
		b.SendRaw(map[string]interface{}{"type": "plugin_lane_gone", "to": ev.From, "sid": ev.SID})
		return
	}
	s := &LaneSession{b: b, ID: k.SID, Key: h.Key, Name: h.Name, user: ev.From, k: k}
	b.lanesMu.Lock()
	if b.lanes == nil {
		b.lanes = map[string]*LaneSession{}
	}
	if b.lanes[s.ID] != nil {
		b.lanesMu.Unlock()
		return // the same hello again
	}
	now := time.Now()
	for id, o := range b.lanes {
		if now.Sub(o.k.used) > laneIdle {
			delete(b.lanes, id)
		}
	}
	if len(b.lanes) >= laneMaxOpen {
		var oldest *LaneSession
		for _, o := range b.lanes {
			if oldest == nil || o.k.used.Before(oldest.k.used) {
				oldest = o
			}
		}
		delete(b.lanes, oldest.ID)
	}
	b.lanes[s.ID] = s
	b.lanesMu.Unlock()
	if f := b.OnLaneOpen; f != nil {
		go f(s)
	}
}

// listed: whether the server has a signed member list (or might: while
// it's being checked, or when it doesn't check out).
func (s *rosterSync) listed() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state != rosterNone
}

// isMember: whether key is on the signed member list as a member (with no
// list: anyone the server lets in).
func (s *rosterSync) isMember(key string) bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case rosterNone:
		return true
	case rosterActive:
		m, ok := s.r.Members[key]
		return ok && m.Kind == kindMember
	}
	return false
}
