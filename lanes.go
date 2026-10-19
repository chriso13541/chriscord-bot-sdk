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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
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
// member list has it.
func (s *LaneSession) MayRead(board string) bool { return s.b.roster.allows(s.Key, board) }

// ── Announcements ────────────────────────────────────────────────────────────

const (
	announceKeep = 20             // per channel, for people who open a lane later
	announceFor  = 24 * time.Hour // and for this long
	announceMax  = 2000           // characters
)

type announcement struct {
	ID    string `json:"id"`
	Board string `json:"board"`
	Text  string `json:"text"`
	At    int64  `json:"at"` // unix milliseconds
}

func (a announcement) msg() map[string]interface{} {
	return map[string]interface{}{"t": "notice", "public": true, "id": a.ID, "board": a.Board, "text": a.Text, "at": a.At}
}

// Announce tells everyone who may read channel something (a plugin's
// "Now playing …"), on their lanes: their apps show it in that channel,
// marked as this plugin's, but it isn't a chat message — it's not in the
// channel's history, and the plugin needs no access to the channel at all.
// The last few per channel are kept for a day and shown to anyone who
// opens a lane later. On a server with a signed member list, "may read" is
// as the list has it.
func (b *Bot) Announce(channel, text string) error {
	if channel == "" || text == "" {
		return nil
	}
	if r := []rune(text); len(r) > announceMax {
		text = string(r[:announceMax])
	}
	var id [8]byte
	rand.Read(id[:])
	a := announcement{ID: hex.EncodeToString(id[:]), Board: channel, Text: text, At: time.Now().UnixMilli()}
	b.lanesMu.Lock()
	if b.announced == nil {
		b.announced = map[string][]announcement{}
	}
	list := append(b.announced[channel], a)
	if len(list) > announceKeep {
		list = list[len(list)-announceKeep:]
	}
	b.announced[channel] = list
	b.lanesMu.Unlock()
	var firstErr error
	for _, s := range b.LaneSessions() {
		if !s.MayRead(channel) {
			continue
		}
		if err := s.Send(a.msg()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// replayAnnouncements: the recent ones s may see, to a lane just opened.
func (b *Bot) replayAnnouncements(s *LaneSession) {
	cutoff := time.Now().Add(-announceFor).UnixMilli()
	b.lanesMu.Lock()
	var all []announcement
	for _, list := range b.announced {
		for _, a := range list {
			if a.At >= cutoff {
				all = append(all, a)
			}
		}
	}
	b.lanesMu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].At < all[j].At })
	for _, a := range all {
		if s.MayRead(a.Board) {
			s.Send(a.msg())
		}
	}
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
	go func() {
		b.replayAnnouncements(s)
		if f := b.OnLaneOpen; f != nil {
			f(s)
		}
	}()
}

// isMember: whether key is on the signed member list as a member.
func (s *rosterSync) isMember(key string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != rosterActive {
		return false
	}
	m, ok := s.r.Members[key]
	return ok && m.Kind == kindMember
}
