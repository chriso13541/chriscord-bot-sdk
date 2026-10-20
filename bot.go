// Package chriscordbot is for writing bots for Chriscord servers.
//
// A bot is made in the Chriscord app (Settings → Bots → New bot), which
// gives its token (ccbot_1_…) and its "Add to server" link. Someone with
// Manage Bots on a server adds it from the link and picks which channels
// it sees. Then:
//
//	b, err := chriscordbot.New(chriscordbot.Options{
//		Server: "https://chat.example.com",
//		Token:  os.Getenv("CHRISCORD_BOT_TOKEN"),
//		Client: "echobot/1.0",
//	})
//	b.OnMessage = func(m *chriscordbot.Message) {
//		if m.Text == "!ping" {
//			b.Send(m.Channel, "pong")
//		}
//	}
//	b.Run(context.Background())
//
// The package takes care of everything the Bot Rules ask of a bot: it signs
// in with the bot's certificate, publishes its encryption key, reads and
// sends end-to-end encrypted messages, takes part in a call's key exchange
// before sending any sound, keeps to the rate limits, answers pings, and
// reconnects with a growing wait.
package chriscordbot

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Version of this package, sent along with the bot's own when it joins.
const Version = "0.2.1"

// Options for New.
type Options struct {
	// Server is the Chriscord server's address, e.g. https://chat.example.com
	// or 192.168.1.10:7070 (http:// is assumed without a scheme).
	Server string
	// Token is the bot's token from the app (ccbot_1_…). Keep it secret.
	Token string
	// Client says what the bot is: its name and version, e.g.
	// "chriscord-musicbot/0.5.0". Required.
	Client string
	// Logf receives the package's log lines (default: the log package).
	Logf func(format string, args ...interface{})
	// HTTPClient for the server's API (default: 30 second timeout).
	HTTPClient *http.Client
	// RosterFile: where the bot remembers the server's signed member list
	// (rostersync.go) between runs, so a server that drops it or starts a
	// different one is noticed. Recommended; without it the bot trusts the
	// first list it sees after each start.
	RosterFile string
}

// Message is a chat message the bot can see, already decrypted.
type Message struct {
	ID      string
	Channel string // board id
	Author  string // their username
	Text    string
	ReplyTo string // the message it answers, if any
	// Seq counts messages in the order they arrived. Handlers run side by
	// side, so a bot that must act on them strictly in order can use it.
	Seq uint64
	// Signed: its writer signed it (with the key the server lists them
	// with). An unsigned one came from an older app — or from someone else
	// who can read the channel, writing as Author.
	Signed bool
}

// Event is anything the server sends, for what the package doesn't cover.
type Event struct {
	Type string
	Raw  json.RawMessage
}

// Bot is one bot's connection to one server.
type Bot struct {
	// Handlers. Set them before Run. Each runs on its own goroutine.

	// OnMessage gets every message the bot can read in its channels
	// (not its own, and not system messages).
	OnMessage func(m *Message)
	// OnConnect runs after each sign-in and connection.
	OnConnect func()
	// OnVoiceState gets who's in which voice channel (board id →
	// usernames), whenever it changes. Only the channels the bot can see.
	OnVoiceState func(channels map[string][]string)
	// OnCallReady: the bot's call connection is up and it can send sound.
	OnCallReady func(channel string)
	// OnCallEnded: the bot was taken out of a call it didn't leave itself
	// (removed by a moderator, lost access, or everyone had gone while it
	// was reconnecting).
	OnCallEnded func(channel, reason string)
	// OnVideoKeyframe: someone started watching the bot's picture (or lost
	// it): the next frame should be a keyframe (video.go).
	OnVideoKeyframe func()
	// OnDenied: the server refused something the bot did, saying why.
	OnDenied func(message string)
	// OnEvent gets every event from the server, including the ones above.
	OnEvent func(e Event)
	// OnLaneOpen: a member's app opened an end-to-end encrypted lane to
	// this bot (lanes.go) — a plugin's commands, clicks and panel.
	OnLaneOpen func(s *LaneSession)
	// OnLane: a message on one of those lanes, decrypted.
	OnLane func(s *LaneSession, msg json.RawMessage)

	lanesMu   sync.Mutex
	announced map[string][]announcement // by channel (lanes.go)
	lanes     map[string]*LaneSession

	server string
	client string
	key    ed25519.PrivateKey
	cert   *BotCert
	logf   func(string, ...interface{})
	api    *api
	text   *textCrypto
	call   *callCrypto
	status *botStatus
	roster *rosterSync
	limit  *channelLimiter
	turns  *turns

	wsMu sync.Mutex
	ws   *websocket.Conn

	mu         sync.Mutex
	me         string
	seq        uint64
	channels   map[string][]string // voice_state: board → who's in it
	voiceBoard string              // the voice channel the bot is in ("" = none)
	// its picture in the call (video.go)
	videoOn          bool
	videoH, videoFPS int
	voice            *voiceSession
	rejoin           bool      // after a reconnect: get back into voiceBoard
	speaking         bool      // SetSpeaking(true) last: said again to anyone joining the call
	restartAt        time.Time // last call connection rebuild
	pfp              []byte
	pfpAt            int64
}

// New checks the token and makes the bot (it doesn't connect until Run).
func New(o Options) (*Bot, error) {
	key, cert, err := ParseBotToken(o.Token)
	if err != nil {
		return nil, err
	}
	client := strings.TrimSpace(o.Client)
	if client == "" {
		return nil, errors.New("Options.Client is required: the bot's name and version, e.g. \"mybot/1.0\"")
	}
	server := strings.TrimRight(strings.TrimSpace(o.Server), "/")
	if server == "" {
		return nil, errors.New("Options.Server is required")
	}
	if !strings.Contains(server, "://") {
		server = "http://" + server
	}
	logf := o.Logf
	if logf == nil {
		logf = log.Printf
	}
	b := &Bot{server: server, client: client + " chriscordbot/" + Version, key: key, cert: cert, logf: logf, channels: map[string][]string{}}
	b.api = newAPI(server, o.HTTPClient)
	b.text = newTextCrypto(b.api, key, logf)
	b.call = newCallCrypto(key, b.sendJSON, logf)
	b.roster = newRosterSync(b.api, o.RosterFile, logf)
	b.text.roster, b.call.signed = b.roster, b.roster
	b.status = newBotStatus(b)
	b.limit = newChannelLimiter()
	b.turns = newTurns()
	return b, nil
}

// Name is the bot's name in its certificate.
func (b *Bot) Name() string { return b.cert.Name }

// PublicKey is the bot's key (hex).
func (b *Bot) PublicKey() string { return b.cert.BotKey }

// Cert is the bot's certificate.
func (b *Bot) Cert() BotCert { return *b.cert }

// Username is what the bot is called on the server ("" until signed in).
func (b *Bot) Username() string { b.mu.Lock(); defer b.mu.Unlock(); return b.me }

// API calls the server's HTTP API as the bot (for anything the package
// doesn't cover). body and out are JSON; either may be nil.
func (b *Bot) API(method, path string, body, out interface{}) error {
	return b.api.call(method, path, body, out)
}

// SendRaw sends one message on the bot's connection, as JSON.
func (b *Bot) SendRaw(v interface{}) error { return b.sendJSON(v) }

func (b *Bot) sendJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b.wsMu.Lock()
	defer b.wsMu.Unlock()
	if b.ws == nil {
		return errors.New("not connected")
	}
	b.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return b.ws.WriteMessage(websocket.TextMessage, data)
}

// ── Running ──────────────────────────────────────────────────────────────────

// Backoff between connection attempts: from MinBackoff, doubling, up to
// MaxBackoff (the Bot Rules ask for at least a second, growing to a minute).
const (
	MinBackoff = time.Second
	MaxBackoff = 60 * time.Second
)

// Run keeps the bot connected until ctx ends.
func (b *Bot) Run(ctx context.Context) error {
	backoff := MinBackoff
	for {
		started := time.Now()
		err := b.session(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			b.logf("chriscordbot: %v", err)
		}
		if time.Since(started) > time.Minute {
			backoff = MinBackoff
		}
		b.logf("chriscordbot: reconnecting in %v", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff = min(backoff*2, MaxBackoff)
	}
}

// login signs in with the bot's certificate.
func (b *Bot) login(ctx context.Context) error {
	pub := b.cert.BotKey
	var ch struct {
		Nonce string `json:"nonce"`
	}
	b.api.setToken("")
	if err := b.api.callCtx(ctx, "POST", "/api/challenge", map[string]string{"public_key": pub}, &ch); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	nonce, err := hex.DecodeString(ch.Nonce)
	if err != nil {
		return errors.New("challenge: bad nonce")
	}
	// The server names the bot itself (whoever added it may have chosen
	// another name); this only has to be a valid username.
	name := b.cert.Name
	if len(name) > 32 {
		name = "bot"
	}
	var j struct {
		Token             string `json:"token"`
		Username          string `json:"username"`
		EncryptedPresence bool   `json:"encrypted_presence"`
		Bot               bool   `json:"bot"`
	}
	err = b.api.callCtx(ctx, "POST", "/api/join", map[string]interface{}{
		"username":   name,
		"public_key": pub,
		"nonce":      ch.Nonce,
		"signature":  hex.EncodeToString(ed25519.Sign(b.key, nonce)),
		"bot":        b.cert,
		"client":     b.client,
	}, &j)
	if err != nil {
		return fmt.Errorf("signing in: %w", err)
	}
	if !j.Bot {
		return errors.New("signing in: this server doesn't support bots yet (it needs updating)")
	}
	b.api.setToken(j.Token)
	b.status.enabled.Store(j.EncryptedPresence)
	b.mu.Lock()
	b.me = j.Username
	b.mu.Unlock()
	b.text.setUsername(j.Username)
	b.logf("chriscordbot: signed in to %s as %s", b.server, j.Username)
	return nil
}

// session is one connection: sign in if needed, then the WebSocket until
// it ends.
func (b *Bot) session(ctx context.Context) error {
	if b.api.getToken() == "" {
		if err := b.login(ctx); err != nil {
			return err
		}
	}
	u, err := url.Parse(b.server)
	if err != nil {
		return err
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/ws"
	u.RawQuery = url.Values{"token": {b.api.getToken()}, "status": {"online"}}.Encode()
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	b.wsMu.Lock()
	b.ws = conn
	b.wsMu.Unlock()
	b.mu.Lock()
	b.rejoin = b.voiceBoard != ""
	b.mu.Unlock()

	stop := make(chan struct{})
	defer func() {
		close(stop)
		b.wsMu.Lock()
		b.ws = nil
		b.wsMu.Unlock()
		conn.Close()
		b.dropVoiceConnection() // the server takes the bot out of the call when this connection goes
	}()
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	b.announcePfp()
	// The signed member list first: until it's checked, keys go to nobody.
	if err := b.roster.refresh(); err != nil {
		b.logf("chriscordbot: the signed member list: %v", err)
	}
	go b.text.begin()
	go b.text.pendingLoop(stop)
	go b.status.loop(stop)
	go func() { // ping every 10 s, as the app does
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				b.wsMu.Lock()
				if b.ws != nil {
					b.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
				}
				b.wsMu.Unlock()
			}
		}
	}()
	if f := b.OnConnect; f != nil {
		go f()
	}

	// Alive while pings and pongs keep coming (the server pings every 20 s).
	alive := func() { conn.SetReadDeadline(time.Now().Add(70 * time.Second)) }
	conn.SetPongHandler(func(string) error { alive(); return nil })
	conn.SetPingHandler(func(data string) error {
		alive()
		b.wsMu.Lock()
		defer b.wsMu.Unlock()
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(5*time.Second))
	})
	got := 0
	for {
		alive()
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if got == 0 && ctx.Err() == nil {
				// Closed straight away: the session isn't valid any more (or
				// it reconnected too soon) — sign in again next time.
				b.api.setToken("")
			}
			return fmt.Errorf("connection closed: %w", err)
		}
		got++
		b.handle(raw)
	}
}

// ── What arrives ─────────────────────────────────────────────────────────────

type serverMsg struct {
	Type          string              `json:"type"`
	Target        string              `json:"target"`
	BoardID       string              `json:"board_id"`
	Data          json.RawMessage     `json:"data"`
	Channels      map[string][]string `json:"channels"`
	SDP           string              `json:"sdp"`
	Candidate     string              `json:"candidate"`
	SDPMid        *string             `json:"sdp_mid"`
	SDPMLineIndex *uint16             `json:"sdp_mline_index"`
	Message       string              `json:"message"`
}

type chatMessage struct {
	ID       string  `json:"id"`
	BoardID  string  `json:"board_id"`
	Username string  `json:"username"`
	Content  string  `json:"content"`
	Kind     *string `json:"kind"`
	ReplyTo  string  `json:"reply_to"`
}

func (b *Bot) handle(raw []byte) {
	var m serverMsg
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	me := b.Username()
	switch m.Type {
	case "message":
		var cm chatMessage
		if json.Unmarshal(m.Data, &cm) == nil && cm.Username != me && cm.Kind == nil {
			b.mu.Lock()
			seq := b.seq
			b.seq++
			b.mu.Unlock()
			go b.deliver(cm, seq)
		}
	case "e2ee_changed":
		b.text.changed()
	case "plugin_lane":
		b.onLane(raw)
	case "roster_changed":
		go func() {
			if err := b.roster.refresh(); err != nil {
				b.logf("chriscordbot: the signed member list: %v", err)
			}
			b.text.changed()
			b.call.rosterChanged() // who may hear the bot may have changed: a new call key
		}()
	case "voice_state":
		b.onVoiceState(m.Channels)
	case "voice_e2ee":
		b.call.handleMessage(raw)
	case "voice_answer":
		if s := b.currentCall(); s != nil {
			s.onAnswer(m.SDP)
		}
	case "voice_ice":
		if s := b.currentCall(); s != nil {
			s.onICE(m.Candidate, m.SDPMid, m.SDPMLineIndex)
		}
	case "voice_renegotiate":
		if s := b.currentCall(); s != nil {
			go s.onRenegotiate(m.SDP)
		}
	case "voice_removed":
		if m.Target == me {
			reason := m.Message
			if reason == "" {
				reason = "Disconnected from the call by a moderator"
			}
			b.logf("chriscordbot: removed from the call (%s)", reason)
			go b.endCall(reason)
		}
	case "voice_move":
		if m.Target == me && m.BoardID != "" {
			b.logf("chriscordbot: moved to %s by a moderator", m.BoardID)
			go b.moveTo(m.BoardID)
		}
	case "pfp_request":
		if m.Target == me {
			go b.uploadPfp()
		}
	case "action_denied":
		if m.Target == me {
			b.logf("chriscordbot: the server refused: %s", m.Message)
			if f := b.OnDenied; f != nil {
				go f(m.Message)
			}
		}
	case "rate_limited":
		b.logf("chriscordbot: sending too much — the server is dropping messages for a second")
	case "kicked":
		if m.Target == me {
			b.logf("chriscordbot: removed from the server")
		}
	}
	if f := b.OnEvent; f != nil {
		go f(Event{Type: m.Type, Raw: append(json.RawMessage{}, raw...)})
	}
}

func (b *Bot) deliver(cm chatMessage, seq uint64) {
	defer b.turns.done(seq)
	f := b.OnMessage
	if f == nil {
		return
	}
	text, signed, ok := b.text.openSigned(cm.BoardID, cm.Username, cm.Content)
	if !ok {
		return
	}
	f(&Message{ID: cm.ID, Channel: cm.BoardID, Author: cm.Username, Text: text, ReplyTo: cm.ReplyTo, Seq: seq, Signed: signed})
}

// WaitTurn waits until the handlers for every message that arrived before
// m have returned (or two minutes, so one stuck handler can't hold up the
// rest). Handlers run side by side; a bot that does something slow first
// (a lookup) and then something that must happen in arrival order (adding
// to a queue) calls this in between.
func (b *Bot) WaitTurn(m *Message) { b.turns.wait(m.Seq) }

type turns struct {
	mu       sync.Mutex
	cond     *sync.Cond
	next     uint64
	finished map[uint64]bool
}

func newTurns() *turns {
	t := &turns{finished: map[uint64]bool{}}
	t.cond = sync.NewCond(&t.mu)
	return t
}

func (t *turns) wait(seq uint64) {
	deadline := time.Now().Add(2 * time.Minute)
	timer := time.AfterFunc(2*time.Minute, func() { t.mu.Lock(); t.cond.Broadcast(); t.mu.Unlock() })
	defer timer.Stop()
	t.mu.Lock()
	defer t.mu.Unlock()
	for t.next < seq && time.Now().Before(deadline) {
		t.cond.Wait()
	}
}

func (t *turns) done(seq uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finished[seq] = true
	for t.finished[t.next] {
		delete(t.finished, t.next)
		t.next++
	}
	t.cond.Broadcast()
}

// ── Sending ──────────────────────────────────────────────────────────────────

// Send posts a message in a text channel, end-to-end encrypted. It waits
// if the bot has sent 5 in that channel in the last 5 seconds (the limit).
func (b *Bot) Send(channel, text string) error { return b.SendReply(channel, text, "") }

// SendReply posts a message answering replyTo ("" for none).
func (b *Bot) SendReply(channel, text, replyTo string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("nothing to send")
	}
	content, err := b.text.seal(channel, text)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}
	b.limit.wait(channel)
	m := map[string]interface{}{"type": "message", "board_id": channel, "content": content}
	if replyTo != "" {
		m["reply_to"] = replyTo
	}
	return b.sendJSON(m)
}

// SetStatus sets the bot's custom status in the member list ("" and ""
// clears it), e.g. SetStatus("🎶", "Song title"). It's encrypted like
// everyone's, so the server can't read it.
func (b *Bot) SetStatus(emoji, text string) { b.status.set(emoji, text) }

// MaxPictureBytes is the largest profile picture the server takes.
const MaxPictureBytes = 8 << 20

// SetPicture sets the bot's profile picture (PNG or JPEG, square works
// best) and when it last changed (unix seconds): the server asks for it
// only when its copy is older. Set it before Run.
func (b *Bot) SetPicture(data []byte, updatedAt int64) error {
	if len(data) > MaxPictureBytes {
		return fmt.Errorf("the picture is %d bytes; the server takes up to %d", len(data), MaxPictureBytes)
	}
	b.mu.Lock()
	b.pfp, b.pfpAt = data, updatedAt
	b.mu.Unlock()
	b.announcePfp()
	return nil
}

func (b *Bot) announcePfp() {
	b.mu.Lock()
	at := b.pfpAt
	has := b.pfp != nil
	b.mu.Unlock()
	if has {
		_ = b.sendJSON(map[string]interface{}{"type": "pfp_info", "pfp_updated_at": at})
	}
}

func (b *Bot) uploadPfp() {
	b.mu.Lock()
	data, at := b.pfp, b.pfpAt
	b.mu.Unlock()
	if data == nil {
		return
	}
	if err := b.sendJSON(map[string]interface{}{
		"type": "pfp_upload", "pfp_data": base64.StdEncoding.EncodeToString(data), "pfp_updated_at": at,
	}); err == nil {
		b.logf("chriscordbot: profile picture uploaded")
	}
}

// Channel is a channel the bot can see.
type Channel struct {
	ID       string // board id (what Send and JoinVoice take)
	Name     string
	Category string
	Voice    bool
}

// Channels lists the channels the bot was given.
func (b *Bot) Channels() ([]Channel, error) {
	var rooms []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		RoomType string `json:"room_type"`
	}
	if err := b.api.call("GET", "/api/rooms", nil, &rooms); err != nil {
		return nil, err
	}
	var out []Channel
	for _, r := range rooms {
		var boards []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := b.api.call("GET", "/api/rooms/"+url.PathEscape(r.ID)+"/boards", nil, &boards); err != nil {
			return nil, err
		}
		for _, bd := range boards {
			out = append(out, Channel{ID: bd.ID, Name: bd.Name, Category: r.Name, Voice: r.RoomType == "voice"})
		}
	}
	return out, nil
}

// channelLimiter keeps the bot to 5 messages per 5 seconds per channel.
type channelLimiter struct {
	mu   sync.Mutex
	sent map[string][]time.Time
}

const messagesPerWindow = 5

var messageWindow = 5 * time.Second // (a var for the tests)

func newChannelLimiter() *channelLimiter { return &channelLimiter{sent: map[string][]time.Time{}} }

func (l *channelLimiter) wait(channel string) {
	for {
		l.mu.Lock()
		now := time.Now()
		keep := l.sent[channel][:0]
		for _, t := range l.sent[channel] {
			if now.Sub(t) < messageWindow {
				keep = append(keep, t)
			}
		}
		if len(keep) < messagesPerWindow {
			l.sent[channel] = append(keep, now)
			l.mu.Unlock()
			return
		}
		wait := messageWindow - now.Sub(keep[0]) + 50*time.Millisecond
		l.sent[channel] = keep
		l.mu.Unlock()
		time.Sleep(wait)
	}
}
