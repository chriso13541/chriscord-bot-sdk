package chriscordbot

// callctl.go — being in a voice channel: joining the way the app does
// (join_voice, then the offer), the call's key exchange, sending sound,
// following a moderator's move, and getting back into the call after the
// connection to the server drops.

import (
	"errors"
	"time"
)

// OpusFrame is how long each packet given to WriteOpus plays for.
const OpusFrame = frameDur

func (b *Bot) currentCall() *voiceSession { b.mu.Lock(); defer b.mu.Unlock(); return b.voice }

// VoiceStates is who's in which voice channel the bot can see.
func (b *Bot) VoiceStates() map[string][]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string][]string, len(b.channels))
	for k, v := range b.channels {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// OthersIn is who else is in a voice channel.
func (b *Bot) OthersIn(channel string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.othersInLocked(channel)
}

func (b *Bot) othersInLocked(board string) []string {
	var out []string
	for _, u := range b.channels[board] {
		if u != b.me {
			out = append(out, u)
		}
	}
	return out
}

// VoiceChannelOf is the voice channel someone's in ("" if none, or one the
// bot can't see).
func (b *Bot) VoiceChannelOf(user string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	for board, users := range b.channels {
		for _, u := range users {
			if u == user {
				return board
			}
		}
	}
	return ""
}

// InVoice is the voice channel the bot is in ("" for none), and whether
// its call connection is up.
func (b *Bot) InVoice() (channel string, ready bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.voiceBoard, b.voice != nil && b.voice.isReady()
}

// CallListeners is how many people in the bot's call have its key (can
// hear it) out of how many are in it.
func (b *Bot) CallListeners() (withKey, total int) { return b.call.ready() }

func (b *Bot) onVoiceState(channels map[string][]string) {
	if channels == nil {
		channels = map[string][]string{}
	}
	b.call.updateRoster(channels)
	b.mu.Lock()
	board := b.voiceBoard
	// Someone new in its call while it's speaking: the server only passes
	// on changes, so they'd see no ring until the next one.
	joined := false
	if board != "" && b.speaking && !b.rejoin {
		before := map[string]bool{}
		for _, u := range b.channels[board] {
			before[u] = true
		}
		for _, u := range channels[board] {
			if u != b.me && !before[u] {
				joined = true
			}
		}
	}
	b.channels = channels
	rejoin := b.rejoin && board != ""
	b.rejoin = false
	b.mu.Unlock()
	if joined {
		go func() {
			// After a moment, for their app to be in the call (it only
			// listens for rings once it is), and again a little later in
			// case its connection was slow.
			for _, wait := range []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond} {
				time.Sleep(wait)
				b.mu.Lock()
				on, still := b.speaking, b.voiceBoard == board
				b.mu.Unlock()
				if !on || !still {
					return
				}
				_ = b.sendJSON(map[string]interface{}{"type": "speaking", "board_id": board, "speaking": true})
			}
		}()
	}
	if f := b.OnVoiceState; f != nil {
		cp := make(map[string][]string, len(channels))
		for k, v := range channels {
			cp[k] = append([]string(nil), v...)
		}
		go f(cp)
	}
	if !rejoin {
		return
	}
	// Back after a dropped connection: into the same channel, if anyone's
	// still there.
	if len(b.OthersIn(board)) == 0 {
		b.logf("chriscordbot: reconnected, but nobody's left in the call — not rejoining")
		go b.endCall("Everyone had left the call while I was reconnecting")
		return
	}
	go func() {
		if err := b.JoinVoice(board); err != nil {
			b.logf("chriscordbot: rejoining the call: %v", err)
		}
	}()
}

// JoinVoice puts the bot in a voice channel (moving it if it's in
// another). Its sound goes out once OnCallReady says the call is up.
func (b *Bot) JoinVoice(channel string) error {
	b.mu.Lock()
	old := b.voice
	was := b.voiceBoard
	b.voice = nil
	b.mu.Unlock()
	if old != nil {
		old.close()
	}
	if was != "" && was != channel {
		b.call.end()
	}
	if err := b.sendJSON(map[string]interface{}{
		"type": "join_voice", "board_id": channel, "muted": false, "deafened": false,
	}); err != nil {
		return err
	}
	b.mu.Lock()
	b.voiceBoard = channel
	b.mu.Unlock()
	return b.startCall(channel)
}

// startCall builds the call's connection and sends the offer.
func (b *Bot) startCall(board string) error {
	s, err := newVoiceSession(b, board, b.OthersIn(board))
	if err != nil {
		return err
	}
	b.mu.Lock()
	if b.voiceBoard != board { // left meanwhile
		b.mu.Unlock()
		s.close()
		return nil
	}
	old := b.voice
	b.voice = s
	b.mu.Unlock()
	if old != nil {
		old.close()
	}
	return s.offer()
}

// callUp: the call's connection is up.
func (b *Bot) callUp(s *voiceSession) {
	b.mu.Lock()
	current := b.voice == s
	board := b.voiceBoard
	b.mu.Unlock()
	if current {
		b.mu.Lock()
		video := b.videoOn
		b.mu.Unlock()
		if video {
			_ = b.announceVideo(board) // still showing its picture
		}
		if f := b.OnCallReady; f != nil {
			f(board)
		}
	}
}

// restartCall rebuilds a failed call connection in place (no join_voice:
// the server takes the fresh offer as a refresh), at most every 5 seconds.
func (b *Bot) restartCall(s *voiceSession) {
	b.mu.Lock()
	if b.voice != s || b.voiceBoard == "" {
		b.mu.Unlock()
		return
	}
	wait := time.Until(b.restartAt.Add(5 * time.Second))
	b.restartAt = time.Now().Add(max(wait, 0))
	board := b.voiceBoard
	b.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
	b.logf("chriscordbot: call connection failed — rebuilding it")
	if err := b.startCall(board); err != nil {
		b.logf("chriscordbot: rebuilding the call: %v", err)
	}
}

// dropVoiceConnection closes the call's connection (the server connection
// went), keeping voiceBoard so the bot rejoins once it's back.
func (b *Bot) dropVoiceConnection() {
	b.mu.Lock()
	s := b.voice
	b.voice = nil
	b.mu.Unlock()
	if s != nil {
		s.close()
	}
}

// LeaveVoice hangs up.
func (b *Bot) LeaveVoice() { b.hangUp() }

func (b *Bot) hangUp() (was string) {
	b.mu.Lock()
	s := b.voice
	was = b.voiceBoard
	b.voice, b.voiceBoard, b.rejoin, b.speaking = nil, "", false, false
	b.videoOn = false // hanging up ends the picture too
	b.mu.Unlock()
	if s != nil {
		s.close()
	}
	b.call.end()
	if was != "" {
		_ = b.sendJSON(map[string]string{"type": "leave_voice"})
		b.logf("chriscordbot: left the call in %s", was)
	}
	return was
}

// endCall: out of the call for a reason other than the bot leaving.
func (b *Bot) endCall(reason string) {
	was := b.hangUp()
	if was == "" {
		return
	}
	if f := b.OnCallEnded; f != nil {
		f(was, reason)
	}
}

// moveTo follows a moderator's move to another channel.
func (b *Bot) moveTo(board string) {
	if err := b.JoinVoice(board); err != nil {
		b.logf("chriscordbot: following a move: %v", err)
	}
}

// SetSpeaking shows (or stops showing) the speaking ring around the bot.
// It stays on until turned off: the server only passes on changes, so
// someone who joins the call meanwhile is told again (onVoiceState).
func (b *Bot) SetSpeaking(on bool) {
	b.mu.Lock()
	b.speaking = on
	b.mu.Unlock()
	board, _ := b.InVoice()
	if board != "" {
		_ = b.sendJSON(map[string]interface{}{"type": "speaking", "board_id": board, "speaking": on})
	}
}

// ErrNotInCall: WriteOpus without a call that's up.
var ErrNotInCall = errors.New("not in a call (or its connection isn't up yet)")

// WriteOpus sends one Opus packet of OpusFrame (20 ms) to the call,
// encrypted with the bot's call key. Pace the packets in real time.
func (b *Bot) WriteOpus(packet []byte) error {
	s := b.currentCall()
	if s == nil || !s.isReady() {
		return ErrNotInCall
	}
	return s.write(packet)
}
