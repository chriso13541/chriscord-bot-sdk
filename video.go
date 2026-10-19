package chriscordbot

// video.go — a bot showing a picture in its call (a video it plays, a
// game it runs…), shown in the app like a screen share. Like its sound,
// the picture is end-to-end encrypted with the bot's own call keys, which
// it gives members (never other bots or plugins); the bot still hears and
// sees nothing of the call.
//
//	b.OnVideoKeyframe = func() { encoder.ForceKeyframe() }
//	b.StartVideo(720, 30)
//	for frame := range encoded { b.WriteVideoH264(frame, pts) } // Annex B access units
//	b.StopVideo()
//
// The frames have to be H.264, Constrained Baseline (no B-frames): the one
// every app can decode. FFmpeg's libx264 with -profile:v baseline -tune
// zerolatency, say, writing Annex B (-f h264).

import (
	"errors"
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v3"
)

const videoMTU = 1200

// h264Capability: what the app's screen share sends.
func h264Capability() webrtc.RTPCodecCapability {
	return webrtc.RTPCodecCapability{
		MimeType:    webrtc.MimeTypeH264,
		ClockRate:   90000,
		SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
	}
}

// videoOut is the call connection's picture section ("screen", as the
// app's screen share).
type videoOut struct {
	trk       *webrtc.TrackLocalStaticRTP
	payloader codecs.H264Payloader
	mu        sync.Mutex
	seq       uint16
}

// addVideoSender adds the send-only picture section, after the audio ones
// (the server tells it apart by its track id, as it does the app's).
func (s *voiceSession) addVideoSender() {
	trk, err := webrtc.NewTrackLocalStaticRTP(h264Capability(), "screen", "chriscord-screen")
	if err != nil {
		s.b.logf("video: local track: %v", err)
		return
	}
	tr, err := s.pc.AddTransceiverFromTrack(trk, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
	if err != nil {
		s.b.logf("video: add transceiver: %v", err)
		return
	}
	s.video = &videoOut{trk: trk, seq: uint16(time.Now().UnixNano())}
	// Someone starting to watch (or recovering) asks for a keyframe.
	go func() {
		var last time.Time
		for {
			pkts, _, err := tr.Sender().ReadRTCP()
			if err != nil {
				return
			}
			for _, p := range pkts {
				switch p.(type) {
				case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
					if time.Since(last) > 300*time.Millisecond {
						last = time.Now()
						if f := s.b.OnVideoKeyframe; f != nil {
							go f()
						}
					}
				}
			}
		}
	}()
}

// write sends one access unit, encrypted for the call.
func (s *voiceSession) writeVideo(frame []byte, pts time.Duration) error {
	if s.video == nil {
		return errors.New("this call connection has no picture section")
	}
	sealed := s.b.call.seal(kindH264, frame)
	if sealed == nil {
		return errors.New("call encryption isn't running")
	}
	v := s.video
	v.mu.Lock()
	defer v.mu.Unlock()
	ts := uint32(pts * 90000 / time.Second)
	payloads := v.payloader.Payload(videoMTU, sealed)
	for i, p := range payloads {
		pkt := &rtp.Packet{Header: rtp.Header{Version: 2, Marker: i == len(payloads)-1, SequenceNumber: v.seq, Timestamp: ts}, Payload: p}
		v.seq++
		if err := v.trk.WriteRTP(pkt); err != nil {
			return err
		}
	}
	return nil
}

// StartVideo starts showing a picture in the bot's call, height pixels tall
// at fps frames a second (what viewers are told it's sent at). The app
// shows it like a screen share: people choose to watch it. Needs the Video
// permission. It stays on through reconnections until StopVideo.
func (b *Bot) StartVideo(height, fps int) error {
	b.mu.Lock()
	board := b.voiceBoard
	b.videoOn, b.videoH, b.videoFPS = true, height, fps
	b.mu.Unlock()
	if board == "" {
		return ErrNotInCall
	}
	return b.announceVideo(board)
}

func (b *Bot) announceVideo(board string) error {
	b.mu.Lock()
	on, h, fps := b.videoOn, b.videoH, b.videoFPS
	b.mu.Unlock()
	if err := b.sendJSON(map[string]interface{}{"type": "voice_screen", "board_id": board, "screen": on}); err != nil {
		return err
	}
	if on && h > 0 && fps > 0 {
		return b.sendJSON(map[string]interface{}{"type": "voice_screen_native", "board_id": board, "height": h, "fps": fps})
	}
	return nil
}

// StopVideo stops showing the picture.
func (b *Bot) StopVideo() {
	b.mu.Lock()
	board, was := b.voiceBoard, b.videoOn
	b.videoOn = false
	b.mu.Unlock()
	if was && board != "" {
		_ = b.announceVideo(board)
	}
}

// WriteVideoH264 sends one encoded frame (an H.264 access unit, Annex B)
// shown at pts (time since the picture started; it sets the frames'
// spacing). Like WriteOpus, ErrNotInCall when there's no call up.
func (b *Bot) WriteVideoH264(frame []byte, pts time.Duration) error {
	s := b.currentCall()
	if s == nil || !s.isReady() {
		return ErrNotInCall
	}
	return s.writeVideo(frame, pts)
}
