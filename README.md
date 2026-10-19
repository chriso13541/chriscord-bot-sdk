# chriscord-bot-sdk

Go package for writing bots for [Chriscord](https://chriscord.app) servers.

A Chriscord bot is an identity of its own: a key, with a certificate from
the person who made it. It shows with a **BOT** tag and who made it, gets
into a server only when someone with **Manage Bots** adds it, and sees only
the channels it was given. It never uses a server's join key, an invite or
the owner key. The full rules are in the Chriscord Bot Rules.

This package does everything those rules ask of a bot, so a bot built on it
only has to say what it does:

- signs in with the bot's certificate (and says what it is, from `Client`);
- publishes its encryption key, then reads and sends **end-to-end encrypted
  messages** the same way the app does, sharing channel keys with newcomers;
- takes part in a call's **key exchange** before sending any sound, and sends
  Opus audio sealed with its call key;
- keeps to the **rate limits** (5 messages per 5 seconds per channel, at
  most 40 requests a second) and waits when the server says so;
- answers pings, and **reconnects** with a growing wait (1 second up to a
  minute), getting back into its call afterwards.

## Making a bot

1. In the Chriscord app: **Settings → Bots → New Bot**. Give it a name and a
   description that says what it keeps. The app shows its **token** once
   (`ccbot_1_…`) and gives an **Add to server** link.
2. Someone with Manage Bots on a server opens the link in the app, chooses
   what the bot may do and which channels it sees, and adds it.
3. Run your bot with the token. Keep the token secret: it *is* the bot. If
   it might have leaked, revoke the bot in the app and make a new one.

## Example

```go
b, err := chriscordbot.New(chriscordbot.Options{
	Server: "https://chat.example.com",
	Token:  os.Getenv("CHRISCORD_BOT_TOKEN"),
	Client: "echobot/1.0", // your bot's name and version
})
if err != nil {
	log.Fatal(err)
}
b.OnMessage = func(m *chriscordbot.Message) {
	if m.Text == "!ping" {
		b.SendReply(m.Channel, "pong", m.ID)
	}
}
b.Run(context.Background())
```

`examples/echo` is that, runnable:

```sh
CHRISCORD_URL=https://chat.example.com CHRISCORD_BOT_TOKEN=ccbot_1_… go run ./examples/echo
```

## What's in it

| | |
|---|---|
| `New(Options)`, `Run(ctx)` | make the bot from its token, and keep it connected until ctx ends |
| `OnMessage` | every message it can read in its channels, decrypted (handlers run side by side; `WaitTurn(m)` waits for earlier ones) |
| `Send`, `SendReply` | post an encrypted message (waits if it's sent 5 in that channel in 5 seconds) |
| `SetStatus(emoji, text)` | its custom status in the member list, encrypted like everyone's |
| `SetPicture(data, updatedAt)` | its profile picture |
| `Channels()` | the channels it was given |
| `OnVoiceState`, `VoiceStates`, `OthersIn`, `VoiceChannelOf` | who's in which voice channel it can see |
| `JoinVoice`, `LeaveVoice`, `InVoice`, `WriteOpus`, `SetSpeaking` | being in a call and sending 20 ms Opus packets |
| `StartVideo`, `WriteVideoH264`, `StopVideo`, `OnVideoKeyframe` | showing a picture in the call (H.264), like a screen share |
| `Announce` | telling a channel something, on lanes (not a chat message) |
| `OnCallReady`, `OnCallEnded` | its call is up; it was taken out of one |
| `OnLaneOpen`, `OnLane`, `LaneSessions`, `LaneSession.Send`, `LaneSession.MayRead` | a plugin's end-to-end encrypted lanes to members' apps (below) |
| `OnDenied`, `OnEvent`, `SendRaw`, `API` | the server's refusals, every event, and anything not covered |
| `NewBotCert`, `EncodeBotToken`, `ParseBotToken`, `BotAddLink`, `NewBotRevocation` | the formats themselves (`botproto.go`) |

chriscord-musicbot is a full example: commands, a queue, and music in calls.

## The signed member list

Every server needs a signed member list: who may read each channel, signed
by its owner and the members who manage members. The server can't change
it. Since 0.2.0 a bot follows it exactly like the app (`rostersync.go`):

- channel keys, keys for newcomers and the bot's call key only go to people
  the list allows, whatever the server says;
- the bot's call key only ever goes to members — never to other bots or
  plugins, which can play into a call but never hear it;
- when someone loses access, the bot's next message uses a new key;
- on a server without a list (or until it's been fetched and checked), the
  bot gives keys to nobody, and can't send messages.

Set `Options.RosterFile` to a file the bot can keep. The bot then remembers
the list between runs, so a server that drops it or starts a different one
is noticed (`Bot.RosterState()` returns `"replaced"`, and no keys go to
anyone). If the owner really did start over, delete the file.

For the bot to read a channel there, the server's approvers have to add it
to the list.

## Who wrote a message

A channel's key is shared by everyone who can read the channel, so it can't
say who wrote a message. Every message the bot sends is signed with its
identity key (`msgsig.go`, the same as the app's), and the bot checks the
signature on every message it reads: one signed by a key that isn't its
writer's is dropped. `Message.Signed` says whether it was signed at all —
an unsigned one came from an older app, or from someone else who can read
the channel writing as `Author`, so don't trust it for anything that
matters.

## Plugin lanes

A plugin whose `plugin.json` says `"lanes": true` gets its commands, panel
clicks, answers and panels end-to-end encrypted (`lane.go`, `lanes.go`).
Each member's app opens a lane to it: sealed for the plugin's published
encryption key (on a server with a signed member list, only if the list has
the plugin's key as a plugin), and signed by the member, so the server can't
pretend to be someone else, read the lane, or replay anything on it.

```go
b.OnLaneOpen = func(s *chriscordbot.LaneSession) { s.Send(myPanel) }
b.OnLane = func(s *chriscordbot.LaneSession, msg json.RawMessage) {
	// {"t":"command","id","command","args","board"} or {"t":"action","id","action","value","board"}
	s.Send(map[string]interface{}{"t": "reply", "to": id, "content": "Done"})
}
```

The app understands `{"t":"reply","to","content","error"?}`,
`{"t":"panel","board","panel"}` (null: none) and `{"t":"notice","board","text"}`.

`b.Announce(channel, text)` tells everyone who may read a channel something
("Now playing …"): it goes on each of their lanes, and their apps show it in
the channel marked as the plugin's. It isn't a chat message — it's not in
the channel's history, and the plugin needs no access to the channel. The
last 20 per channel are kept for a day and shown to anyone who opens a lane
later. Apps say when the server held back messages on a lane (the counters
skip).
`s.Key` is the member's identity key and `s.Name` their name; check
`s.MayRead(channel)` before sending a panel about a channel, or acting on
one a command names. On a server with a signed member list only its members
can open a lane. The server still sees who uses which plugin, when, and how
much. A plugin the server runs is on the server's machine, so lanes keep
what's said to it from the server software, its database and logs, not
from whoever controls that machine.

## A picture in a call

`video.go`: a bot in a call can show a picture too (a video it plays, say),
which the app shows like a screen share. Like its sound, it's encrypted with
the bot's own call keys; the bot still hears and sees nothing of the call.

```go
b.OnVideoKeyframe = func() { encoder.ForceKeyframe() } // someone started watching
b.StartVideo(720, 30)                                  // height, fps
b.WriteVideoH264(accessUnit, pts)                      // Annex B, Constrained Baseline
b.StopVideo()
```

It needs the Video permission (`"video"` in a plugin's permissions).

## Keeping in step

`botproto.go` is the same file (bar the package line) as the app's, and the
server checks the same signatures; `botproto_test.go` pins them in both.
`textcrypt.go`, `e2ee.go` and `e2ee_frame.go` follow the app's encryption
and must change with it; `lane.go` is the same file as the app's, and
`msgsig.go` the same down to its own message contents.

## Testing

```sh
go test ./...
```

`bot_test.go` runs a bot against a stand-in server: signing in with its
certificate, encrypted chat both ways with a pretend member, the message
limit and reconnecting. chriscord-musicbot's integration test covers calls,
with real WebRTC.
