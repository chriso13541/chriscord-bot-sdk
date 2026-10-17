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
| `OnCallReady`, `OnCallEnded` | its call is up; it was taken out of one |
| `OnDenied`, `OnEvent`, `SendRaw`, `API` | the server's refusals, every event, and anything not covered |
| `NewBotCert`, `EncodeBotToken`, `ParseBotToken`, `BotAddLink`, `NewBotRevocation` | the formats themselves (`botproto.go`) |

chriscord-musicbot is a full example: commands, a queue, and music in calls.

## Keeping in step

`botproto.go` is the same file (bar the package line) as the app's, and the
server checks the same signatures; `botproto_test.go` pins them in both.
`textcrypt.go`, `e2ee.go` and `e2ee_frame.go` follow the app's encryption
and must change with it.

## Testing

```sh
go test ./...
```

`bot_test.go` runs a bot against a stand-in server: signing in with its
certificate, encrypted chat both ways with a pretend member, the message
limit and reconnecting. chriscord-musicbot's integration test covers calls,
with real WebRTC.
