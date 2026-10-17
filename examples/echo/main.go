// echo is the smallest useful bot: it answers !ping with pong, and !echo
// <words> with the words. It keeps nothing.
//
//	CHRISCORD_URL=https://chat.example.com CHRISCORD_BOT_TOKEN=ccbot_1_… go run ./examples/echo
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"

	chriscordbot "github.com/chriso13541/chriscord-bot-sdk"
)

func main() {
	b, err := chriscordbot.New(chriscordbot.Options{
		Server: os.Getenv("CHRISCORD_URL"),
		Token:  os.Getenv("CHRISCORD_BOT_TOKEN"),
		Client: "echobot/1.0",
	})
	if err != nil {
		log.Fatal(err)
	}
	b.OnMessage = func(m *chriscordbot.Message) {
		switch {
		case m.Text == "!ping":
			b.SendReply(m.Channel, "pong", m.ID)
		case strings.HasPrefix(m.Text, "!echo "):
			b.Send(m.Channel, strings.TrimPrefix(m.Text, "!echo "))
		}
	}
	b.OnConnect = func() { b.SetStatus("👋", "Type !ping") }

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	b.Run(ctx)
}
