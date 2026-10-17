package chriscordbot

// api.go — the server's HTTP API, with the session token, kept under the
// bot rate limit (50 requests a second; this stays at 40) and waiting when
// the server says to.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RequestsPerSecond is how many HTTP requests a bot sends at most (the
// server allows 50).
const RequestsPerSecond = 40

type api struct {
	base   string
	client *http.Client

	mu    sync.Mutex
	token string

	rateMu sync.Mutex
	sent   []time.Time // the last second's requests
}

func newAPI(base string, client *http.Client) *api {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &api{base: base, client: client}
}

func (a *api) setToken(t string) { a.mu.Lock(); a.token = t; a.mu.Unlock() }
func (a *api) getToken() string  { a.mu.Lock(); defer a.mu.Unlock(); return a.token }

// HTTPError is an error answer from the server.
type HTTPError struct {
	Code    int
	Message string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Code) }

func isConflict(err error) bool {
	var h *HTTPError
	return errors.As(err, &h) && h.Code == http.StatusConflict
}

// pace waits until another request fits in the last second.
func (a *api) pace() {
	for {
		a.rateMu.Lock()
		now := time.Now()
		keep := a.sent[:0]
		for _, t := range a.sent {
			if now.Sub(t) < time.Second {
				keep = append(keep, t)
			}
		}
		a.sent = keep
		if len(a.sent) < RequestsPerSecond {
			a.sent = append(a.sent, now)
			a.rateMu.Unlock()
			return
		}
		wait := time.Second - now.Sub(a.sent[0])
		a.rateMu.Unlock()
		time.Sleep(wait)
	}
}

func (a *api) call(method, path string, body, out interface{}) error {
	return a.callCtx(context.Background(), method, path, body, out)
}

func (a *api) callCtx(ctx context.Context, method, path string, body, out interface{}) error {
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		a.pace()
		req, err := http.NewRequestWithContext(ctx, method, a.base+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if t := a.getToken(); t != "" {
			req.Header.Set("X-Session-Token", t)
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return fmt.Errorf("network error: %w", err)
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 3 {
			// Told to wait: wait as long as it says (a second if it doesn't).
			wait := time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s < 60 {
				wait = time.Duration(s) * time.Second
			}
			resp.Body.Close()
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			var e map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&e)
			msg := e["error"]
			if msg == "" {
				msg = http.StatusText(resp.StatusCode)
			}
			return &HTTPError{resp.StatusCode, msg}
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}
}

func randRead(b []byte) (int, error) { return io.ReadFull(rand.Reader, b) }
