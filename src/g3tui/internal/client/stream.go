package client

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gorilla/websocket"
	"github.com/golismero/g3/src/g3lib"
)

type StreamState int

const (
	StreamConnecting StreamState = iota
	StreamConnected
	StreamDisconnected
	StreamReconnecting
)

func (s StreamState) String() string {
	switch s {
	case StreamConnecting:
		return "connecting"
	case StreamConnected:
		return "connected"
	case StreamDisconnected:
		return "disconnected"
	case StreamReconnecting:
		return "reconnecting"
	}
	return "unknown"
}

// StreamStateChanged fires every time the WS connection transitions between
// Connecting, Connected, Disconnected, Reconnecting. The header bar
// consumes this for its dot color.
type StreamStateChanged struct {
	State StreamState
	Err   error // populated on transitions into Disconnected/Reconnecting
}

// SubscribeScanProgress dials c.WSURL, subscribes to the scan.status
// channel, and forwards each progress message as ScanProgressUpdate.
// Reconnects with exponential backoff up to 30s on any error or close.
// Stops cleanly when ctx is cancelled.
func (c *Client) SubscribeScanProgress(ctx context.Context, send func(tea.Msg)) {
	backoff := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	attempt := 0

	for {
		if ctx.Err() != nil {
			return
		}

		if attempt == 0 {
			send(StreamStateChanged{State: StreamConnecting})
		} else {
			send(StreamStateChanged{State: StreamReconnecting})
		}

		conn, err := dialAndSubscribe(ctx, c.WSURL, c.Token)
		if err != nil {
			send(StreamStateChanged{State: StreamDisconnected, Err: err})
			d := backoff[min(attempt, len(backoff)-1)]
			attempt++
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
				continue
			}
		}

		send(StreamStateChanged{State: StreamConnected})
		attempt = 0
		readLoop(ctx, conn, send)
		_ = conn.Close()
		send(StreamStateChanged{State: StreamDisconnected})
	}
}

func dialAndSubscribe(ctx context.Context, wsURL, token string) (*websocket.Conn, error) {
	dialer := *websocket.DefaultDialer
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return nil, err
	}
	// One subscribe frame per channel. The server spawns an
	// independent writer goroutine per subscribe, so both feeds share
	// this single connection without further coordination.
	for _, msgtype := range []string{"scan.status", "scan.removed"} {
		frame := []byte(`{"msgtype":"` + msgtype + `"}`)
		if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func readLoop(ctx context.Context, conn *websocket.Conn, send func(tea.Msg)) {
	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		_ = conn.Close()
		close(closed)
	}()
	defer func() {
		select {
		case <-closed:
		default:
			// caller-side close; drain the watcher goroutine.
			// TODO: this default branch returns immediately without
			// waiting for the watcher to exit, so on server-side
			// disconnects the watcher goroutine leaks until ctx is
			// cancelled (at TUI exit). Fix by blocking on <-closed
			// unconditionally after calling conn.Close(); the watcher
			// exits promptly once the connection is closed.
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() == nil {
				send(StreamStateChanged{State: StreamDisconnected, Err: err})
			}
			return
		}
		var env struct {
			MsgType string          `json:"msgtype"`
			Data    json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			send(ErrorMsg{Op: "ws-decode", Err: err})
			continue
		}
		switch env.MsgType {
		case "scan.status":
			var status g3lib.G3ScanStatus
			if err := json.Unmarshal(env.Data, &status); err != nil {
				send(ErrorMsg{Op: "ws-decode", Err: err})
				continue
			}
			send(ScanProgressUpdate{
				ScanID:   status.ScanID,
				Status:   status.Status,
				Progress: status.Progress,
				Message:  status.Message,
			})
		case "scan.removed":
			var removed g3lib.G3ScanRemoved
			if err := json.Unmarshal(env.Data, &removed); err != nil {
				send(ErrorMsg{Op: "ws-decode", Err: err})
				continue
			}
			send(ScanRemoved{ScanID: removed.ScanID})
		default:
			continue
		}
	}
}
