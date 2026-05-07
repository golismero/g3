package client

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Poll drives a single fetch-and-emit loop until ctx is cancelled. Each
// iteration calls fetch() and forwards the resulting tea.Msg via send.
// Returning nil from fetch is allowed — the iteration is skipped silently
// (useful when the caller wants to suppress emission for a tick).
//
// Errors are emitted as ErrorMsg{Op: opLabel, Err: err}; the loop continues.
// Pause-on-blur is implemented by the caller cancelling its ctx; when the
// pane regains focus it spawns a fresh Poll.
func Poll(ctx context.Context, interval time.Duration, opLabel string,
	fetch func(context.Context) (tea.Msg, error),
	send func(tea.Msg),
) {
	t := time.NewTicker(interval)
	defer t.Stop()

	tick := func() {
		msg, err := fetch(ctx)
		if err != nil {
			if ctx.Err() == nil {
				send(ErrorMsg{Op: opLabel, Err: err})
			}
			return
		}
		if msg != nil {
			send(msg)
		}
	}

	tick() // fire once immediately so first paint isn't blocked by `interval`
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
