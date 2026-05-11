// Package client wraps every g3api endpoint and the WS scanprogress
// subscription used by g3tui. All inputs/outputs are domain types from
// g3lib; tea.Msg carriers below are just thin envelopes so the UI layer
// can route updates without depending on the underlying transport.
package client

import (
	"golismero.com/g3lib"
)

// Snapshot of the scan list (id + status + progress + message) returned
// by /scan/list+/scan/progress, or by the polling fallback when WS is down.
type ScanListSnapshot struct {
	Entries []g3lib.ScanStatusEntry
}

// Single scan-status update pushed via the WS scanprogress channel.
// Progress is a pointer mirroring the wire shape: senders that don't
// know the current progress (e.g. cancellation, failure) leave it nil,
// and receivers must preserve any existing value rather than treating
// nil as zero.
type ScanProgressUpdate struct {
	ScanID   string
	Status   g3lib.G3SCANSTATUS
	Progress *int
	Message  string
}

// Per-task status payload from /scan/tasks/status. Always delivered to
// the focused-pane sub-model (not routed through the global ErrorMsg
// banner) so a transient HTTP blip can't tear down the polling chain;
// the receiver re-arms regardless of Err.
type TaskStatusUpdate struct {
	ScanID   string
	Response g3lib.ScanTaskStatusResponse
	Err      error
}

// Per-task log payload from /scan/logs. ScanID and TaskID identify the
// binding so a stale tick from a previous focus is dropped on receipt.
// Err inline (not routed via ErrorMsg) so a transient HTTP blip can't
// tear down the polling chain — the receiver re-arms regardless.
type LogChunk struct {
	ScanID string
	TaskID string
	Log    g3lib.G3TaskLog
	Err    error
}

// Per-scan log payload from /scan/logs (TaskID="" mode). Carries the raw
// row list; the consumer (full-screen LogsViewer) walks the stream to
// render and to build its taskID→tool map from [g3:dispatch] markers.
type ScanLogChunk struct {
	ScanID  string
	Entries []g3lib.LogEntry
	Err     error
}

// Successful one-shot fetch from /scan/report.
type ReportLoaded struct {
	ScanID   string
	Markdown string
	Errors   string // non-empty if the server reported parse errors during generation
}

// Wizard upload result for one file.
type FileUploaded struct {
	LocalPath string
	FileID    string // server-side handle to substitute into the script's import line
}

// Submit-flow result of POST /scan/start.
type ScanStarted struct {
	ScanID string
}

// Outcome of POST /scan/stop.
type ScanCancelRequested struct {
	ScanID string
}

// Outcome of POST /scan/delete.
type ScanDeleted struct {
	ScanID string
}

// Cached at app start; the wizard's import-tool dropdown reads this.
type PluginsLoaded struct {
	Plugins []PluginListEntry
}

type PluginListEntry struct {
	Name        string
	URL         string
	Description string
}

// ErrorMsg is the generic carrier for any failed call. The owning model
// decides how to surface it (banner, inline error, etc.).
type ErrorMsg struct {
	Op  string // human label like "/scan/start"
	Err error
}
