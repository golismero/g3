package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/golismero/g3/src/g3lib"
	"github.com/golismero/g3/src/g3tui/internal/client"
)

// reportPaneGenCounter is a process-wide monotonic counter mirroring
// the LogsViewer pattern: it stamps each ReportPane and its async
// messages so a late-arriving fetch result for a previously-closed pane
// cannot be misrouted to a freshly-opened one for the same scanID.
var reportPaneGenCounter int

type reportState int

const (
	reportLoading reportState = iota
	reportLoaded
	reportSaving    // brief; sync write completes before next render in practice
	reportExporting // multi-call data fetch; spinner overlay active
	reportError
)

// reportFetchedMsg carries the dispatched magenta report result back to the
// pane. Generation guards against late deliveries.
type reportFetchedMsg struct {
	Generation int
	Markdown   string
	Errors     string
	Err        error
}

// reportPaneClosedMsg fires on Esc. App tears down the overlay.
type reportPaneClosedMsg struct{}

// ReportPane is the full-screen Markdown report overlay opened by `r`.
// Parallel in role and lifecycle to LogsViewer: instantiated each open,
// discarded on close, no long-lived state.
type ReportPane struct {
	cli          *client.Client
	glamourStyle string // "dark" or "light"; resolved at startup, never re-probed

	scanID     string
	scanStatus g3lib.G3SCANSTATUS
	generation int

	state    reportState
	markdown string
	rendered string
	errors   string
	err      error

	viewport viewport.Model
	spinner  spinner.Model

	picker        *FilePicker
	exportPending bool // set true by openExportPicker; consumed by pickerSaveConfirmedMsg

	banner        string
	bannerStyle   lipgloss.Style
	bannerExpires time.Time

	exportCtx    context.Context
	exportCancel context.CancelFunc

	width  int
	height int
}

func NewReportPane(cli *client.Client, scanID string, scanStatus g3lib.G3SCANSTATUS, glamourStyle string) ReportPane {
	reportPaneGenCounter++
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	// Fall back to "dark" if caller didn't supply a style.
	if glamourStyle == "" {
		glamourStyle = "dark"
	}
	return ReportPane{
		cli:          cli,
		glamourStyle: glamourStyle,
		scanID:       scanID,
		scanStatus:   scanStatus,
		generation:   reportPaneGenCounter,
		state:        reportLoading,
		viewport:     viewport.New(0, 0),
		spinner:      sp,
	}
}

// SetScanStatus keeps the pane's title in sync with the dashboard's
// scan list. Mirrors LogsViewer.SetScanStatus.
func (p *ReportPane) SetScanStatus(status g3lib.G3SCANSTATUS) {
	p.scanStatus = status
}

func (p *ReportPane) SetSize(w, h int) {
	p.width = w
	p.height = h
	inner := w - 4
	chrome := 2
	titleRow := 1
	spacerRow := 1
	bannerRow := 0
	if p.errors != "" || p.banner != "" {
		bannerRow = 2
	}
	contentHeight := max(1, h-chrome-titleRow-spacerRow-bannerRow)
	p.viewport.Width = inner
	p.viewport.Height = contentHeight
	if p.picker != nil {
		p.picker.SetSize(w, h)
	}
	if p.state == reportLoaded {
		p.renderAndApply()
	}
}

func (p ReportPane) InitCmd() tea.Cmd {
	return tea.Batch(p.fetchCmd(), p.spinner.Tick)
}

func (p ReportPane) Help() []key.Binding {
	switch p.state {
	case reportLoaded:
		bindings := []key.Binding{Keys.Save}
		if isTerminal(p.scanStatus) {
			bindings = append(bindings, Keys.Export)
		}
		bindings = append(bindings, Keys.Back)
		return bindings
	case reportError:
		return []key.Binding{Keys.Retry, Keys.Back}
	default:
		return []key.Binding{Keys.Back}
	}
}

func (p ReportPane) Update(msg tea.Msg) (ReportPane, tea.Cmd) {
	switch m := msg.(type) {
	case reportFetchedMsg:
		if m.Generation != p.generation {
			return p, nil
		}
		if m.Err != nil {
			p.state = reportError
			p.err = m.Err
			return p, nil
		}
		p.markdown = m.Markdown
		p.errors = m.Errors
		p.state = reportLoaded
		p.SetSize(p.width, p.height)
		p.viewport.GotoTop()
		return p, nil

	case spinner.TickMsg:
		if p.state != reportLoading && p.state != reportExporting {
			return p, nil
		}
		var cmd tea.Cmd
		p.spinner, cmd = p.spinner.Update(m)
		return p, cmd

	case tea.KeyMsg:
		// While the picker is open, all keystrokes route to it.
		if p.picker != nil {
			np, cmd := p.picker.Update(m)
			p.picker = &np
			return p, cmd
		}
		// While exporting, only Esc is meaningful (cancel).
		if p.state == reportExporting {
			if key.Matches(m, Keys.Back) {
				if p.exportCancel != nil {
					p.exportCancel()
				}
				return p, nil
			}
			return p, nil
		}
		switch {
		case key.Matches(m, Keys.Back):
			return p, func() tea.Msg { return reportPaneClosedMsg{} }
		case key.Matches(m, Keys.Retry):
			if p.state == reportError {
				p.state = reportLoading
				p.err = nil
				return p, tea.Batch(p.fetchCmd(), p.spinner.Tick)
			}
		case key.Matches(m, Keys.Save):
			if p.state == reportLoaded {
				return p.openSavePicker()
			}
		case key.Matches(m, Keys.Export):
			if p.state == reportLoaded && isTerminal(p.scanStatus) {
				return p.openExportPicker()
			}
		case key.Matches(m, Keys.Up):
			p.viewport.ScrollUp(1)
		case key.Matches(m, Keys.Down):
			p.viewport.ScrollDown(1)
		case key.Matches(m, Keys.PgUp):
			p.viewport.HalfPageUp()
		case key.Matches(m, Keys.PgDn):
			p.viewport.HalfPageDown()
		case key.Matches(m, Keys.GotoTop):
			p.viewport.GotoTop()
		case key.Matches(m, Keys.GotoBottom):
			p.viewport.GotoBottom()
		}
		return p, nil

	case pickerSaveConfirmedMsg:
		if p.picker == nil {
			return p, nil
		}
		path := m.Path
		p.picker = nil
		if p.exportPending {
			p.exportPending = false
			return p.startExport(path)
		}
		return p.writeMarkdown(path)

	case pickerCanceledMsg:
		p.picker = nil
		p.exportPending = false
		return p, nil

	case client.ReportSaved:
		p.state = reportLoaded
		p.setTransientBanner(BannerSuccess, fmt.Sprintf("Saved to %s", m.Path))
		return p, p.expireBannerCmd()

	case client.ReportSaveError:
		p.state = reportLoaded
		p.setBanner(BannerError, fmt.Sprintf("Save failed: %v", m.Err))
		return p, nil

	case client.ExportDone:
		p.state = reportLoaded
		p.exportCancel = nil
		p.exportCtx = nil
		p.setTransientBanner(BannerSuccess, fmt.Sprintf("Exported %d objects to %s", m.Count, m.Path))
		return p, p.expireBannerCmd()

	case client.ExportError:
		p.state = reportLoaded
		p.exportCancel = nil
		p.exportCtx = nil
		p.setBanner(BannerError, fmt.Sprintf("Export failed: %v", m.Err))
		return p, nil

	case bannerExpireMsg:
		if !p.bannerExpires.IsZero() && time.Now().After(p.bannerExpires) {
			p.banner = ""
			p.bannerExpires = time.Time{}
		}
		return p, nil
	}
	return p, nil
}

func (p ReportPane) View() string {
	title := AppTitle.Render(p.renderTitle(p.width - 4))

	var body string
	switch p.state {
	case reportLoading:
		body = lipgloss.Place(
			p.viewport.Width, p.viewport.Height,
			lipgloss.Center, lipgloss.Center,
			p.spinner.View()+"  Loading report…",
		)
	case reportError:
		msg := fmt.Sprintf("Failed to load report: %v\n\n[r] retry  [esc] back", p.err)
		body = lipgloss.Place(
			p.viewport.Width, p.viewport.Height,
			lipgloss.Center, lipgloss.Center,
			BannerError.Render(msg),
		)
	case reportLoaded, reportSaving:
		body = p.viewport.View()
	case reportExporting:
		overlay := p.spinner.View() + "  Exporting scan data…\n\n    [esc] cancel"
		body = lipgloss.Place(
			p.viewport.Width, p.viewport.Height,
			lipgloss.Center, lipgloss.Center,
			BannerWarn.Render(overlay),
		)
	}

	parts := []string{title, ""}
	if p.banner != "" {
		parts = append(parts, p.bannerStyle.Width(p.viewport.Width).Render(p.banner))
	} else if p.errors != "" {
		first := firstLine(p.errors)
		parts = append(parts, BannerWarn.Width(p.viewport.Width).Render(
			"Report generated with caveats: "+first,
		))
	}
	parts = append(parts, body)

	rendered := PaneBorderFocused.Width(p.width - 2).Height(p.height - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, parts...),
	)

	if p.picker != nil {
		return lipgloss.Place(
			p.width, p.height,
			lipgloss.Center, lipgloss.Center,
			p.picker.View(),
		)
	}
	return rendered
}

func (p ReportPane) renderTitle(maxWidth int) string {
	status := string(p.scanStatus)
	if status == "" {
		status = "?"
	}
	candidates := []string{
		fmt.Sprintf("Report · %s · %s", p.scanID, status),
		fmt.Sprintf("Report · %s · %s", collapseID(p.scanID, colTaskIDMid), status),
		fmt.Sprintf("Report · %s · %s", collapseID(p.scanID, colTaskIDMin), status),
		fmt.Sprintf("Report · %s · %s", collapseID(p.scanID, colTaskIDFloor), status),
		fmt.Sprintf("Report · %s", status),
		"Report",
	}
	for _, c := range candidates {
		if lipgloss.Width(c) <= maxWidth {
			return c
		}
	}
	runes := []rune("Report")
	if len(runes) > maxWidth {
		return string(runes[:maxWidth])
	}
	return "Report"
}

// htmlImgWithPRe and htmlImgRe rewrite HTML <img> tags in the report
// markdown to "*[Image: <alt>]*" text before Glamour sees them.
// Glamour configures goldmark without WithUnsafe(), so raw HTML blocks
// like the pie-chart <p><img src='data:image/png;base64,…'/></p> emitted
// by the magenta reporter plugin are dropped entirely at render time —
// taking the alt-text inside the <img> with them. Preprocessing here is
// contained to g3tui; magenta's markdown is unchanged for the web GUI
// and g3cli report consumers.
//
// More architecturally correct alternative: register a custom goldmark
// renderer with WithUnsafe() that intercepts HTMLBlock/HTMLSpan nodes
// containing <img> and rewrites them to ImageElement nodes (or emits the
// same text fallback). Not adopted because Glamour does not expose its
// internal goldmark instance — adopting it would require either forking
// Glamour or building a parallel rendering pipeline, both
// disproportionate complexity for the same user-visible output.
var (
	htmlImgWithPRe = regexp.MustCompile(`(?i)<p[^>]*>\s*<img\s+[^>]*\balt=['"]([^'"]*)['"][^>]*/?>\s*</p>`)
	htmlImgRe      = regexp.MustCompile(`(?i)<img\s+[^>]*\balt=['"]([^'"]*)['"][^>]*/?>`)
)

// renderAndApply re-renders the cached markdown through Glamour at the
// current viewport width and pushes the result into the viewport.
// Called on initial load and on every resize.
func (p *ReportPane) renderAndApply() {
	width := p.viewport.Width
	if width < 1 {
		width = 1
	}
	r, err := glamour.NewTermRenderer(
		glamour.WithStylePath(p.glamourStyle),
		glamour.WithWordWrap(width),
	)
	// Glamour failures are non-fatal: raw markdown is still readable, and
	// the most likely cause (unsupported terminal) is not actionable here.
	if err != nil {
		p.rendered = p.markdown
		p.viewport.SetContent(p.rendered)
		return
	}
	md := htmlImgWithPRe.ReplaceAllString(p.markdown, "*[Image: $1]*")
	md = htmlImgRe.ReplaceAllString(md, "*[Image: $1]*")
	out, err := r.Render(md)
	if err != nil {
		p.rendered = p.markdown
		p.viewport.SetContent(p.rendered)
		return
	}
	p.rendered = out
	p.viewport.SetContent(out)
}

func (p ReportPane) fetchCmd() tea.Cmd {
	cli := p.cli
	sid := p.scanID
	gen := p.generation
	return func() tea.Msg {
		md, errs, err := cli.GetReport(context.Background(), sid)
		return reportFetchedMsg{
			Generation: gen,
			Markdown:   md,
			Errors:     errs,
			Err:        err,
		}
	}
}

// firstLine returns the substring of s up to (but not including) the
// first newline.
func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}

// bannerExpireMsg fires 5 seconds after a banner is shown to clear it.
type bannerExpireMsg struct{}

func (p ReportPane) openSavePicker() (ReportPane, tea.Cmd) {
	p.exportPending = false
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	short := p.scanID
	if len(short) > 8 {
		short = short[:8]
	}
	pk := NewSaveFilePicker(cwd, fmt.Sprintf("%s-report.md", short), "Save report (Markdown)")
	pk.SetSize(p.width, p.height)
	cmd := pk.InitCmd()
	p.picker = &pk
	return p, cmd
}

func (p ReportPane) openExportPicker() (ReportPane, tea.Cmd) {
	p.exportPending = true
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	short := p.scanID
	if len(short) > 8 {
		short = short[:8]
	}
	pk := NewSaveFilePicker(cwd, fmt.Sprintf("%s-export.json", short), "Export scan data (JSON)")
	pk.SetSize(p.width, p.height)
	cmd := pk.InitCmd()
	p.picker = &pk
	return p, cmd
}

func (p ReportPane) writeMarkdown(path string) (ReportPane, tea.Cmd) {
	p.state = reportSaving
	md := []byte(p.markdown)
	return p, func() tea.Msg {
		if err := os.WriteFile(path, md, 0o644); err != nil {
			return client.ReportSaveError{Err: err}
		}
		return client.ReportSaved{Path: path}
	}
}

func (p ReportPane) startExport(path string) (ReportPane, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	p.exportCtx = ctx
	p.exportCancel = cancel
	p.state = reportExporting

	cli := p.cli
	sid := p.scanID
	return p, tea.Batch(
		p.spinner.Tick,
		runJSONExportCmd(ctx, cli, sid, path),
	)
}

// setBanner shows a sticky banner (used for errors): it stays until the
// user acts — a later banner replaces it, or closing the pane clears it.
// Never a timer.
func (p *ReportPane) setBanner(style lipgloss.Style, text string) {
	p.banner = text
	p.bannerStyle = style
	p.bannerExpires = time.Time{}
}

// setTransientBanner shows a banner that auto-clears after 5s. Only for
// non-error feedback (e.g. "Saved to …") — errors must use setBanner so
// the user isn't forced to race the clock to read them.
func (p *ReportPane) setTransientBanner(style lipgloss.Style, text string) {
	p.setBanner(style, text)
	p.bannerExpires = time.Now().Add(5 * time.Second)
}

func (p ReportPane) expireBannerCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return bannerExpireMsg{} })
}

// runJSONExportCmd drives the two-call export pattern: /scan/datalist
// then batched /scan/data, writing a beautified JSON array to a temp
// file alongside the target and renaming atomically on completion.
// Cancelable via context (Esc); temp file is removed on every error
// and cancel path.
func runJSONExportCmd(ctx context.Context, cli *client.Client, scanID, path string) tea.Cmd {
	return func() tea.Msg {
		ids, err := cli.GetScanDataList(ctx, scanID)
		if err != nil {
			return client.ExportError{Path: path, Err: err}
		}
		if ctx.Err() != nil {
			return client.ExportError{Path: path, Err: ctx.Err()}
		}
		if len(ids) == 0 {
			if err := writeExportFile(path); err != nil {
				return client.ExportError{Path: path, Err: err}
			}
			return client.ExportDone{Path: path, Count: 0}
		}

		tmp := path + ".tmp"
		fd, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return client.ExportError{Path: path, Err: err}
		}
		cleanup := func() {
			_ = fd.Close()
			_ = os.Remove(tmp)
		}

		if _, err := fd.WriteString("[\n"); err != nil {
			cleanup()
			return client.ExportError{Path: path, Err: err}
		}

		const batchSize = 20
		firstWritten := false
		count := 0
		for start := 0; start < len(ids); start += batchSize {
			if ctx.Err() != nil {
				cleanup()
				return client.ExportError{Path: path, Err: ctx.Err()}
			}
			end := start + batchSize
			if end > len(ids) {
				end = len(ids)
			}
			batch := ids[start:end]
			objs, err := cli.GetScanData(ctx, scanID, batch)
			if err != nil {
				cleanup()
				return client.ExportError{Path: path, Err: err}
			}
			for _, obj := range objs {
				jb, err := jsonMarshalIndent(obj)
				if err != nil {
					cleanup()
					return client.ExportError{Path: path, Err: err}
				}
				if firstWritten {
					if _, err := fd.WriteString(",\n"); err != nil {
						cleanup()
						return client.ExportError{Path: path, Err: err}
					}
				}
				if _, err := fd.WriteString("  "); err != nil {
					cleanup()
					return client.ExportError{Path: path, Err: err}
				}
				if _, err := fd.Write(jb); err != nil {
					cleanup()
					return client.ExportError{Path: path, Err: err}
				}
				firstWritten = true
				count++
			}
		}

		if _, err := fd.WriteString("\n]\n"); err != nil {
			cleanup()
			return client.ExportError{Path: path, Err: err}
		}
		if err := fd.Close(); err != nil {
			_ = os.Remove(tmp)
			return client.ExportError{Path: path, Err: err}
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return client.ExportError{Path: path, Err: err}
		}
		return client.ExportDone{Path: path, Count: count}
	}
}

// writeExportFile writes the empty-array case atomically. Kept as a
// helper so the empty-scan path mirrors the temp+rename shape used by
// the main export.
func writeExportFile(path string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("[]\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func jsonMarshalIndent(obj map[string]any) ([]byte, error) {
	return json.MarshalIndent(obj, "  ", "  ")
}
