package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/willabides/kongplete"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)

// Version is overwritten at link time by release builds via
// -ldflags "-X main.Version=...". Stays "dev" for local builds.
var Version = "dev"

const G3_API_BASEURL = "G3_API_BASEURL"
const G3_API_TOKEN = "G3_API_TOKEN"

// CmdContext is passed to every command's Run(vars CmdContext) method.
// Tier 1 populates it but only Tier 2+ commands consume it.
type CmdContext struct {
	Ctx     context.Context
	BaseURL string
	Token   string
}

type CompletionsCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" help:"Target shell (bash, zsh, or fish)."`
}

func (c *CompletionsCmd) Run() error {
	return g3lib.EmitShellCompletion(c.Shell, "g3man", os.Stdout)
}

// writeOutput writes data to outputPath. "-" or "" means stdout.
func writeOutput(outputPath string, data []byte) error {
	if outputPath == "-" || outputPath == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// emitJSON marshals data as JSON (compact, or indented when CLI.Beautify) and
// writes it to outputPath followed by a newline.
func emitJSON(outputPath string, data any) error {
	var jsonBytes []byte
	var err error
	if CLI.Beautify {
		jsonBytes, err = json.MarshalIndent(data, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(data)
	}
	if err != nil {
		return err
	}
	return writeOutput(outputPath, append(jsonBytes, '\n'))
}

// emitIDs writes one ID per line to outputPath. Used by the -q mode of
// list-style verbs (matches g3cli's `ps` ID-collapse pattern).
func emitIDs(outputPath string, ids []string) error {
	var sb strings.Builder
	for _, id := range ids {
		sb.WriteString(id)
		sb.WriteByte('\n')
	}
	return writeOutput(outputPath, []byte(sb.String()))
}

// decodeAs re-marshals an APIResponse's Data field and unmarshals it into out.
// MakeApiRequest returns Data as `any` (typically map[string]interface{} or
// []interface{} from the JSON decoder); this helper gives typed access without
// inline type assertions on every verb.
func decodeAs(data any, out any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// readJSONInput reads JSON bytes from inputPath. "-" or "" means stdin.
// Used by verbs that accept a JSON body via stdin or -i.
func readJSONInput(inputPath string) ([]byte, error) {
	if inputPath == "-" || inputPath == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(inputPath)
}

// requireManagedScan calls /scan/progress, finds the scan's row, and errors
// out if its status is anything other than MANAGED. Will collapse to a single
// GET /scans/{scanid} call after the REST migration.
func requireManagedScan(vars CmdContext, scanid string) error {
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/progress", vars.Token, g3lib.ReqGetScanProgressTable{})
	if err != nil {
		return err
	}
	if resp.Status != "success" {
		return errors.New("malformed response from server")
	}
	var entries []g3lib.ScanStatusEntry
	if err := decodeAs(resp.Data, &entries); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.ScanID == scanid {
			if entry.Status != g3lib.STATUS_MANAGED {
				return fmt.Errorf("scan %s is not managed (status: %s) — use g3cli for orchestrated scans", scanid, entry.Status)
			}
			return nil
		}
	}
	return fmt.Errorf("scan %s not found", scanid)
}

type EnvCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
}

func (cmd *EnvCmd) Run(vars CmdContext) error {
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/config/env", vars.Token, g3lib.ReqGetEnv{})
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

type ToolsCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
}

func (cmd *ToolsCmd) Run(vars CmdContext) error {
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/plugin/list", vars.Token, g3lib.ReqListPlugins{})
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	if CLI.Quiet {
		var plugins []map[string]string
		if err := decodeAs(resp.Data, &plugins); err != nil {
			log.Critical("Malformed response from server: " + err.Error())
			return err
		}
		names := make([]string, 0, len(plugins))
		for _, p := range plugins {
			names = append(names, p["name"])
		}
		return emitIDs(cmd.Output, names)
	}

	return emitJSON(cmd.Output, resp.Data)
}

type DescribeCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
}

func (cmd *DescribeCmd) Run(vars CmdContext) error {
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/plugin/describe", vars.Token, g3lib.ReqListPlugins{})
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

type LsCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
}

func (cmd *LsCmd) Run(vars CmdContext) error {
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/progress", vars.Token, g3lib.ReqGetScanProgressTable{})
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	var entries []g3lib.ScanStatusEntry
	if err := decodeAs(resp.Data, &entries); err != nil {
		log.Critical("Malformed response from server: " + err.Error())
		return err
	}

	managed := make([]g3lib.ScanStatusEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Status == g3lib.STATUS_MANAGED {
			managed = append(managed, entry)
		}
	}

	if CLI.Quiet {
		ids := make([]string, 0, len(managed))
		for _, entry := range managed {
			ids = append(ids, entry.ScanID)
		}
		return emitIDs(cmd.Output, ids)
	}

	return emitJSON(cmd.Output, managed)
}

type PsCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
	ScanID string `arg:""    required:""             help:"Scan ID."`
}

func (cmd *PsCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	req := g3lib.ReqQueryScanTaskStatus{ScanID: cmd.ScanID}
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/tasks/status", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	var payload g3lib.ScanTaskStatusResponse
	if err := decodeAs(resp.Data, &payload); err != nil {
		log.Critical("Malformed response from server: " + err.Error())
		return err
	}

	if CLI.Quiet {
		ids := make([]string, 0, len(payload.Tasks))
		for _, t := range payload.Tasks {
			ids = append(ids, t.TaskID)
		}
		return emitIDs(cmd.Output, ids)
	}

	return emitJSON(cmd.Output, payload)
}

type LogsCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
	ScanID string `arg:""    required:""             help:"Scan ID."`
	TaskID string `arg:""    optional:""             help:"Optional task ID. When omitted, all task logs for the scan are returned, chronologically interleaved."`
}

func (cmd *LogsCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	req := g3lib.ReqQueryLog{ScanID: cmd.ScanID, TaskID: cmd.TaskID}
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/logs", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	return emitJSON(cmd.Output, resp.Data)
}

type GetCmd struct {
	Output  string   `short:"o" type:"path" default:"-" help:"Output file."`
	ScanID  string   `arg:""    required:""             help:"Scan ID."`
	DataIDs []string `arg:""    optional:""             help:"Optional data IDs. When omitted, all data objects for the scan are returned (capped at 100 server-side)."`
}

func (cmd *GetCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	req := g3lib.ReqLoadData{ScanID: cmd.ScanID, DataIDs: cmd.DataIDs}
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/data", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	if CLI.Quiet {
		var data []g3lib.G3Data
		if err := decodeAs(resp.Data, &data); err != nil {
			log.Critical("Malformed response from server: " + err.Error())
			return err
		}
		ids := make([]string, 0, len(data))
		for _, d := range data {
			if id, ok := d["_id"].(string); ok {
				ids = append(ids, id)
			}
		}
		return emitIDs(cmd.Output, ids)
	}

	return emitJSON(cmd.Output, resp.Data)
}

type OutputCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
	ScanID string `arg:""    required:""             help:"Scan ID."`
	TaskID string `arg:""    required:""             help:"Task ID."`
}

func (cmd *OutputCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	req := g3lib.ReqLoadData{ScanID: cmd.ScanID, TaskID: cmd.TaskID}
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/data", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	if CLI.Quiet {
		var data []g3lib.G3Data
		if err := decodeAs(resp.Data, &data); err != nil {
			log.Critical("Malformed response from server: " + err.Error())
			return err
		}
		ids := make([]string, 0, len(data))
		for _, d := range data {
			if id, ok := d["_id"].(string); ok {
				ids = append(ids, id)
			}
		}
		return emitIDs(cmd.Output, ids)
	}

	return emitJSON(cmd.Output, resp.Data)
}

type FetchCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file (binary artifact bundle). Use - for stdout."`
	ScanID string `arg:""    required:""             help:"Scan ID."`
	TaskID string `arg:""    required:""             help:"Task ID."`
}

func (cmd *FetchCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	var dst io.Writer
	if cmd.Output == "-" || cmd.Output == "" {
		dst = os.Stdout
	} else {
		f, err := os.Create(cmd.Output)
		if err != nil {
			log.Critical("Cannot create output file: " + err.Error())
			return err
		}
		defer f.Close()
		dst = f
	}

	req := g3lib.ReqTaskArtifacts{ScanID: cmd.ScanID, TaskID: cmd.TaskID}
	if err := g3lib.DownloadFile(vars.Ctx, vars.BaseURL, "/scan/task/artifacts", vars.Token, req, dst); err != nil {
		log.Critical("Artifact download failed: " + err.Error())
		return err
	}
	return nil
}

type NewCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
}

func (cmd *NewCmd) Run(vars CmdContext) error {
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/create", vars.Token, g3lib.ReqCreateScan{})
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

type RmCmd struct {
	Force   bool     `short:"f"                         default:"false" help:"Skip the irreversible-deletion confirmation prompt."`
	Output  string   `short:"o" type:"path" default:"-" help:"Output file."`
	ScanIDs []string `arg:""    required:""                            help:"Scan IDs to delete."`
}

func (cmd *RmCmd) Run(vars CmdContext) error {
	if !cmd.Force {
		var msg string
		if len(cmd.ScanIDs) == 1 {
			msg = fmt.Sprintf("Do you really want to DELETE the scan %s? This is IRREVERSIBLE!", cmd.ScanIDs[0])
		} else {
			msg = fmt.Sprintf("Do you really want to DELETE the selected %d scans? This is IRREVERSIBLE!", len(cmd.ScanIDs))
		}
		if !g3lib.AskForConfirmation(msg) {
			log.Error("User cancelled the operation.")
			return errors.New("user cancelled the operation")
		}
	}

	for _, scanid := range cmd.ScanIDs {
		if err := requireManagedScan(vars, scanid); err != nil {
			log.Critical(err.Error())
			return err
		}
		req := g3lib.ReqDeleteScan{ScanID: scanid}
		resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/delete", vars.Token, req)
		if err != nil {
			log.Critical("API request failed for " + scanid + ": " + err.Error())
			return err
		}
		if resp.Status != "success" {
			log.Critical("Malformed response from server.")
			return errors.New("malformed response from server")
		}
	}
	return nil
}

type TargetCmd struct {
	Output  string   `short:"o" type:"path" default:"-" help:"Output file."`
	ScanID  string   `arg:""    required:""             help:"Scan ID."`
	Targets []string `arg:""    required:""             help:"Target(s) to add (one or more URLs/hosts)."`
}

func (cmd *TargetCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	req := g3lib.ReqAddTargets{ScanID: cmd.ScanID, Targets: cmd.Targets}
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/target/add", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

type PutCmd struct {
	Input  string `short:"i" type:"existingfile" default:"-" help:"Input JSON file (array of G3Data objects). Use - for stdin."`
	Output string `short:"o" type:"path"         default:"-" help:"Output file."`
	ScanID string `arg:""    required:""                    help:"Scan ID."`
}

func (cmd *PutCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	raw, err := readJSONInput(cmd.Input)
	if err != nil {
		log.Critical("Cannot read input: " + err.Error())
		return err
	}

	var data []g3lib.G3Data
	if err := json.Unmarshal(raw, &data); err != nil {
		log.Critical("Invalid JSON input: " + err.Error())
		return err
	}

	req := g3lib.ReqInsertData{ScanID: cmd.ScanID, Data: data}
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/data/insert", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

type UploadCmd struct {
	Output string `short:"o" type:"path"         default:"-" help:"Output file."`
	Path   string `arg:""    type:"existingfile" required:""  help:"Path to the file to upload."`
}

func (cmd *UploadCmd) Run(vars CmdContext) error {
	f, err := os.Open(cmd.Path)
	if err != nil {
		log.Critical("Cannot open file: " + err.Error())
		return err
	}
	defer f.Close()

	resp, err := g3lib.UploadFile(vars.Ctx, vars.BaseURL, "/file/upload", vars.Token, "file", filepath.Base(cmd.Path), f)
	if err != nil {
		log.Critical("Upload failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

type ImportCmd struct {
	Output string `short:"o" type:"path" default:"-" help:"Output file."`
	ScanID string `arg:""    required:""             help:"Scan ID."`
	Tool   string `arg:""    required:""             help:"Tool (plugin) name whose importer should be run on the file."`
	FileID string `arg:""    required:""             help:"Uploaded file ID (UUID from a prior 'g3man upload')."`
}

func (cmd *ImportCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	req := g3lib.ReqImport{ScanID: cmd.ScanID, Tool: cmd.Tool, FileID: cmd.FileID}
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/import", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

type RunCmd struct {
	Input  string `short:"i" type:"existingfile" default:"-" help:"Input JSON file with dispatch fields (kind, index, dataid, preset). Use - for stdin."`
	Output string `short:"o" type:"path"         default:"-" help:"Output file."`
	ScanID string `arg:""    required:""                    help:"Scan ID."`
	Tool   string `arg:""    required:""                    help:"Tool (plugin) name to dispatch."`
}

func (cmd *RunCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	raw, err := readJSONInput(cmd.Input)
	if err != nil {
		log.Critical("Cannot read input: " + err.Error())
		return err
	}

	var req g3lib.ReqTaskDispatch
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			log.Critical("Invalid JSON input: " + err.Error())
			return err
		}
	}
	req.ScanID = cmd.ScanID
	req.Tool = cmd.Tool

	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/task/dispatch", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

type CancelCmd struct {
	Output  string   `short:"o" type:"path" default:"-" help:"Output file."`
	ScanID  string   `arg:""    required:""             help:"Scan ID."`
	TaskIDs []string `arg:""    required:""             help:"Task IDs to cancel (one or more)."`
}

func (cmd *CancelCmd) Run(vars CmdContext) error {
	if err := requireManagedScan(vars, cmd.ScanID); err != nil {
		log.Critical(err.Error())
		return err
	}

	req := g3lib.ReqTaskCancel{ScanID: cmd.ScanID, TaskIDs: cmd.TaskIDs}
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/task/cancel", vars.Token, req)
	if err != nil {
		log.Critical("API request failed: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	return emitJSON(cmd.Output, resp.Data)
}

var CLI struct {
	Quiet    bool             `short:"q" default:"false" help:"Quiet mode."`
	Beautify bool             `short:"b" default:"false" help:"Beautify JSON output."`
	Version  kong.VersionFlag `                          help:"Show version and exit."`

	Cancel      CancelCmd      `cmd:"" help:"Cancel one or more tasks in a managed scan."`
	Completions CompletionsCmd `cmd:"" help:"Emit shell completion registration snippet."`
	Describe    DescribeCmd    `cmd:"" help:"Show LLM tool contracts for all registered plugins."`
	Env         EnvCmd         `cmd:"" help:"Show the deployment-wide G3_ENV_* environment map."`
	Fetch       FetchCmd       `cmd:"" help:"Download the artifact bundle of a completed task to -o (binary; defaults to stdout)."`
	Get         GetCmd         `cmd:"" help:"Get data objects from a managed scan by ID (or all data when no IDs given)."`
	Import      ImportCmd      `cmd:"" help:"Run a tool's importer on an uploaded file (managed scan)."`
	Logs        LogsCmd        `cmd:"" help:"Show execution logs for a managed scan (optionally filtered to one task)."`
	Ls          LsCmd          `cmd:"" help:"List managed scans."`
	New         NewCmd         `cmd:"" help:"Create a new managed scan; prints the scan ID."`
	Output      OutputCmd      `cmd:"" help:"Show all data objects produced by one specific task in a managed scan."`
	Ps          PsCmd          `cmd:"" help:"List tasks (with status) for a managed scan."`
	Put         PutCmd         `cmd:"" help:"Insert raw G3Data objects into a managed scan (reads JSON array from stdin or -i)."`
	Rm          RmCmd          `cmd:"" help:"Delete one or more managed scans (confirmation prompt unless -f)."`
	Run         RunCmd         `cmd:"" help:"Dispatch a tool task in a managed scan (reads kind/index/dataid/preset from stdin or -i); prints the task_id."`
	Target      TargetCmd      `cmd:"" help:"Add targets to a managed scan; returns the inserted data IDs."`
	Tools       ToolsCmd       `cmd:"" help:"List registered plugins."`
	Upload      UploadCmd      `cmd:"" help:"Upload a file to g3api; returns the file ID for use with 'g3man import'."`
}

func main() {
	// Build the parser (without parsing) so kongplete can hook in for Tab
	// completion before os.Args is consumed.
	parser := kong.Must(&CLI,
		kong.Name("g3man"),
		kong.Description("Golismero3 - Managed-scan CLI (debug/inspection tool for the managed g3api surface)."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
		kong.Vars{"version": Version},
	)
	// Short-circuits and exits when the shell invokes us with COMP_LINE set.
	// No-op in normal invocation.
	kongplete.Complete(parser)
	kctx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	// `g3man completions <shell>` must work without G3_API_* env vars set
	// — the user is setting up their shell, not making API calls. Short-
	// circuit before the env-var checks below.
	if strings.HasPrefix(kctx.Command(), "completions ") {
		parser.FatalIfErrorf(kctx.Run())
		return
	}

	// Load the environment variables.
	g3lib.LoadDotEnvFile()

	// Initialize the logger.
	log.InitLogger()
	if ll := os.Getenv("G3_CMD_LOG_LEVEL"); ll != "" {
		log.SetLogLevel(ll)
	}

	// Change the log level based on the flags.
	if CLI.Quiet {
		log.SetLogLevel("CRITICAL")
	}

	// Prepare the context variables for the commands.
	var cmdctx CmdContext

	// Get the API base URL.
	cmdctx.BaseURL = os.Getenv(G3_API_BASEURL)
	if cmdctx.BaseURL == "" {
		log.Critical("Missing environment variable: " + G3_API_BASEURL)
		os.Exit(1)
	}

	// Get the shared API bearer token.
	cmdctx.Token = os.Getenv(G3_API_TOKEN)
	if cmdctx.Token == "" {
		log.Critical("Missing environment variable: " + G3_API_TOKEN)
		os.Exit(1)
	}

	// Create the cancellation context for the tool.
	// Inspired by: https://pace.dev/blog/2020/02/17/repond-to-ctrl-c-interrupt-signals-gracefully-with-context-in-golang-by-mat-ryer.html
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	cmdctx.Ctx = ctx
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()
	go func() {
		select {
		case <-signalChan: // first signal, cancel context
			log.Critical("\nInterrupt received!")
			cancel()
		case <-ctx.Done():
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()

	// Process the command.
	err = kctx.Run(cmdctx)
	parser.FatalIfErrorf(err)
}
