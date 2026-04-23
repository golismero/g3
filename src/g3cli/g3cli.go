package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/alexeyco/simpletable"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/websocket"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)

const G3_API_BASEURL = "G3_API_BASEURL"
const G3_API_WSURL = "G3_API_WSURL"

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type CmdContext struct {
	Ctx          context.Context
	BaseURL      string
	WebSocketURL string
	Token        string
}

type ScanCmd struct {
	Input  string `short:"i" type:"existingfile" default:"-"     help:"Input file."`
	Output string `short:"o" type:"path"         default:"-"     help:"Output file."`
	ScanID string `arg:""    optional:""                         help:"Optional ID of an existing scan to continue or re-start."`
}

type ProgressCmd struct {
}

type LogsCmd struct {
	Output  string   `short:"o" type:"path"         default:"-"     help:"Output file."`
	ScanID  string   `arg:""    optional:""                         help:"Optional Scan ID."`
	TaskIDs []string `arg:""    optional:""                         help:"Optional task IDs."`
}

type LsCmd struct {
	Output string `short:"o" type:"path"         default:"-"     help:"Output file."`
}

type PsCmd struct {
	Output string `short:"o" type:"path"         default:"-"     help:"Output file."`
}

type CancelCmd struct {
	ScanID string `arg:""    required:""                         help:"Scan ID."`
	TaskID string `arg:""    optional:""                         help:"Task ID."`
}

type ReportCmd struct {
	ScanID string `arg:""    required:""                         help:"Scan ID."`
	Output string `short:"o" type:"path"         default:"-"     help:"Output file."`
}

type ExportCmd struct {
	Beautify bool     `short:"b"                     default:"false" help:"Beautify output data."`
	Output   string   `short:"o" type:"path"         default:"-"     help:"Output file."`
	ScanID   string   `arg:""    required:""                         help:"Scan ID."`
	DataIDs  []string `arg:""    optional:""                         help:"Optional data IDs."`
}

type ToolsCmd struct {
	Output string `short:"o" type:"path"         default:"-"     help:"Output file."`
}

type RmCmd struct {
	Force   bool     `short:"f"                     default:"false" help:"Do not ask for confirmation for dangerous operations."`
	ScanIDs []string `arg:""    required:""                         help:"Scan IDs."`
}

var CLI struct {
	Username string `short:"u" default:"admin" help:"Username."`
	Password string `short:"p" default:"admin" help:"Password."`
	Quiet    bool   `short:"q" default:"false" help:"Quiet mode."`

	Scan     ScanCmd     `cmd:"" aliases:"s" help:"Start a new scan or re-start an existing stopped scan."`
	Progress ProgressCmd `cmd:"" aliases:"w" help:"Show the progress of each running scan in real time."`
	Logs     LogsCmd     `cmd:"" aliases:"f" help:"Show the execution logs of a scan."`
	Ls       LsCmd       `cmd:"" aliases:"l" help:"Show the list of all scans."`
	Ps       PsCmd       `cmd:"" aliases:"t" help:"Show the list of currently running scans."`
	Cancel   CancelCmd   `cmd:"" aliases:"c" help:"Cancel a running scan."`
	Report   ReportCmd   `cmd:"" aliases:"o" help:"Produce a Markdown report for a completed scan."`
	Export   ExportCmd   `cmd:"" aliases:"x" help:"Export the JSON data for a scan."`
	Tools    ToolsCmd    `cmd:"" aliases:"p" help:"Show the list of tools supported by the server."`
	Rm       RmCmd       `cmd:"" aliases:"d" help:"Delete all information of a scan."`
}

func main() {
	var err error

	// Parse the command line options.
	parser := kong.Parse(&CLI,
		kong.Name("g3cli"),
		kong.Description("Golismero3 - The Pentesting Swiss Army Knife"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{Compact: true}),
	)

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

	// Get the API websocket URL.
	cmdctx.WebSocketURL = os.Getenv(G3_API_WSURL)
	if cmdctx.BaseURL == "" {
		log.Critical("Missing environment variable: " + G3_API_WSURL)
		os.Exit(1)
	}

	// When debugging the API, show the URLs.
	if g3lib.DoDebugAPI() {
		log.Debug("API debug mode is on!")
		log.Debug("Base API URL:  " + cmdctx.BaseURL)
		log.Debug("Websocket URL: " + cmdctx.WebSocketURL)
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
			log.Critical("\nSIGTERM received!")
			cancel()
		case <-ctx.Done():
		}
		<-signalChan // second signal, hard exit
		os.Exit(1)
	}()

	// Log in to the server.
	var loginReq g3lib.ReqLogin
	loginReq.Username = CLI.Username
	loginReq.Password = CLI.Password
	loginResp, err := g3lib.MakeApiRequest(ctx, cmdctx.BaseURL, "/auth/login", loginReq)
	if err != nil {
		log.Critical("Malformed response from server: " + err.Error())
		os.Exit(1)
	}
	if loginResp.Status != "success" {
		log.Critical(loginResp.Data)
		os.Exit(1)
	}
	token, ok := loginResp.Data.(string)
	if !ok {
		log.Critical("Malformed response from server.")
		os.Exit(1)
	}
	cmdctx.Token = token

	// Process the command.
	err = parser.Run(cmdctx)
	parser.FatalIfErrorf(err)
}

func (cmd *ScanCmd) Run(vars CmdContext) error {
	input := cmd.Input
	output := cmd.Output
	token := vars.Token
	ctx := vars.Ctx
	baseUrl := vars.BaseURL

	// Get the scan script.
	var scriptBytes []byte
	var err error
	if input == "-" {
		scriptBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Critical(err)
			return err
		}
	} else {
		scriptBytes, err = os.ReadFile(input)
		if err != nil {
			log.Critical("Error reading file " + input + ": " + err.Error())
			return err
		}
	}
	script := string(scriptBytes)

	// Parse the script. We don't need to perform a full validation,
	// so we don't pass the collection of plugins for checking.
	// We only need the list of imports at this stage.
	parsed, err := g3lib.ParseScript(nil, script)
	if err == nil {
		err = validator.New().Struct(parsed)
	}
	if err != nil {
		log.Critical("Error parsing file " + input + ": " + err.Error())
		return err
	}
	log.Debug(
		"\n" +
		"--------------------------------------------------------------------------------\n" +
		"--- Server: " + baseUrl + "\n" +
		"--- Running script:\n" +
		"\n" +
		parsed.String() + "\n" +
		"--------------------------------------------------------------------------------\n")

	// Upload the imported files to the server.
	for index, parsedImport := range parsed.Imports {
		log.Info("Uploading imported file: " + parsedImport.Path)

		// Open the file for reading.
		fd, err := os.Open(parsedImport.Path)
		if err != nil {
			log.Critical("Error reading file " + parsedImport.Path + ": " + err.Error())
			return err
		}
		defer fd.Close()

		// Create a pipe so we can copy the file contents to the HTTP writer.
		bodyReader, bodyWriter := io.Pipe()
		defer bodyReader.Close()
		defer bodyWriter.Close()
		writer := multipart.NewWriter(bodyWriter)
		defer writer.Close()

		// Upload the file in a multipart post request.
		req, err := http.NewRequest("POST", baseUrl + "/file/upload", bodyReader)
		if err != nil {
			log.Critical("Internal error: " + err.Error())
			return err
		}
		req.Header.Add("Content-Type", writer.FormDataContentType())
		go func() {
			part, err := writer.CreateFormField("auth")
			if err != nil {
				log.Critical("Internal error: " + err.Error())
				return
			}
			_, err = part.Write([]byte(token))
			if err != nil {
				log.Critical("Internal error: " + err.Error())
				return
			}
			part, err = writer.CreateFormFile("file", filepath.Base(parsedImport.Path))
			if err != nil {
				log.Critical("Internal error: " + err.Error())
				return
			}
			_, err = io.Copy(part, fd)
			if err != nil {
				log.Critical("Error uploading file " + parsedImport.Path + ": " + err.Error())
				return
			}
			writer.Close()
			bodyWriter.Close()
		}()
		req = req.WithContext(ctx)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Critical("Error uploading imported file" + parsedImport.Path + ": " + err.Error())
			return err
		}
		defer res.Body.Close()

		// Parse the response to get the file ID.
		respBytes, err := io.ReadAll(res.Body)
		if err != nil {
			log.Critical(err.Error())
			return err
		}
		var response g3lib.APIResponse
		if res.StatusCode != http.StatusOK {
			response.Status = "error"
			response.Data = res.Status
			var tmp g3lib.APIResponse
			err = json.Unmarshal(respBytes, &tmp)
			if err == nil {
				_, ok := tmp.Data.(string)
				if ok {
					response.Data = tmp.Data
				}
			}
			err = errors.New(response.Data.(string))
			return err
		}
		err = json.Unmarshal(respBytes, &response)
		if err != nil {
			log.Critical(err.Error())
			return err
		}
		err = validator.New().Struct(response)
		if err != nil {
			log.Critical(err.Error())
			return err
		}
		if response.Status == "error" {
			_, ok := response.Data.(string)
			if !ok {
				response.Data = "Malformed response from server."
			}
			err = errors.New(response.Data.(string))
			return err
		}
		fileid, ok := response.Data.(string)
		if !ok {
			err = errors.New("malformed response from server")
			return err
		}

		// Swap the file path for the file ID.
		parsedImport.Path = fileid
		parsed.Imports[index] = parsedImport
	}

	// Send the scan request to the server.
	var req g3lib.ReqStartScan
	req.Token = token
	if cmd.ScanID != "" {
		req.ScanID = cmd.ScanID
	}
	req.Script = parsed.String()
	resp, err := g3lib.MakeApiRequest(ctx, baseUrl, "/scan/start", req)
	if err != nil {
		log.Critical("Error sending API request: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical(resp.Data)
		return errors.New("malformed response from server")
	}
	scanid, ok := resp.Data.(string)
	if !ok || scanid == "" {
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	// Save the scan ID as output.
	if output == "-" {
		fmt.Println(scanid)
	} else {
		err = os.WriteFile(output, []byte(scanid + "\n"), 0644)
		if err != nil {
			log.Critical("Error writing to file " + output + ": " + err.Error())
			return err
		}
	}
	return nil
}

func (cmd *ProgressCmd) Run(vars CmdContext) error {
	token := vars.Token
	//ctx := vars.Ctx

	// Figure out if we have to show debug output for the API calls.
	doDebugAPI := g3lib.DoDebugAPI()

	// Connect to the websocket API.
	c, _, err := websocket.DefaultDialer.Dial(vars.WebSocketURL, nil)
	if err != nil {
		log.Critical(err.Error())
		return err
	}
	defer c.Close()
	defer c.WriteMessage(websocket.CloseMessage, []byte("")) //nolint:errcheck

	// Send a request for scan progress updates.
	msg := fmt.Sprintf(`{"msgtype":"scanprogress","token":"%s"}`, token)
	if doDebugAPI {
		log.Debug("--> " + msg)
	}
	err = c.WriteMessage(websocket.TextMessage, []byte(msg))
	if err != nil {
		log.Critical(err.Error())
		return err
	}

	// Read the responses and print them forever.
	// FIXME this should happen within the cancellation context.
	log.Info("Receiving progress updates, press Control+C twice to quit...")
	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			log.Critical(err.Error())
			return err
		}
		fmt.Printf("%v\n", string(message)) // FIXME
	}
}

func (cmd *LogsCmd) Run(vars CmdContext) error {
	output := cmd.Output
	token := vars.Token
	ctx := vars.Ctx

	// If no scan ID was given on the command line, get all of them.
	var scanidlist []string
	if cmd.ScanID != "" {
		scanidlist = append(scanidlist, cmd.ScanID)
	} else {
		log.Debug("Querying list of scans...")
		var req g3lib.ReqEnumerateScans
		req.Token = token
		resp, err := g3lib.MakeApiRequest(ctx, vars.BaseURL, "/scan/list", req)
		if err != nil {
			log.Critical("Error sending API request: " + err.Error())
			return err
		}
		if resp.Status != "success" {
			log.Critical(resp.Data)
			return errors.New("malformed response from server")
		}
		if resp.Data != nil {
			tmp, ok := resp.Data.([]interface{})
			if ok {
				for _, tmp2 := range tmp {
					var tmp3 string
					tmp3, ok = tmp2.(string)
					if !ok {
						break
					}
					scanidlist = append(scanidlist, tmp3)
				}
			}
			if !ok {
				log.Criticalf("%v", resp.Data)
				log.Critical("Malformed response from server.")
				return errors.New("malformed response from server")
			}
		}
		if len(scanidlist) == 0 {
			log.Critical("No scans found in database.")
			return errors.New("no scans found in database")
		}
	}

	// If no target IDs were given on the command line, get all of them for the selected scan.
	taskidmap := map[string][]string{}
	if len(cmd.TaskIDs) > 0 {
		taskidmap[cmd.ScanID] = cmd.TaskIDs
	} else {
		for _, scanid := range scanidlist {
			log.Debugf("Querying list of tasks for scan %s...", scanid)
			var req g3lib.ReqQueryScanTaskList
			req.Token = token
			req.ScanID = scanid
			resp, err := g3lib.MakeApiRequest(ctx, vars.BaseURL, "/scan/tasks", req)
			if err != nil {
				log.Critical("Error sending API request: " + err.Error())
				return err
			}
			if resp.Status != "success" {
				log.Critical(resp.Data)
				return errors.New("malformed response from server")
			}
			var taskidlist []string
			if resp.Data != nil {
				tmp, ok := resp.Data.([]interface{})
				if ok {
					for _, tmp2 := range tmp {
						var tmp3 string
						tmp3, ok = tmp2.(string)
						if !ok {
							break
						}
						taskidlist = append(taskidlist, tmp3)
					}
				}
				if !ok {
					log.Criticalf("%v", resp.Data)
					log.Critical("Malformed response from server.")
					return errors.New("malformed response from server")
				}
			}
			if len(taskidlist) == 0 {
				log.Warning("No tasks found for scan: " + scanid)
			} else {
				taskidmap[scanid] = taskidlist
			}
		}
	}

	// Get the logs for each task.
	var allLogs []g3lib.G3TaskLog
	for _, scanid := range scanidlist {
		taskidlist, ok := taskidmap[scanid]
		if ok {
			for _, taskid := range taskidlist {
				log.Debugf("Querying logs for scan %s, task %s...", scanid, taskid)
				var req g3lib.ReqQueryLog
				req.Token = token
				req.ScanID = scanid
				req.TaskID = taskid
				resp, err := g3lib.MakeApiRequest(ctx, vars.BaseURL, "/scan/logs", req)
				if err != nil {
					log.Critical("Error sending API request: " + err.Error())
					return err
				}
				if resp.Status != "success" {
					log.Critical(resp.Data)
					return errors.New("malformed response from server")
				}
				data, ok := resp.Data.(map[string]interface{})
				if !ok {
					return errors.New("malformed response from server")
				}
				tmp1, ok := data["lines"]
				if !ok {
					log.Warning("No log lines for task: " + taskid)
					continue
				}
				if tmp1 == nil {
					log.Warning("No log lines for task: " + taskid)
					continue
				}
				tmp2, ok := tmp1.([]interface{})
				if !ok {
					return errors.New("malformed response from server")
				}
				var lines []g3lib.TaskLogLine
				for _, tmp3 := range tmp2 {
					tmp4, ok := tmp3.(map[string]interface{})
					if !ok {
						return errors.New("malformed response from server")
					}
					tmp5, ok := tmp4["timestamp"]
					if !ok {
						return errors.New("malformed response from server")
					}
					tmp6, ok := tmp5.(float64)
					if !ok {
						return errors.New("malformed response from server")
					}
					tmp7 := int64(tmp6)
					tmp8, ok := tmp4["text"]
					if !ok {
						return errors.New("malformed response from server")
					}
					tmp9, ok := tmp8.(string)
					if !ok {
						return errors.New("malformed response from server")
					}
					var line g3lib.TaskLogLine
					line.Timestamp = tmp7
					line.Text = tmp9
					lines = append(lines, line)
				}
				tmp8, ok := data["start"]
				if !ok {
					return errors.New("malformed response from server")
				}
				tmp9, ok := tmp8.(float64)
				if !ok {
					return errors.New("malformed response from server")
				}
				start := int64(tmp9)
				tmp10, ok := data["end"]
				if !ok {
					return errors.New("malformed response from server")
				}
				tmp11, ok := tmp10.(float64)
				if !ok {
					return errors.New("malformed response from server")
				}
				end := int64(tmp11)
				tmp12, ok := data["scanid"]
				if !ok {
					return errors.New("malformed response from server")
				}
				tmp13, ok := tmp12.(string)
				if !ok || tmp13 != scanid {
					return errors.New("malformed response from server")
				}
				tmp14, ok := data["taskid"]
				if !ok {
					return errors.New("malformed response from server")
				}
				tmp15, ok := tmp14.(string)
				if !ok || tmp15 != taskid {
					return errors.New("malformed response from server")
				}
				var tasklog g3lib.G3TaskLog
				tasklog.ScanID = scanid
				tasklog.TaskID = taskid
				tasklog.Start = start
				tasklog.End = end
				tasklog.Lines = lines
				allLogs = append(allLogs, tasklog)
			}
		}
	}
	log.Debugf("Found %d logs in total.", len(allLogs))

	// Open the output file.
	var fd *os.File
	var err error
	if output == "-" {
		fd = os.Stdout
	} else {
		fd, err = os.OpenFile(output, os.O_RDWR | os.O_CREATE | os.O_TRUNC, 0600)
		if err != nil {
			log.Critical("Error writing to file " + output + ": " + err.Error())
			return err
		}
		defer fd.Close()
	}

	// Output the logs.
	for _, tasklog := range allLogs {
		fmt.Fprintln(fd, "\033[1m--------------------------------------------------------------------------------\033[0m")
		fmt.Fprintln(fd, "\033[1m--- Scan ID: " + tasklog.ScanID + "\033[0m")
		fmt.Fprintln(fd, "\033[1m--- Task ID: " + tasklog.TaskID + "\033[0m")
		fmt.Fprintln(fd, "\033[1m--- Started: " + time.Unix(tasklog.Start, 0).Format(time.RFC850) + "\033[0m")
		fmt.Fprintln(fd, "\033[1m--- Ended:   " + time.Unix(tasklog.End, 0).Format(time.RFC850) + "\033[0m")
		fmt.Fprintln(fd, "\033[1m--------------------------------------------------------------------------------\033[0m")
		for _, logline := range tasklog.Lines {
			fmt.Fprintf(fd, "\033[1m%s:\033[0m %s\033[0m\n", time.Unix(logline.Timestamp, 0).String(), logline.Text)
		}
		fmt.Fprintln(fd, "")
	}
	return nil
}

func (cmd *LsCmd) Run(vars CmdContext) error {
	output := cmd.Output
	token := vars.Token
	baseUrl := vars.BaseURL
	ctx := vars.Ctx

	// Get the list of scan IDs.
	var req g3lib.ReqEnumerateScans
	req.Token = token
	resp, err := g3lib.MakeApiRequest(ctx, baseUrl, "/scan/list", req)
	if err != nil {
		log.Critical("Error sending API request: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical(resp.Data)
		return errors.New("malformed response from server")
	}
	var scanidlist []string
	if resp.Data != nil {
		tmp, ok := resp.Data.([]interface{})
		if ok {
			for _, tmp2 := range tmp {
				var tmp3 string
				tmp3, ok = tmp2.(string)
				if !ok {
					break
				}
				scanidlist = append(scanidlist, tmp3)
			}
		}
		if !ok {
			log.Criticalf("%v", resp.Data)
			log.Critical("Malformed response from server.")
			return errors.New("malformed response from server")
		}
	}
	outputStr := strings.Join(scanidlist, "\n")
	if outputStr != "" {
		outputStr = outputStr + "\n"
	}

	// Save the scan IDs as output.
	if output == "-" {
		fmt.Print(outputStr)
	} else {
		err = os.WriteFile(output, []byte(outputStr), 0644)
		if err != nil {
			log.Critical("Error writing to file " + output + ": " + err.Error())
			return err
		}
	}
	return nil
}

func (cmd *PsCmd) Run(vars CmdContext) error {
	output := cmd.Output
	token := vars.Token
	ctx := vars.Ctx
	baseUrl := vars.BaseURL
	quiet := CLI.Quiet

	// Get the scan progress.
	var req g3lib.ReqGetScanProgressTable
	req.Token = token
	resp, err := g3lib.MakeApiRequest(ctx, baseUrl, "/scan/progress", req)
	if err != nil {
		log.Critical("Error sending API request: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical(resp.Data)
		return errors.New("malformed response from server")
	}
	var scanprogress []g3lib.ScanStatusEntry
	if resp.Data != nil {
		tmp, ok := resp.Data.([]interface{})
		if ok {
			for _, tmp2 := range tmp {
				var tmp3 g3lib.ScanStatusEntry
				var tmp4 map[string]interface{}
				var tmp5 any
				var tmp6 float64
				var tmp7 string

				tmp4, ok = tmp2.(map[string]interface{});   if !ok { break }
				tmp5, ok = tmp4["scanid"];                  if !ok { break }
				tmp3.ScanID, ok = tmp5.(string);            if !ok { break }
				tmp5, ok = tmp4["status"];                  if !ok { break }
				tmp7, ok = tmp5.(string);                   if !ok { break }

				found := false
				for _, status := range g3lib.VALID_STATUS {
					if string(status) == tmp7 {
						tmp3.Status = status
						found = true
						break
					}
				}
				if !found {
					ok = false
					break
				}

				tmp5, ok = tmp4["progress"];                if !ok { break }
				tmp6, ok = tmp5.(float64);                  if !ok { break }
				tmp3.Progress = int(tmp6)
				tmp5, ok = tmp4["message"];                 if !ok { break }
				tmp3.Message, ok = tmp5.(string);           if !ok { break }

				scanprogress = append(scanprogress, tmp3)
			}
		}
		if !ok {
			log.Criticalf("%v", resp.Data)
			log.Critical("Malformed response from server.")
			return errors.New("malformed response from server")
		}
	}

	// Build the text table.
	var outputText string
	if quiet {
		for _, entry := range scanprogress {
			if entry.Status == g3lib.STATUS_RUNNING {
				outputText = outputText + entry.ScanID + "\n"
			}
		}
	} else {
		table := simpletable.New()
		table.Header = &simpletable.Header{
			Cells: []*simpletable.Cell{
				{Align: simpletable.AlignCenter, Text: "SCAN ID"},
				{Align: simpletable.AlignCenter, Text: "STATUS"},
				{Align: simpletable.AlignCenter, Text: "PROGRESS"},
				{Align: simpletable.AlignCenter, Text: "MESSAGE"},
			},
		}
		for _, entry := range scanprogress {
			msg := strings.ReplaceAll(entry.Message, "\n", " ", )
			if len(msg) > 80 {
				msg = msg[:77] + "..."
			}
			r := []*simpletable.Cell{
				{Align: simpletable.AlignCenter, Text: entry.ScanID},
				{Align: simpletable.AlignCenter, Text: string(entry.Status)},
				{Align: simpletable.AlignCenter, Text: fmt.Sprintf("%d%%", entry.Progress)},
				{Align: simpletable.AlignCenter, Text: msg},
			}
			table.Body.Cells = append(table.Body.Cells, r)
		}
		table.SetStyle(simpletable.StyleCompactLite)
		outputText = "\n" + table.String() + "\n\n"
	}

	// Save the table as output.
	if output == "-" {
		fmt.Print(outputText)
	} else {
		err = os.WriteFile(output, []byte(outputText), 0644)
		if err != nil {
			log.Critical("Error writing to file " + output + ": " + err.Error())
			return err
		}
	}
	return nil
}

func (cmd *CancelCmd) Run(vars CmdContext) error {

	// Cancel the running scan.
	var req g3lib.ReqStopScan
	req.Token = vars.Token
	req.ScanID = cmd.ScanID
	resp, err := g3lib.MakeApiRequest(vars.Ctx, vars.BaseURL, "/scan/stop", req)
	if err != nil {
		log.Critical("Error sending API request: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical(resp.Data)
		return errors.New("malformed response from server")
	}
	return nil
}

func (cmd *ReportCmd) Run(vars CmdContext) error {
	output := cmd.Output
	token := vars.Token
	ctx := vars.Ctx
	baseUrl := vars.BaseURL

	// Request a report.
	var req g3lib.ReqReport
	req.Token = token
	req.ScanID = cmd.ScanID
	resp, err := g3lib.MakeApiRequest(ctx, baseUrl, "/scan/report", req)
	if err != nil {
		log.Critical("Error sending API request: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical(resp.Data)
		return errors.New("malformed response from server")
	}
	result, ok := resp.Data.(map[string]interface{})
	if !ok {
		log.Criticalf("%v", resp.Data)
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	// If there were parsing errors during the report generation, show them.
	errorIface, ok := result["errors"]
	if ok {
		errorText, ok := errorIface.(string)
		if !ok {
			log.Criticalf("%v", resp.Data)
			log.Critical("Malformed response from server.")
			return errors.New("malformed response from server")
		}
		log.Error(
			"Errors were encountered when generating the report:\n---------------------------------------------------\n" + errorText)
	}

	// Get the report text.
	reportIface, ok := result["report"]
	if !ok {
		log.Criticalf("%v", resp.Data)
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}
	reportText, ok := reportIface.(string)
	if !ok {
		log.Criticalf("%v", resp.Data)
		log.Critical("Malformed response from server.")
		return errors.New("malformed response from server")
	}

	// Save the report text.
	if output == "-" {
		fmt.Print(reportText)
	} else {
		err = os.WriteFile(output, []byte(reportText), 0644)
		if err != nil {
			log.Critical("Error writing to file " + output + ": " + err.Error())
			return err
		}
	}
	return nil
}

func (cmd *ExportCmd) Run(vars CmdContext) error {
	output := cmd.Output
	token := vars.Token
	ctx := vars.Ctx

	// If no data IDs were given on the command line, get all of them.
	var dataidlist []string
	if len(cmd.DataIDs) > 0 {
		dataidlist = cmd.DataIDs
	} else {
		log.Debugf("Querying IDs of data objects for scan %s...", cmd.ScanID)
		var req g3lib.ReqGetScanDataIDs
		req.Token = token
		req.ScanID = cmd.ScanID
		resp, err := g3lib.MakeApiRequest(ctx, vars.BaseURL, "/scan/datalist", req)
		if err != nil {
			log.Critical("Error sending API request: " + err.Error())
			return err
		}
		if resp.Status != "success" {
			log.Critical(resp.Data)
			return errors.New("malformed response from server")
		}
		if resp.Data != nil {
			tmp, ok := resp.Data.([]interface{})
			if ok {
				for _, tmp2 := range tmp {
					var tmp3 string
					tmp3, ok = tmp2.(string)
					if !ok {
						break
					}
					dataidlist = append(dataidlist, tmp3)
				}
			}
			if !ok {
				log.Criticalf("%v", resp.Data)
				log.Critical("Malformed response from server.")
				return errors.New("malformed response from server")
			}
		}
		if len(dataidlist) == 0 {
			log.Critical("No data found in scan.")
			return errors.New("no data found in scan")
		}
	}

	// Open the output file.
	var fd *os.File
	var err error
	if output == "-" {
		fd = os.Stdout
	} else {
		fd, err = os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Critical("Error writing to file " + output + ": " + err.Error())
			return err
		}
		defer fd.Close()
	}

	// Get the data objects in batches and output them.
	if cmd.Beautify {
		fmt.Fprintf(fd, "[\n")
	} else {
		fmt.Fprintf(fd, "[")
	}
	batchSize := 20
	for index := 0; index < len(dataidlist); index += batchSize {
		sliceEnd := min(index+batchSize, len(dataidlist))
		batch := dataidlist[index:sliceEnd]
		var req g3lib.ReqLoadData
		req.Token = token
		req.ScanID = cmd.ScanID
		req.DataIDs = batch
		resp, err := g3lib.MakeApiRequest(ctx, vars.BaseURL, "/scan/data", req)
		if err != nil {
			log.Critical("Error sending API request: " + err.Error())
			return err
		}
		if resp.Status != "success" {
			log.Critical(resp.Data)
			return errors.New("malformed response from server")
		}
		if resp.Data != nil {
			tmp, ok := resp.Data.([]interface{})
			if !ok {
				log.Critical(resp.Data)
				return errors.New("malformed response from server")
			}
			for idx, tmp2 := range tmp {
				var jsonBytes []byte
				if cmd.Beautify {
					jsonBytes, err = json.MarshalIndent(tmp2, "  ", "  ")
				} else {
					jsonBytes, err = json.Marshal(tmp2)
				}
				if err != nil {
					log.Error(err.Error())
					continue
				}
				if cmd.Beautify {
					fmt.Fprintf(fd, "  ")
				}
				_, err = fd.Write(jsonBytes)
				if err != nil {
					log.Critical(err.Error())
					return err
				}
				if idx < len(tmp) - 1 || sliceEnd < len(dataidlist) - 1 {
					if cmd.Beautify {
						fmt.Fprintf(fd, ",\n")
					} else {
						fmt.Fprintf(fd, ",")
					}
				}
			}
		}
	}
	if cmd.Beautify {
		fmt.Fprintf(fd, "\n]\n")
	} else {
		fmt.Fprintf(fd, "]")
	}
	return nil
}

func (cmd *ToolsCmd) Run(vars CmdContext) error {
	output := cmd.Output
	token := vars.Token
	ctx := vars.Ctx
	baseUrl := vars.BaseURL

	// Get the remote list of plugins.
	var req g3lib.ReqListPlugins
	req.Token = token
	resp, err := g3lib.MakeApiRequest(ctx, baseUrl, "/plugin/list", req)
	if err != nil {
		log.Critical("Error sending API request: " + err.Error())
		return err
	}
	if resp.Status != "success" {
		log.Critical(resp.Data)
		return errors.New("malformed response from server")
	}
	tmp1, ok := resp.Data.([]interface{})
	if !ok {
		log.Critical(resp.Data)
		return errors.New("malformed response from server")
	}
	var pluginList []map[string]string
	for _, tmp2 := range tmp1 {
		tmp3, ok := tmp2.(map[string]interface{})
		if !ok {
			return errors.New("malformed response from server")
		}
		pluginData := map[string]string{}
		tmp4, ok := tmp3["name"]
		if !ok {
			return errors.New("malformed response from server")
		}
		tmp5, ok := tmp4.(string)
		if !ok {
			return errors.New("malformed response from server")
		}
		pluginData["name"] = tmp5
		tmp6, ok := tmp3["url"]
		if !ok {
			return errors.New("malformed response from server")
		}
		tmp7, ok := tmp6.(string)
		if !ok {
			return errors.New("malformed response from server")
		}
		pluginData["url"] = tmp7
		tmp8, ok := tmp3["description"]
		if !ok {
			return errors.New("malformed response from server")
		}
		tmp9, ok := tmp8.(string)
		if !ok {
			return errors.New("malformed response from server")
		}
		pluginData["description"] = tmp9
		pluginList = append(pluginList, pluginData)
	}

	// Open the output file.
	var fd *os.File
	if output == "-" {
		fd = os.Stdout
	} else {
		fd, err = os.OpenFile(output, os.O_RDWR | os.O_CREATE | os.O_TRUNC, 0600)
		if err != nil {
			log.Critical("Error writing to file " + output + ": " + err.Error())
			return err
		}
		defer fd.Close()
	}

	// If -q is used, print only the names of the plugins.
	// If not, print a nicer looking output with all of the human descriptions and stuff.
	if !CLI.Quiet {
		fmt.Fprintln(fd, "")
	}
	for _, pluginData := range pluginList {
		if CLI.Quiet {
			fmt.Fprintln(fd, pluginData["name"])
		} else {
			fmt.Fprintln(fd, fmt.Sprint("Name:        " + pluginData["name"]))
			fmt.Fprintln(fd, fmt.Sprint("Homepage:    " + pluginData["url"]))
			fmt.Fprintln(fd, fmt.Sprint("Description: " + pluginData["description"]))
			fmt.Fprintln(fd, "")
		}
	}
	return nil
}

func (cmd *RmCmd) Run(vars CmdContext) error {
	token := vars.Token
	baseUrl := vars.BaseURL
	ctx := vars.Ctx
	force := cmd.Force
	arguments := cmd.ScanIDs

	// Ask the user for confirmation, unless -f was used.
	if ! force {
		var msg string
		if len(arguments) == 1 {
			msg = fmt.Sprintf("Do you really want to DELETE the scan %s? This is IRREVERSIBLE!", arguments[0])
		} else {
			msg = fmt.Sprintf("Do you really want to DELETE the selected %d scans? This is IRREVERSIBLE!", len(arguments))
		}
		confirm := g3lib.AskForConfirmation(msg)
		if ! confirm {
			log.Error("User cancelled the operation.")
			return errors.New("user cancelled the operation")
		}
	}

	// Send a cancel message, just in case.
	//
	// If the scan was actually running there's a chance for a small
	// race condition and a worker or scanner may still write some
	// scan related info. I think? Haven't thought much about it.
	//
	// You probably shouldn't delete a running scan anyway.
	//
	for _, scanid := range arguments {
		log.Debugf("Stopping scan with ID %s...", scanid)
		var req g3lib.ReqStopScan
		req.Token = token
		req.ScanID = scanid
		resp, err := g3lib.MakeApiRequest(ctx, baseUrl, "/scan/stop", req)
		if err != nil {
			log.Critical("Error sending API request: " + err.Error())
		} else if resp.Status != "success" {
			log.Critical(resp.Data)
		}
	}

	// Delete the scan data.
	for _, scanid := range arguments {
		log.Infof("Deleting scan with ID %s...", scanid)
		var req g3lib.ReqDeleteScan
		req.Token = token
		req.ScanID = scanid
		resp, err := g3lib.MakeApiRequest(ctx, baseUrl, "/scan/delete", req)
		if err != nil {
			log.Critical("Error sending API request: " + err.Error())
		} else if resp.Status != "success" {
			log.Critical(resp.Data)
		}
	}
	log.Info("...done!")
	return nil
}
