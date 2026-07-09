package g3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	log "github.com/golismero/g3/src/g3/log"
)

const G3_DEBUG_API = "G3_DEBUG_API"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type APIResponse struct {
	Status string    `json:"status"              validate:"required"`
	Data any         `json:"data,omitempty"`
}

type ReqStartScan struct {
	Script string    `json:"script"              validate:"required"`
}

type ReqCreateScan struct {
}

type ReqAddTargets struct {
	ScanID  string   `json:"scanid"              validate:"uuid"`
	Targets []string `json:"targets"             validate:"required,min=1,dive,required"`
}

type ReqInsertData struct {
	ScanID string    `json:"scanid"              validate:"uuid"`
	Data   []Data    `json:"data"                validate:"required,min=1"`
}

type ReqImport struct {
	ScanID string    `json:"scanid"              validate:"uuid"`
	Tool   string    `json:"tool"                validate:"required"`
	FileID string    `json:"fileid"              validate:"required,uuid"`
}

type ReqStopScan struct {
	ScanID string    `json:"scanid"              validate:"uuid"`
}

type ReqEnumerateScans struct {
}

type ReqDeleteScan struct {
	ScanID string    `json:"scanid"              validate:"uuid"`
}

type ReqGetScanProgressTable struct {
}

type ReqGetScanDataIDs struct {
	ScanID string    `json:"scanid"              validate:"uuid"`
}

type ReqLoadData struct {
	ScanID  string   `json:"scanid"              validate:"uuid"`
	DataIDs []string `json:"dataids"             validate:"omitempty,dive,mongodb"`
	TaskID  string   `json:"taskid,omitempty"    validate:"omitempty,uuid"`
}

type ReqTaskArtifacts struct {
	ScanID string    `json:"scanid"              validate:"required,uuid"`
	TaskID string    `json:"taskid"              validate:"required,uuid"`
}

type ReqTaskCancel struct {
	ScanID  string   `json:"scanid"              validate:"required,uuid"`
	TaskIDs []string `json:"taskids"             validate:"required,min=1,dive,uuid"`
}

type ReqTaskDispatch struct {
	ScanID string    `json:"scanid"              validate:"required,uuid"`
	Kind   string    `json:"kind"                validate:"required,oneof=tool report"`
	Tool   string    `json:"tool"                validate:"required"`
	DataID string    `json:"dataid,omitempty"    validate:"omitempty,mongodb"`
	Preset string    `json:"preset,omitempty"`
}

type ReqQueryLog struct {
	ScanID string    `json:"scanid"              validate:"uuid"`
	TaskID string    `json:"taskid"              validate:"omitempty,uuid"`
}

type ReqQueryScanTaskList struct {
	ScanID string    `json:"scanid"              validate:"uuid"`
}

type ReqQueryScanTaskStatus struct {
	ScanID string    `json:"scanid"              validate:"uuid"`
}

type ReqListPlugins struct {
}

type ReqGetEnv struct {
}

type ReqCheckScriptSyntax struct {
	Script string    `json:"script"              validate:"required"`
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type LogEntry struct {
	Timestamp int64  `json:"timestamp"   validate:"gte=0"`
	ScanID    string `json:"scanid"      validate:"required,uuid"`
	TaskID    string `json:"taskid"      validate:"required,uuid"`
	Text      string `json:"text"`
}

type TaskLogLine struct {
	Timestamp int64  `json:"timestamp"       validate:"gte=0"`
	Text      string `json:"text"`
}
type G3TaskLog struct {
	ScanID string        `json:"scanid"          validate:"required,uuid"`
	TaskID string        `json:"taskid"          validate:"required,uuid"`
	Start  int64         `json:"start,omitempty" validate:"gte=0"`
	End    int64         `json:"end,omitempty"   validate:"gte=0"`
	Lines  []TaskLogLine `json:"lines,omitempty" validate:"dive"`
}

// Remove ANSI escapes from a string.
// https://github.com/acarl005/stripansi/blob/master/stripansi.go
var RE_ANSI = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))")
func StripAnsi(s string) string {
	return RE_ANSI.ReplaceAllString(s, "")
}

func (log G3TaskLog) String() string {
	var text string
	for _, line := range log.Lines {
		text = text + fmt.Sprintf("[%s]\t%s\n", time.Unix(line.Timestamp, 0), StripAnsi(line.Text))
	}
	return text
}

type ScanStatusEntry struct {
	ScanID   string       `json:"scanid"      validate:"required,uuid"`
	Status   G3SCANSTATUS `json:"status"      validate:"required"`
	Progress int          `json:"progress"    validate:"gte=0,lte=100"`
	Message  string       `json:"message"`
}

type TaskStatusEntry struct {
	TaskID     string `json:"taskid"                   validate:"required,uuid"`
	Tool       string `json:"tool,omitempty"`
	Worker     string `json:"worker,omitempty"`
	State      string `json:"state,omitempty"`
	DispatchTS int64  `json:"dispatch_ts,omitempty"`
	StartTS    int64  `json:"start_ts,omitempty"`
	CompleteTS int64  `json:"complete_ts,omitempty"`
	ErrorMsg   string `json:"error_msg,omitempty"`
	FirstLogTS int64  `json:"first_log_ts"             validate:"gte=0"`
	LastLogTS  int64  `json:"last_log_ts"              validate:"gte=0"`
	LineCount  int    `json:"line_count"               validate:"gte=0"`
	AgeSeconds int64  `json:"age_seconds"              validate:"gte=0"`
}

type ScanTaskStatusResponse struct {
	ScanStatus G3SCANSTATUS      `json:"scan_status"`
	Tasks      []TaskStatusEntry `json:"tasks"`
}

type TaskState struct {
	TaskID     string `json:"taskid"`
	Tool       string `json:"tool,omitempty"`
	DispatchTS int64  `json:"dispatch_ts,omitempty"`
	Worker     string `json:"worker,omitempty"`
	StartTS    int64  `json:"start_ts,omitempty"`
	State      string `json:"state,omitempty"`
	CompleteTS int64  `json:"complete_ts,omitempty"`
	ErrorMsg   string `json:"error_msg,omitempty"`
}

type G3MESSAGETYPE string
const (
	G3_MSG_TASK     G3MESSAGETYPE = "task"
	G3_MSG_SCAN     G3MESSAGETYPE = "scan"
	G3_MSG_STATUS   G3MESSAGETYPE = "status"
	G3_MSG_CANCEL   G3MESSAGETYPE = "cancel"
	G3_MSG_STOP     G3MESSAGETYPE = "stop"
	G3_MSG_RESPONSE G3MESSAGETYPE = "response"
	G3_MSG_REPORT   G3MESSAGETYPE = "report"
	G3_MSG_DISPATCH G3MESSAGETYPE = "dispatch"
)
var G3_VALID_MSG = [...]G3MESSAGETYPE{G3_MSG_TASK, G3_MSG_SCAN, G3_MSG_STATUS, G3_MSG_CANCEL, G3_MSG_RESPONSE, G3_MSG_REPORT, G3_MSG_DISPATCH}

type G3SCANSTATUS string
const (
	G3_STATUS_WAITING  G3SCANSTATUS = "WAITING"
	G3_STATUS_RUNNING  G3SCANSTATUS = "RUNNING"
	G3_STATUS_ERROR    G3SCANSTATUS = "ERROR"
	G3_STATUS_CANCELED G3SCANSTATUS = "CANCELED"
	G3_STATUS_FINISHED G3SCANSTATUS = "FINISHED"
	G3_STATUS_UNKNOWN  G3SCANSTATUS = "UNKNOWN"
	G3_STATUS_MANAGED  G3SCANSTATUS = "MANAGED"
)
var G3_VALID_STATUS = [...]G3SCANSTATUS{G3_STATUS_WAITING, G3_STATUS_RUNNING, G3_STATUS_ERROR, G3_STATUS_CANCELED, G3_STATUS_FINISHED, G3_STATUS_UNKNOWN, G3_STATUS_MANAGED}

const NIL_TASKID = "00000000-0000-0000-0000-000000000000"

type G3Message struct {
	MessageType G3MESSAGETYPE   `json:"msgtype"     validate:"required"`
	SenderID string             `json:"senderid"    validate:"required"`
	ScanID string               `json:"scanid"      validate:"required,uuid"`
}

type G3TaskMessage struct {
	G3Message
	TaskID string               `json:"taskid"      validate:"required,uuid"`
}

type G3Task struct {            // MessageType: MSG_TASK
	G3TaskMessage
	DataID string               `json:"dataid"      validate:"required,mongodb"`
	Tool string                 `json:"tool"        validate:"required"`
	Index int                   `json:"index"       validate:"gte=0"`
}

type G3ReportTask struct {      // MessageType: MSG_REPORT
	G3TaskMessage
	Tool   string `json:"tool"   validate:"required"`
	Preset string `json:"preset"`
}

type G3Dispatch struct {        // MessageType: MSG_DISPATCH
	G3TaskMessage
	Kind   string `json:"kind"   validate:"required,oneof=tool report"`
	Tool   string `json:"tool"   validate:"required"`
	// kind=tool fields:
	DataID string `json:"dataid,omitempty" validate:"omitempty,mongodb"`
	Index  int    `json:"index,omitempty"  validate:"gte=0"`
	// kind=report fields:
	Preset string `json:"preset,omitempty"`
}

type G3Response struct {        // MessageType: MSG_RESPONSE
	G3TaskMessage
	Response []string           `json:"response"    validate:"dive,mongodb"`
}

type G3CancelTask struct {      // MessageType: MSG_CANCEL
	G3Message
	Tasks []string              `json:"tasks"       validate:"required"`
	Handled bool                `json:"handled"`
}

type G3Scan struct {            // MessageType: MSG_SCAN
	G3Message
	Mode string                 `json:"mode"        validate:"required"`
	Pipelines [][]string        `json:"pipelines"`  // can be empty
	Report *ReportStatement     `json:"report,omitempty"`
}

type G3ScanStatus struct {      // MessageType: MSG_STATUS
	G3Message
	Status G3SCANSTATUS         `json:"status"`
	Progress *int               `json:"progress,omitempty"`
	Message string       	    `json:"message"`
	Seq uint64                  `json:"seq"`
}

type G3ScanStop struct {        // MessageType: MSG_STOP
	G3Message
}

type G3ScanRemoved struct {
	ScanID string               `json:"scanid"      validate:"required,uuid"`
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func DoDebugAPI() bool {
	return strings.ToLower(os.Getenv(G3_DEBUG_API)) == "true"
}

// Make an API request as a client.
func MakeApiRequest(ctx context.Context, baseurl string, endpoint string, token string, body any) (*APIResponse, error) {

	// Figure out if we have to show debug output for the API calls.
	doDebugAPI := DoDebugAPI()

	// Encode the request structure as JSON.
	jsonBytes, err := EncodeJSON(body)
	if err != nil {
		return nil, err
	}

	// Get the endpoint URL.
	url := baseurl + endpoint		// FIXME make this fancy

	// When debugging, show the request.
	if doDebugAPI {
		log.Debug(endpoint + " --> " + string(jsonBytes))
	}

	// Make the HTTP request.
	r, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}
	r = r.WithContext(ctx)
	r.Header.Add("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer " + token)
	client := http.DefaultClient
	res, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Read the response bytes, if any.
	respBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if doDebugAPI {
		log.Debug("<-- " + string(respBytes))
	}

	// If the HTTP request was successful...
	// Any 2xx is a success, not just 200 OK: async endpoints like
	// /scan/task/dispatch reply 202 Accepted with a normal {status,data}
	// envelope.
	var response APIResponse
	if res.StatusCode >= 200 && res.StatusCode < 300 {

		// Decode the response bytes.
		// If there are none, this is an error, regardless of the HTTP status code.
		err = DecodeJSON(respBytes, &response)
		if err != nil {
			return nil, err
		}

		// We may get a 2xx with an error status, in theory.
		// The server should never do this, but let's cover that case anyway.
		if response.Status == "error" {
			_, ok := response.Data.(string)
			if !ok {
				response.Data = "Malformed response from server."
			}
			if err == nil {
				err = errors.New(response.Data.(string))
			}
		}

	// If the HTTP request failed...
	} else {

		// Try to decode the response bytes.
		// If there are none or there is an error when decoding,
		// use the HTTP status text as an error message.
		response.Status = "error"
		response.Data = res.Status
		var tmp APIResponse
		err = DecodeJSON(respBytes, &tmp)
		if err == nil {
			_, ok := tmp.Data.(string)
			if ok {
				response.Data = tmp.Data
			}
		}
		err = errors.New(response.Data.(string))
	}
	return &response, err
}

// DownloadFile is the binary-response sibling of MakeApiRequest. It POSTs the
// JSON body with bearer auth, streams a successful response into dst, and
// surfaces JSON error envelopes from non-2xx responses as Go errors.
//
// The endpoint must respond with a binary body on success (any non-JSON
// Content-Type is fine; the helper doesn't inspect it) and a standard
// {status,data} JSON envelope on failure, per the SendApiError convention.
func DownloadFile(ctx context.Context, baseurl string, endpoint string, token string, body any, dst io.Writer) error {

	// Figure out if we have to show debug output for the API calls.
	doDebugAPI := DoDebugAPI()

	// Encode the request structure as JSON.
	jsonBytes, err := EncodeJSON(body)
	if err != nil {
		return err
	}

	// Get the endpoint URL.
	url := baseurl + endpoint

	// When debugging, show the request.
	if doDebugAPI {
		log.Debug(endpoint + " --> " + string(jsonBytes))
	}

	// Make the HTTP request.
	r, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	r = r.WithContext(ctx)
	r.Header.Add("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// On success, stream the body verbatim into dst.
	if res.StatusCode == http.StatusOK {
		_, err := io.Copy(dst, res.Body)
		return err
	}

	// On non-2xx, attempt to decode the JSON error envelope.
	respBytes, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		return errors.New(res.Status)
	}
	if doDebugAPI {
		log.Debug("<-- " + string(respBytes))
	}
	var response APIResponse
	if err := DecodeJSON(respBytes, &response); err != nil {
		return errors.New(res.Status)
	}
	var msg = res.Status
	if x, ok := response.Data.(string); ok {
		msg = x
	}
	return errors.New(msg)
}
