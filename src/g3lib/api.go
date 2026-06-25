package g3lib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/websocket"

	log "github.com/golismero/g3/src/g3log"
)

const G3_DEBUG_API = "G3_DEBUG_API"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func DoDebugAPI() bool {
	return strings.ToLower(os.Getenv(G3_DEBUG_API)) == "true"
}

func ValidateHttpRequest(r *http.Request) error {
	if r.Method != "POST" {
		return errors.New("invalid HTTP method")
	}
	if h, ok := r.Header["Content-Type"]; !ok || len(h) != 1 || h[0] != "application/json" {
		return errors.New("invalid or missing Content-Type header")
	}
	if h, ok := r.Header["Content-Length"]; !ok || len(h) != 1 || h[0] == "0" {
		return errors.New("missing payload")
	}
	return nil
}

// Make an API request as a client.
func MakeApiRequest(ctx context.Context, baseurl string, endpoint string, token string, body any) (*APIResponse, error) {

	// Figure out if we have to show debug output for the API calls.
	doDebugAPI := DoDebugAPI()

	// Validate the request structure.
	err := validator.New().Struct(body)
	if err != nil {
		return nil, err
	}

	// Encode the request structure as JSON.
	jsonBytes, err := json.Marshal(body)
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
	// envelope. Mirrors the 2xx convention documented on DownloadFile/UploadFile.
	var response APIResponse
	if res.StatusCode >= 200 && res.StatusCode < 300 {

		// Decode the response bytes.
		// If there are none, this is an error, regardless of the HTTP status code.
		err = json.Unmarshal(respBytes, &response)
		if err != nil {
			return nil, err
		}

		// Validate the response structure.
		err = validator.New().Struct(response)

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
		err = json.Unmarshal(respBytes, &tmp)
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

	// Validate the request structure.
	if err := validator.New().Struct(body); err != nil {
		return err
	}

	// Encode the request structure as JSON.
	jsonBytes, err := json.Marshal(body)
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
	var envelope APIResponse
	if jerr := json.Unmarshal(respBytes, &envelope); jerr == nil {
		if msg, ok := envelope.Data.(string); ok && msg != "" {
			return errors.New(msg)
		}
	}
	return errors.New(res.Status)
}

// UploadFile POSTs the contents of src to endpoint as a multipart form with the
// given field name and filename, using bearer-token auth. Returns the parsed
// JSON envelope on 2xx, or an error containing the server's message on non-2xx.
//
// The whole file is buffered in memory before the request fires. That's
// acceptable for the upload sizes g3 supports (importer inputs, plugin
// artifacts); if streaming becomes necessary, switch to io.Pipe with a
// goroutine — see g3cli's inline pattern for a reference implementation.
func UploadFile(ctx context.Context, baseurl string, endpoint string, token string, fieldName string, filename string, src io.Reader) (*APIResponse, error) {

	doDebugAPI := DoDebugAPI()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, src); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	url := baseurl + endpoint
	if doDebugAPI {
		log.Debug(endpoint + " --> multipart upload, field=" + fieldName + " filename=" + filename)
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	respBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if doDebugAPI {
		log.Debug("<-- " + string(respBytes))
	}

	var response APIResponse
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(respBytes, &response); err != nil {
			return nil, err
		}
		if response.Status == "error" {
			msg, ok := response.Data.(string)
			if !ok {
				msg = "Malformed response from server."
			}
			return &response, errors.New(msg)
		}
		return &response, nil
	}

	// Non-2xx: try to surface the JSON-envelope message; otherwise use HTTP status text.
	response.Status = "error"
	response.Data = res.Status
	var tmp APIResponse
	if err := json.Unmarshal(respBytes, &tmp); err == nil {
		if msg, ok := tmp.Data.(string); ok {
			response.Data = msg
		}
	}
	return &response, errors.New(response.Data.(string))
}

func SendApiResponse(w http.ResponseWriter, data any) {
	var response APIResponse
	response.Status = "success"
	response.Data = data
	w.WriteHeader(http.StatusOK)
	response.Write(w)
}

func SendApiError(w http.ResponseWriter, statusCode int, errorMsg string) {
	var response APIResponse
	response.Status = "error"
	response.Data = errorMsg
	w.WriteHeader(statusCode)
	response.Write(w)
}

type WSRequest struct {
	MsgType string              `json:"msgtype"             validate:"required"`
	ScanID string               `json:"scanid,omitempty"    validate:"omitempty,uuid"`
}

type WSResponse struct {
	MsgType string              `json:"msgtype"             validate:"required"`
	Data any                    `json:"data,omitempty"`
}

type APIResponse struct {
	Status string               `json:"status"              validate:"required"`
	Data any                    `json:"data,omitempty"`
}
func (resp *APIResponse) Write(w http.ResponseWriter) {
	respBytes, err := json.Marshal(*resp)
	if err != nil {
		log.Error("Error encoding API response: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError) //nolint:errcheck
		return
	}
	w.Write(respBytes) //nolint:errcheck
}

type ReqStartScan struct {
	Script string               `json:"script"              validate:"required"`
}
func (req *ReqStartScan) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqCreateScan struct {
}
func (req *ReqCreateScan) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqAddTargets struct {
	ScanID  string   `json:"scanid"              validate:"uuid"`
	Targets []string `json:"targets"             validate:"required,min=1,dive,required"`
}
func (req *ReqAddTargets) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqInsertData struct {
	ScanID string   `json:"scanid"              validate:"uuid"`
	Data   []G3Data `json:"data"                validate:"required,min=1"`
}
func (req *ReqInsertData) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqImport struct {
	ScanID string `json:"scanid"              validate:"uuid"`
	Tool   string `json:"tool"                validate:"required"`
	FileID string `json:"fileid"              validate:"required,uuid4"`
}
func (req *ReqImport) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqStopScan struct {
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqStopScan) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqEnumerateScans struct {
}
func (req *ReqEnumerateScans) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqDeleteScan struct {
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqDeleteScan) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqGetScanProgressTable struct {
}
func (req *ReqGetScanProgressTable) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqGetScanDataIDs struct {
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqGetScanDataIDs) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqLoadData struct {
	ScanID  string   `json:"scanid"              validate:"uuid"`
	DataIDs []string `json:"dataids"             validate:"omitempty,dive,mongodb"`
	TaskID  string   `json:"taskid,omitempty"    validate:"omitempty,uuid4"`
}
func (req *ReqLoadData) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqTaskArtifacts struct {
	ScanID string `json:"scanid" validate:"required,uuid"`
	TaskID string `json:"taskid" validate:"required,uuid"`
}
func (req *ReqTaskArtifacts) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqTaskCancel struct {
	ScanID  string   `json:"scanid"  validate:"required,uuid"`
	TaskIDs []string `json:"taskids" validate:"required,min=1,dive,uuid"`
}
func (req *ReqTaskCancel) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqTaskDispatch struct {
	ScanID string `json:"scanid" validate:"required,uuid"`
	Kind   string `json:"kind"   validate:"required,oneof=tool report"`
	Tool   string `json:"tool"   validate:"required"`
	// kind=tool fields: server auto-evaluates plugin.Commands[i].Condition
	// against the dataid's G3Data and dispatches every matching command.
	DataID string `json:"dataid,omitempty" validate:"omitempty,mongodb"`
	// kind=report fields:
	Preset string `json:"preset,omitempty"`
}

func (req *ReqTaskDispatch) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqQueryLog struct {
	ScanID string               `json:"scanid"              validate:"uuid"`
	TaskID string               `json:"taskid"              validate:"omitempty,uuid"`
}
func (req *ReqQueryLog) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqQueryScanTaskList struct {
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqQueryScanTaskList) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqQueryScanTaskStatus struct {
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqQueryScanTaskStatus) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqListPlugins struct {
}
func (req *ReqListPlugins) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqGetEnv struct {
}
func (req *ReqGetEnv) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

// PluginListItem is the human/GUI-facing plugin summary served by
// /plugin/list. The three capability booleans are derived server-side from
// the plugin definition; a plugin may expose any combination of them, so
// consumers filter on the flags rather than inferring capability from the
// name or category:
//   Importer — accepts a file to import      (plugin.Importer != nil)
//   Reporter — generates downloadable reports (plugin.Reporter != nil)
//   Runnable — has at least one tool command  (len(plugin.Commands) > 0)
type PluginListItem struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Importer    bool   `json:"importer"`
	Reporter    bool   `json:"reporter"`
	Runnable    bool   `json:"runnable"`
}

type ReqCheckScriptSyntax struct {
	Script string               `json:"script"              validate:"required"`
}
func (req *ReqCheckScriptSyntax) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This structure wraps a websocket connection to ensure concurrency.

type SyncWebSocket struct {
	mread sync.Mutex
	mwrite sync.Mutex
	conn *websocket.Conn
}

func WrapWebSocket(conn *websocket.Conn) *SyncWebSocket {
	sws := SyncWebSocket{}
	sws.conn = conn
	return &sws
}

func (sws *SyncWebSocket) ReadRequest() (*WSRequest, error) {
	for {
		sws.mread.Lock()
		messageType, data, err := sws.conn.ReadMessage()
		sws.mread.Unlock()
		if err != nil {
			return nil, err
		}
		if messageType == websocket.PingMessage {
			sws.mwrite.Lock()
			sws.conn.WriteMessage(websocket.PongMessage, data) //nolint:errcheck
			sws.mwrite.Unlock()
			continue
		}
		if messageType == websocket.CloseMessage {
			return nil, nil
		}
		if messageType != websocket.TextMessage {
			err = errors.New("invalid message type")
			return nil, err
		}
		var request WSRequest
		err = json.Unmarshal(data, &request)
		return &request, err
	}
}

func (sws *SyncWebSocket) WriteResponse(response WSResponse) error {
	data, err := json.Marshal(response)
	if err == nil {
		sws.mwrite.Lock()
		err = sws.conn.WriteMessage(websocket.TextMessage, data)
		sws.mwrite.Unlock()
	}
	return err
}

func (sws *SyncWebSocket) WriteData(msgtype string, data any) error {
	response := WSResponse{}
	response.MsgType = msgtype
	response.Data = data
	return sws.WriteResponse(response)
}

func (sws *SyncWebSocket) WriteSuccess() error {
	response := WSResponse{}
	response.MsgType = "success"
	return sws.WriteResponse(response)
}

func (sws *SyncWebSocket) WriteError(text string) error {
	response := WSResponse{}
	response.MsgType = "error"
	response.Data = text
	return sws.WriteResponse(response)
}
