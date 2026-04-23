package g3lib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/websocket"

	log "golismero.com/g3log"
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
func MakeApiRequest(ctx context.Context, baseurl string, endpoint string, body any) (*APIResponse, error) {

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
	var response APIResponse
	if res.StatusCode == http.StatusOK {

		// Decode the response bytes.
		// If there are none, this is an error, regardless of the HTTP status code.
		err = json.Unmarshal(respBytes, &response)
		if err != nil {
			return nil, err
		}

		// Validate the response structure.
		err = validator.New().Struct(response)

		// We may get a 200 OK with an error status, in theory.
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
	AuthenticatedRequest
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

type ReqLogin struct {
	Username string             `json:"username"            validate:"required"`
	Password string             `json:"password"            validate:"required"`
}
func (req *ReqLogin) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type AuthenticatedRequest struct {
	Token string                `json:"token"               validate:"required"`
}

type ReqRefresh struct {
	AuthenticatedRequest
}
func (req *ReqRefresh) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqTicket struct {
	AuthenticatedRequest
}
func (req *ReqTicket) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqStartScan struct {
	AuthenticatedRequest
	ScanID string               `json:"scanid,omitempty"    validate:"omitempty,uuid"`
	Script string               `json:"script,omitempty"    validate:"omitempty"`
}
func (req *ReqStartScan) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqStopScan struct {
	AuthenticatedRequest
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqStopScan) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqEnumerateScans struct {
	AuthenticatedRequest
}
func (req *ReqEnumerateScans) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqDeleteScan struct {
	AuthenticatedRequest
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqDeleteScan) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqGetScanProgressTable struct {
	AuthenticatedRequest
}
func (req *ReqGetScanProgressTable) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqGetScanDataIDs struct {
	AuthenticatedRequest
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqGetScanDataIDs) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqLoadData struct {
	AuthenticatedRequest
	ScanID string               `json:"scanid"              validate:"uuid"`
	DataIDs []string            `json:"dataids"             validate:"omitempty,dive,mongodb"`
}
func (req *ReqLoadData) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqReport struct {
	AuthenticatedRequest
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqReport) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqQueryLog struct {
	AuthenticatedRequest
	ScanID string               `json:"scanid"              validate:"uuid"`
	TaskID string               `json:"taskid"              validate:"uuid"`
}
func (req *ReqQueryLog) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqQueryScanTaskList struct {
	AuthenticatedRequest
	ScanID string               `json:"scanid"              validate:"uuid"`
}
func (req *ReqQueryScanTaskList) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqListPlugins struct {
	AuthenticatedRequest
}
func (req *ReqListPlugins) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqCheckScriptSyntax struct {
	AuthenticatedRequest
	Script string               `json:"script"              validate:"required"`
}
func (req *ReqCheckScriptSyntax) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqListFiles struct {
	AuthenticatedRequest
}
func (req *ReqListFiles) Decode(r *http.Request) error {
	if err := ValidateHttpRequest(r); err != nil { return err }
	if err := json.NewDecoder(r.Body).Decode(req); err != nil { return err }
	return validator.New().Struct(req)
}

type ReqRemoveFile struct {
	AuthenticatedRequest
	FileID string               `json:"fileid"              validate:"uuid"`
}
func (req *ReqRemoveFile) Decode(r *http.Request) error {
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
