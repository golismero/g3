package g3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

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
	FileID string    `json:"fileid"              validate:"required,uuid4"`
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
	TaskID  string   `json:"taskid,omitempty"    validate:"omitempty,uuid4"`
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
