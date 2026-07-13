package g3

//////////////////////////////////////////////////////////////////////////////
// Requests

// POST /scans/start
type ScanRequest struct {
	Script    string `json:"script"             validate:"required"`
}

// POST /scans/{scanid}/data
// POST /scans/{scanid}/data/list
type DataRequest struct {
	Data      []Data `json: "data"              validate:"required,min=1,dive,required"`
}

// POST /scans/{scanid}/import
type ImportRequest struct {
	Tool      string `json:"tool"               validate:"required,g3name"`
	FileID    string `json:"fileid"             validate:"required,uuid"`
}

// POST /scans/{scanid}/targets
type TargetsRequest struct {
	Targets []string `json:"targets"           validate:"required,min=1,dive,required"`
}

// POST /scans/{scanid}/dispatch
type DispatchRequest struct {
	Tool      string `json:"tool"               validate:"required,g3name"`
	DataID    string `json:"dataid"             validate:"required,uuid"`
}

// POST /scans/{scanid}/run
type RunRequest struct {
	Tool      string `json:"tool"               validate:"required,g3name"`
	DataID    string `json:"dataid"             validate:"required,uuid"`
}

// POST /scans/{scanid}/report
type ReportRequest struct {
	Tool      string `json:"tool"               validate:"omitempty,g3name"`
	Preset    string `json:"preset,omitempty"`
}

// POST /scans/{scanid}/data/filter
// POST /scans/{scanid}/data/filter/list
type FilterRequest struct {
	TaskIDs []string `json:"task_ids,omitempty" validate:"omitempty,dive,uuid"`
	DataIDs []string `json:"data_ids,omitempty" validate:"omitempty,dive,uuid"`
}

// POST /scans/{scanid}/data/match
// POST /scans/{scanid}/data/match/list
type MatchRequest struct {
	Fingerprints []string `json:"fp"            validate:"required"`
}

//////////////////////////////////////////////////////////////////////////////
// Responses

// Endpoints that *may* not return a JSON response body, even on success:
//
// Response: "200 OK" + file download
// - GET /scans/{scanid}/tasks/{taskid}/artifacts
// - GET /scans/{scanid}/report
//
// Response: "201 Created" + "Location: /scans/{scanid}"
// - POST /scans/managed
// - POST /scans/start
//
// Response: "201 Created" + "Location: /scans/{scanid}/tasks/{taskid}/artifacts"
// - POST /scans/{scanid}/report
//
// Response: "202 Accepted"
// - POST /scans/{scanid}/stop
// - POST /scans/{scanid}/delete
// - POST /scans/{scanid}/tasks/{taskid}/stop

var _STATUS_MANAGED    = "managed"
var _STATUS_WAITING    = "waiting"
var _STATUS_DISPATCHED = "dispatched"
var _STATUS_RUNNING    = "running"
var _STATUS_CANCELED   = "canceled"
var _STATUS_DONE       = "done"
var _STATUS_WARNING    = "warning"
var _STATUS_ERROR      = "error"

var STATUS_MANAGED = &_STATUS_MANAGED
var STATUS_WAITING = &_STATUS_WAITING
var STATUS_DISPATCHED = &_STATUS_DISPATCHED
var STATUS_RUNNING = &_STATUS_RUNNING
var STATUS_CANCELED = &_STATUS_CANCELED
var STATUS_DONE = &_STATUS_DONE
var STATUS_WARNING = &_STATUS_WARNING
var STATUS_ERROR = &_STATUS_ERROR

type ScanResponse struct {
	ScanID   string `json:"scanid"          validate:"required,uuid"`
}

type TaskResponse struct {
	TaskID   string `json:"taskid"          validate:"required,uuid"`
}

// GET /scans/{scanid}/data
// GET /scans/{scanid}/tasks/{taskid}/data
// POST /scans/{scanid}/data
// POST /scans/{scanid}/data/filter
// POST /scans/{scanid}/data/match
// POST /scans/{scanid}/import
// POST /scans/{scanid}/run
// POST /scans/{scanid}/targets
type DataResponse struct {
	Data     []Data `json: "data,omitempty" validate:"omitempty,dive"`
}

// GET /scans/list
type ScanIdListResponse struct {
	IDs    []string `json:"scans,omitempty"   validate:"omitempty,dive,uuid"`
}

// GET /scans/{scanid}/tasks/list
// POST /scans/{scanid}/dispatch
// POST /scans/{scanid}/run
type TaskIdListResponse struct {
	IDs    []string `json:"tasks,omitempty"   validate:"omitempty,dive,uuid"`
}

// GET /scans/{scanid}/data/list
// GET /scans/{scanid}/tasks/{taskid}/data/list
// POST /scans/{scanid}/data/filter/list
// POST /scans/{scanid}/data/match/list
type DataIdListResponse struct {
	IDs    []string `json:"data,omitempty"   validate:"omitempty,dive,uuid"`
}

// POST /files
type FileIdListResponse struct {
	IDs    []string `json:"files,omitempty"  validate:"omitempty,dive,uuid"`
}

// GET /scans/{scanid}/tasks/{taskid}/manifest
type ManifestResponse struct {
	Manifest	// already includes scan and task id
}

// GET /config
type ConfigResponse struct {
	Version                string `json:"ver"           validate:"required,semver|eq=latest|eq=dev"`
	Environment map[string]string `json:"env,omitempty"`
	Plugins      []PluginListItem `json:"plugins"       validate:"required,dive"`
}

// GET /scans/{scanid}/tasks/{taskid}/logs
type TaskLogsResponse struct {
	TaskResponse
	Logs               []LogLine `json:"logs,omitempty" validate:"omitempty,dive"`
}

// GET /scans/{scanid}/logs
type ScanLogsResponse struct {
	ScanResponse
	Logs      []TaskLogsResponse `json:"logs,omitempty" validate:"omitempty,dive"`
}

type UpdateResponse struct {
	LastSeq               uint64 `json:"last_seq"               validate:"gte=0"`
	CreatedAt             uint64 `json:"created_at"             validate:"gt=0"`
	StartedAt            *uint64 `json:"started_at,omitempty"   validate:"omitempty,gt=0"`
	EndedAt              *uint64 `json:"ended_at,omitempty"     validate:"omitempty,gt=0"`
	LastUpdatedAt         uint64 `json:"last_updated_at"        validate:"gt=0"`
}

// GET /scans/{scanid}/status
type ScanStatusResponse struct {
	ScanResponse
	UpdateResponse
	Status                string `json:"status"                 validate:"required,oneof=managed waiting dispatched running canceled done warning error"`
	Progress                uint `json:"progress,omitempty"     validate:"gte=0,lte=100"`
	Message              *string `json:"message,omitempty"`
}

// GET /scans/{scanid}/tasks/{taskid}
type TaskStatusResponse struct {
	TaskResponse
	UpdateResponse
	Status                string `json:"status"                 validate:"required,oneof=waiting dispatched running canceled done warning error"`
	Tool                 *string `json:"tool,omitempty"         validate:"omitempty,g3name"`
	Worker               *string `json:"worker,omitempty"`
}

// GET /scans/{scanid}/tasks
type ScanTasksResponse struct {
	ScanResponse
	Tasks   []TaskStatusResponse `json:"tasks,omitempty"        validate:"omitempty,dive"`
}

// GET /scans/{scanid}
type ScanFullResponse struct {
	ScanStatusResponse
	Tasks   []TaskStatusResponse `json:"tasks,omitempty"        validate:"omitempty,dive"`
}

// GET /scans/status
type AllScansStatusResponse struct {
	Scans   []ScanStatusResponse `json:"scans,omitempty"        validate:"omitempty,dive"`
}

// GET /scans
type AllScansFullResponse struct {
	Scans     []ScanFullResponse `json:"scans,omitempty"        validate:"omitempty,dive"`
}

func GetScanType(status string) string {
	switch status {
	case "managed":
		return "managed"
	default:
		return "automated"
	}
}

func IsScanStatusTerminal(status string) bool {
	switch status {
	case "waiting", "dispatched", "running":
		return false
	case "canceled", "done", "warning", "error", "managed":
		return true
	default:
		panic("internal error: unsupported status: " + status)
	}
}

func IsTaskStatusTerminal(status string) bool {
	switch status {
	case "waiting", "dispatched", "running":
		return false
	case "canceled", "done", "warning", "error":
		return true
	default:
		panic("internal error: unsupported status: " + status)
	}
}
