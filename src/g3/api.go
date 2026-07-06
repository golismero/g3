package g3

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Scan and task status.

var _STATUS_MANAGED = "managed"
var _STATUS_WAITING = "waiting"
var _STATUS_DISPATCHED = "dispatched"
var _STATUS_RUNNING = "running"
var _STATUS_CANCELED = "canceled"
var _STATUS_DONE = "done"
var _STATUS_WARNING = "warning"
var _STATUS_ERROR = "error"

var STATUS_MANAGED = &_STATUS_MANAGED
var STATUS_WAITING = &_STATUS_WAITING
var STATUS_DISPATCHED = &_STATUS_DISPATCHED
var STATUS_RUNNING = &_STATUS_RUNNING
var STATUS_CANCELED = &_STATUS_CANCELED
var STATUS_DONE = &_STATUS_DONE
var STATUS_WARNING = &_STATUS_WARNING
var STATUS_ERROR = &_STATUS_ERROR

type StatusResponse struct {
	LastSeq               uint64 `json:"last_seq"               validate:"gte=0"`
	CreatedAt             uint64 `json:"created_at"             validate:"gt=0"`
	StartedAt            *uint64 `json:"started_at,omitempty"   validate:"omitempty,gt=0"`
	EndedAt              *uint64 `json:"ended_at,omitempty"     validate:"omitempty,gt=0"`
	LastUpdatedAt         uint64 `json:"last_updated_at"        validate:"gt=0"`
}

type ScanStatusResponse struct {
	StatusResponse
	ScanID                string `json:"scanid"                 validate:"required,uuid"`
	Status                string `json:"status"                 validate:"required,oneof=managed waiting dispatched running canceled done warning error"`
	Progress                uint `json:"progress,omitempty"     validate:"gte=0,lte=100"`
	Message              *string `json:"message,omitempty"`
}

type TaskStatusResponse struct {
	StatusResponse
	TaskID                string `json:"taskid"                 validate:"required,uuid"`
	Status                string `json:"status"                 validate:"required,oneof=waiting dispatched running canceled done warning error"`
	Tool                 *string `json:"tool,omitempty"         validate:"omitempty,g3name"`
	Worker               *string `json:"worker,omitempty"`
}

type ScanTasksResponse struct {
	ScanID                string `json:"scanid"                 validate:"required,uuid"`
	Tasks   []TaskStatusResponse `json:"tasks,omitempty"        validate:"omitempty,dive"`
}

type ScanFullResponse struct {
	ScanStatusResponse
	Tasks   []TaskStatusResponse `json:"tasks,omitempty"        validate:"omitempty,dive"`
}

type AllScansStatusResponse struct {
	Scans   []ScanStatusResponse `json:"scans,omitempty"        validate:"omitempty,dive"`
}

type AllScansFullResponse struct {
	Scans     []ScanFullResponse `json:"scans,omitempty"        validate:"omitempty,dive"`
}

func IsStatusTerminal(state string) bool {
	switch state {
	case "waiting", "dispatched", "running", "managed":
		return false
	case "canceled", "done", "warning", "error":
		return true
	default:
		panic("internal error")
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Scan and task logs.

type TaskLogsResponse struct {
	TaskID                string `json:"taskid"      validate:"required,uuid"`
	Logs               []LogLine `json:"logs"        validate:"omitempty,dive"`
}

type ScanLogsResponse struct {
	ScanID                string `json:"scanid"      validate:"required,uuid"`
	Logs      []TaskLogsResponse `json:"logs"        validate:"omitempty,dive"`
}
