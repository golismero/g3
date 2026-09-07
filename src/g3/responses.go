package g3

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

type ScanResponse struct {
	ScanID string `json:"scanid" validate:"required,uuid"`
}

type TaskResponse struct {
	TaskID string `json:"taskid" validate:"required,uuid"`
}

// GET /scans/{scanid}/data
// GET /scans/{scanid}/tasks/{taskid}/data
// POST /scans/{scanid}/data
// POST /scans/{scanid}/data/filter
// POST /scans/{scanid}/import
// POST /scans/{scanid}/run
// POST /scans/{scanid}/targets
type DataResponse struct {
	Data []Data `json:"data,omitempty"`
}

// GET /scans/list
type ScanIdListResponse struct {
	ScanIDs []string `json:"scan_ids,omitempty" validate:"omitempty,dive,uuid"`
}

// GET /scans/{scanid}/tasks/list
// POST /scans/{scanid}/dispatch
// POST /scans/{scanid}/run
type TaskIdListResponse struct {
	TaskIDs []string `json:"task_ids,omitempty" validate:"omitempty,dive,uuid"`
}

// GET /scans/{scanid}/data/list
// GET /scans/{scanid}/tasks/{taskid}/data/list
// POST /scans/{scanid}/data/filter/list
type DataIdListResponse struct {
	DataIDs []string `json:"data_ids,omitempty" validate:"omitempty,dive,mongodb"`
}

// POST /files
type FileIdListResponse struct {
	FileIDs []string `json:"file_ids,omitempty" validate:"omitempty,dive,uuid"`
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
	Logs []LogLine `json:"logs,omitempty" validate:"omitempty,dive"`
}

// GET /scans/{scanid}/logs
type ScanLogsResponse struct {
	ScanResponse
	Logs []TaskLogsResponse `json:"logs,omitempty" validate:"omitempty,dive"`
}

type UpdateResponse struct {
	LastSeq       uint64 `json:"last_seq"             validate:"gte=0"`
	CreatedAt     uint64 `json:"created_at"           validate:"gt=0"`
	StartedAt    *uint64 `json:"started_at,omitempty" validate:"omitempty,gt=0"`
	EndedAt      *uint64 `json:"ended_at,omitempty"   validate:"omitempty,gt=0"`
	LastUpdatedAt uint64 `json:"last_updated_at"      validate:"gt=0"`
}

// GET /scans/{scanid}/status
type ScanStatusResponse struct {
	ScanResponse
	UpdateResponse
	Status   string `json:"status"             validate:"required,oneof=managed waiting dispatched running canceled done warning error"`
	Progress   uint `json:"progress,omitempty" validate:"gte=0,lte=100"`
	Message *string `json:"message,omitempty"`
}

// GET /scans/{scanid}/tasks/{taskid}
type TaskStatusResponse struct {
	TaskResponse
	UpdateResponse
	Status  string `json:"status"           validate:"required,oneof=waiting dispatched running canceled done warning error"`
	Tool   *string `json:"tool,omitempty"   validate:"omitempty,g3name"`
	Worker *string `json:"worker,omitempty"`
}

// GET /scans/{scanid}/tasks
type ScanTasksResponse struct {
	ScanResponse
	Tasks []TaskStatusResponse `json:"tasks,omitempty" validate:"omitempty,dive"`
}

// GET /scans/{scanid}
type ScanFullResponse struct {
	ScanStatusResponse
	Tasks []TaskStatusResponse `json:"tasks,omitempty" validate:"omitempty,dive"`
}

// GET /scans/status
type AllScansStatusResponse struct {
	Scans []ScanStatusResponse `json:"scans,omitempty" validate:"omitempty,dive"`
}

// GET /scans
type AllScansFullResponse struct {
	Scans []ScanFullResponse `json:"scans,omitempty" validate:"omitempty,dive"`
}
