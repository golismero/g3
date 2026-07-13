package g3

// POST /scans/start
type ScanRequest struct {
	Script    string `json:"script"             validate:"required"`
}

// POST /scans/{scanid}/data
// POST /scans/{scanid}/data/list
type DataRequest struct {
	Data      []Data `json:"data"               validate:"required,min=1,dive,required"`
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
