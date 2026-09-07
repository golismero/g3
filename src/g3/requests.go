package g3

type ScanPathArgument struct {
	ScanID string `path:"scanid" doc:"Scan ID" validate:"required,uuid"`
}

type TaskPathArgument struct {
	TaskID string `path:"taskid" doc:"Task ID" validate:"required,uuid"`
}

// POST /scans/start
type ScriptBodyArgument struct {
	Script string `json:"script" doc:"Golismero script" validate:"required"`
}

// POST /scans/{scanid}/data
type DataBodyArgument struct {
	Data []Data `json:"data" doc:"New data" validate:"required,min=1,dive,required"`
}

// POST /scans/{scanid}/targets
type TargetsBodyArgument struct {
	Targets []string `json:"targets" doc:"Targets (IPs & ranges, hostnames, URLs, etc.)" validate:"required,min=1,dive,required"`
}

type ToolBodyArgument struct {
	Tool string `json:"tool" doc:"Tool name" validate:"required,g3name"`
}

// POST /scans/{scanid}/import
type ImportBodyArgument struct {
	ToolBodyArgument
	FileID string `json:"fileid" doc:"Input file ID (provided by /files/upload)" validate:"required,uuid"`
}

// POST /scans/{scanid}/dispatch
// POST /scans/{scanid}/run
type RunArgument struct {
	ToolBodyArgument
	DataID string `json:"dataid" doc:"Input data ID (provided by /scans/{scanid}/targets or /scans/{scanid}/data)" validate:"required,uuid"`
}

// POST /scans/{scanid}/report
type ReportBodyArgument struct {
	ToolBodyArgument
	Preset string `json:"preset,omitempty" doc:"Optional report preset"`
}

// POST /scans/{scanid}/data/filter
// POST /scans/{scanid}/data/filter/list
type FilterBodyArgument struct {
	TaskIDs []string `json:"task_ids,omitempty" doc:"Filter by task ID(s)" validate:"omitempty,dive,uuid"`
	DataIDs []string `json:"data_ids,omitempty" doc:"Filter by data ID(s)" validate:"omitempty,dive,mongodb"`
	Fingerprints []string `json:"fp,omitempty" doc:"Filter by finterprint(s)" validate:"omitempty,dive,required"`
}
