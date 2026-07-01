package g3

// ManifestFilename is the name of the per-task manifest the worker writes into
// each task's artifact slot directory.
const ManifestFilename = "manifest.json"

// ManifestFile describes one file in the task's artifact slot.
type ManifestFile struct {
	Name     string `json:"name"     validate:"required"`
	Size     int64  `json:"size"     validate:"ge=0"`
	Modified int64  `json:"modified" validate:"gt=0"`
}

// ManifestWork describes one sub-command run within the task: a command line
// (the plugin entrypoint may run multiple sub-commands internally and the
// filenames the plugin claimed for that command via _artifacts. The filenames
// reference entries in Manifest.Files.
type ManifestWork struct {
	Cmd       string   `json:"cmd"       validate:"required"`
	Artifacts []string `json:"artifacts" validate:"omitempty"`
}

// Manifest is the per-task record written into
// <artifacts-root>/<scanid>/<taskid>/manifest.json. It is the integration
// contract downstream consumers (e.g. magenta) read to map artifact files back
// to the tool that produced them.
//
// Files lists every regular file in the slot (worker-enumerated, authoritative).
// Work groups output objects by _cmd: one entry per unique command, with the
// union of _artifacts claims as that entry's Artifacts. Files present in Files
// but absent from every Work.Artifacts are intentional orphans (debug, forensic
// retention).
type Manifest struct {
	ScanID     string         `json:"scan_id"     validate:"required,uuid,ne=ne=00000000-0000-0000-0000-000000000000"`
	TaskID     string         `json:"task_id"     validate:"required,uuid,ne=ne=00000000-0000-0000-0000-000000000000"`
	Plugin     string         `json:"plugin"      validate:"required"`
	Tool       string         `json:"tool"        validate:"required"`
	ExitStatus string         `json:"exit_status" validate:"required"`
	StartedAt  int64          `json:"started_at"  validate:"gt=0"`
	EndedAt    int64          `json:"ended_at"    validate:"gt=0"`
	Files      []ManifestFile `json:"files"       validate:"dive"`
	Work       []ManifestWork `json:"work"        validate:"dive"`
}
