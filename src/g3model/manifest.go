package g3model

// ManifestFilename is the name of the per-task manifest the worker writes into
// each task's artifact slot directory.
const ManifestFilename = "manifest.json"

// G3ManifestFile describes one file in the task's artifact slot.
type G3ManifestFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
}

// G3ManifestWork describes one sub-command run within the task: a command line
// (the plugin entrypoint may run multiple sub-commands internally and the
// filenames the plugin claimed for that command via _artifacts. The filenames
// reference entries in G3Manifest.Files.
type G3ManifestWork struct {
	Cmd       string   `json:"cmd"`
	Artifacts []string `json:"artifacts"`
}

// G3Manifest is the per-task record written into
// <artifacts-root>/<scanid>/<taskid>/manifest.json. It is the integration
// contract downstream consumers (e.g. magenta) read to map artifact files back
// to the tool that produced them.
//
// Files lists every regular file in the slot (worker-enumerated, authoritative).
// Work groups output objects by _cmd: one entry per unique command, with the
// union of _artifacts claims as that entry's Artifacts. Files present in Files
// but absent from every Work.Artifacts are intentional orphans (debug, forensic
// retention).
type G3Manifest struct {
	ScanID     string           `json:"scan_id"`
	TaskID     string           `json:"task_id"`
	Plugin     string           `json:"plugin"`
	Tool       string           `json:"tool"`
	ExitStatus string           `json:"exit_status"`
	StartedAt  int64            `json:"started_at"`
	EndedAt    int64            `json:"ended_at"`
	Files      []G3ManifestFile `json:"files"`
	Work       []G3ManifestWork `json:"work"`
}
