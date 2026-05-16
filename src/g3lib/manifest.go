package g3lib

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
// (the plugin entrypoint may run multiple sub-commands internally — testssl-
// per-port, vulners-per-CPE, etc.) and the filenames the plugin claimed for that
// command via _artifacts. The filenames reference entries in G3Manifest.Files.
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

// ManifestTool derives the canonical tool name for the manifest's root `tool`
// field. It prefers the _tool the plugin stamped onto its first emitted G3Data
// (g3lib's runPluginInternal injects this for every object, including the dummy
// object it appends when the plugin emitted nothing) and falls back to the g3
// plugin name when the output array is unexpectedly empty.
func ManifestTool(outputArray []G3Data, plugin G3Plugin) string {
	if len(outputArray) > 0 {
		if t, ok := outputArray[0]["_tool"].(string); ok && t != "" {
			return t
		}
	}
	return plugin.Name
}

// EnumerateSlot lists every regular file in slotDir, returning a G3ManifestFile
// per entry. Subdirectories and the manifest file itself are excluded.
func EnumerateSlot(slotDir string) ([]G3ManifestFile, error) {
	entries, err := os.ReadDir(slotDir)
	if err != nil {
		return nil, err
	}
	files := []G3ManifestFile{}
	for _, entry := range entries {
		// Skip subdirectories (no recursion — see TODO), the manifest itself,
		// and any non-regular entries. Filtering to regular files defends
		// against a plugin planting a symlink or device in its slot; a curated
		// consumer reading those later would surface unrelated host content.
		// TODO: subdirectories a plugin creates are not recursed into; only
		// top-level files in the slot are listed. Revisit if a plugin ever
		// needs a nested artifact layout.
		if !entry.Type().IsRegular() || entry.Name() == ManifestFilename {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		files = append(files, G3ManifestFile{
			Name:     entry.Name(),
			Size:     info.Size(),
			Modified: info.ModTime().Unix(),
		})
	}
	return files, nil
}

// ValidateArtifactClaims walks outputArray and verifies that every present
// _artifacts field is shaped as a list of strings AND that every claimed
// filename appears in files. Returns nil if every claim is well-formed and
// present on disk; returns an error whose message is suitable for the
// manifest's exit_status field otherwise. The first failure short-circuits the
// scan — once a plugin has emitted one bad claim, the diagnostic value of
// piling on more is limited.
func ValidateArtifactClaims(outputArray []G3Data, files []G3ManifestFile) error {
	present := make(map[string]struct{}, len(files))
	for _, f := range files {
		present[f.Name] = struct{}{}
	}
	for i, data := range outputArray {
		raw, ok := data["_artifacts"]
		if !ok {
			continue
		}
		list, ok := raw.([]interface{})
		if !ok {
			return fmt.Errorf("malformed _artifacts on output[%d]: expected list of strings, got %T", i, raw)
		}
		for j, item := range list {
			name, ok := item.(string)
			if !ok {
				return fmt.Errorf("malformed _artifacts on output[%d][%d]: expected string, got %T", i, j, item)
			}
			if _, exists := present[name]; !exists {
				cmd, _ := data["_cmd"].(string)
				return fmt.Errorf("missing artifact %q (claimed by cmd %q on output[%d])", name, cmd, i)
			}
		}
	}
	return nil
}

// BuildManifestWork groups outputArray by _cmd and unions per-group _artifacts
// into a single G3ManifestWork entry per unique command. Output order follows
// first-occurrence of each unique _cmd in outputArray. Callers are expected to
// have already run ValidateArtifactClaims (or otherwise accepted that malformed
// _artifacts shapes will be silently ignored here — ValidateArtifactClaims is
// the loud guard).
func BuildManifestWork(outputArray []G3Data) []G3ManifestWork {
	work := []G3ManifestWork{}
	indexByCmd := map[string]int{}
	for _, data := range outputArray {
		cmd, _ := data["_cmd"].(string)
		idx, exists := indexByCmd[cmd]
		if !exists {
			idx = len(work)
			work = append(work, G3ManifestWork{Cmd: cmd, Artifacts: []string{}})
			indexByCmd[cmd] = idx
		}
		raw, hasArtifacts := data["_artifacts"]
		if !hasArtifacts {
			continue
		}
		list, ok := raw.([]interface{})
		if !ok {
			continue
		}
		for _, item := range list {
			name, ok := item.(string)
			if !ok {
				continue
			}
			if !ContainsStr(work[idx].Artifacts, name) {
				work[idx].Artifacts = append(work[idx].Artifacts, name)
			}
		}
	}
	return work
}

// WriteManifest marshals m as indented JSON and writes it to slotDir/manifest.json.
// The caller is responsible for populating every field (including Files and
// Work). This function does no enumeration or validation.
func WriteManifest(slotDir string, m G3Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(slotDir, ManifestFilename), data, 0o644)
}

// CreateEphemeralArtifactSlot creates an isolated, transient slot directory
// suitable for a single CLI plugin invocation. The returned path is absolute
// so it resolves correctly when passed to `docker run -v`; the caller is
// responsible for removing the directory (e.g. with os.RemoveAll). Unlike the
// worker's per-task slot under <G3_ARTIFACTS_ROOT>/<scanid>/<taskid>, these
// ephemeral slots are not keyed by scan or task identity and are not expected
// to be persisted past the invocation.
func CreateEphemeralArtifactSlot() (string, error) {
	return os.MkdirTemp("", "g3-cli-artifacts-")
}
