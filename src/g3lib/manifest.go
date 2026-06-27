package g3lib

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/golismero/g3/src/g3model"
)

// Re-export g3model stuff.
const ManifestFilename = g3model.ManifestFilename
type G3ManifestFile = g3model.ManifestFile
type G3ManifestWork = g3model.ManifestWork
type G3Manifest = g3model.Manifest

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

// BundleTaskSlot enumerates slotDir (any task's artifact slot) and streams its
// contents to w, applying the 0/1/many discovery rule from the reporter plugin
// spec:
//
//   - 0 regular files → returns ("", "", os.ErrNotExist) so callers can render
//     a 404. (Impossible in practice: WriteManifest always lands manifest.json
//     in the slot. A 0 means the slot was reaped or the task_id is wrong.)
//   - Exactly 1 regular file, no subdirs → streams that file as-is to w.
//     Returned filename: <stem>-<taskID>.<ext> (stem/ext split on last dot).
//     Returned content-type: mime.TypeByExtension(.ext) or "application/octet-stream".
//   - Otherwise → streams a zip containing every regular file (recursing
//     subdirs). Returned filename: <tool>-<taskID>.zip; content-type:
//     "application/zip".
//
// The zip writer targets w directly — no in-memory buffering.
func BundleTaskSlot(slotDir, tool, taskID string, w io.Writer) (filename, contentType string, err error) {

	// First pass: walk the slot to classify it.
	var files []string                 // regular files, relative to slotDir
	var hasSubdir bool
	err = filepath.WalkDir(slotDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == slotDir {
			return nil
		}
		rel, _ := filepath.Rel(slotDir, path)
		if d.IsDir() {
			hasSubdir = true
			return nil
		}
		if d.Type().IsRegular() {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}

	// 0 files → not found.
	if len(files) == 0 {
		return "", "", os.ErrNotExist
	}

	// Exactly 1 file, no subdirs → stream as-is.
	if len(files) == 1 && !hasSubdir {
		name := files[0]
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		out := stem + "-" + taskID + ext
		ctype := mime.TypeByExtension(ext)
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		fp, err := os.Open(filepath.Join(slotDir, name))
		if err != nil {
			return "", "", err
		}
		defer fp.Close()
		if _, err := io.Copy(w, fp); err != nil {
			return "", "", err
		}
		return out, ctype, nil
	}

	// Otherwise → zip. Re-walk so we pick up files inside subdirs too.
	zw := zip.NewWriter(w)
	// Safety net for early-error returns. The success path closes explicitly
	// below and propagates the error — calling Close twice is harmless.
	defer zw.Close() //nolint:errcheck
	err = filepath.WalkDir(slotDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == slotDir || d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(slotDir, path)
		zf, err := zw.Create(rel)
		if err != nil {
			return err
		}
		fp, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fp.Close()
		_, err = io.Copy(zf, fp)
		return err
	})
	if err != nil {
		return "", "", err
	}
	// Flush the zip central directory before returning success — without this
	// any error from finalizing the archive would be silently dropped and the
	// caller would ship a corrupt zip downstream.
	if err := zw.Close(); err != nil {
		return "", "", err
	}
	return tool + "-" + taskID + ".zip", "application/zip", nil
}
