package g3lib

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/kballard/go-shellquote"
)

// ManifestFilename is the name of the per-task manifest the worker writes into
// each task's artifact slot directory.
const ManifestFilename = "manifest.json"

// G3ManifestFile describes one file a plugin left in its artifact slot.
type G3ManifestFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
}

// G3Manifest is the per-task record written into
// <artifacts-root>/<scanid>/<taskid>/manifest.json. It is the integration
// contract downstream consumers (e.g. magenta) read to map artifact files back
// to the tool that produced them.
type G3Manifest struct {
	ScanID     string           `json:"scan_id"`
	TaskID     string           `json:"task_id"`
	Plugin     string           `json:"plugin"`
	Tool       string           `json:"tool"`
	Cmd        string           `json:"cmd"`
	ExitStatus string           `json:"exit_status"`
	StartedAt  int64            `json:"started_at"`
	EndedAt    int64            `json:"ended_at"`
	Files      []G3ManifestFile `json:"files"`
}

// ManifestProvenance derives the canonical tool name and command line for a
// task's manifest. It prefers the _tool / _cmd the plugin stamped onto its
// emitted G3Data (guaranteed present and string-shaped by runPluginInternal),
// and falls back to the same defaults runPluginInternal would inject when the
// output array is empty (e.g. the plugin emitted unparseable JSON).
func ManifestProvenance(outputArray []G3Data, plugin G3Plugin, parsed ParsedPluginCommand) (string, string) {
	tool := plugin.Name
	cmd := shellquote.Join(parsed.Command...)
	if len(outputArray) > 0 {
		if t, ok := outputArray[0]["_tool"].(string); ok && t != "" {
			tool = t
		}
		if c, ok := outputArray[0]["_cmd"].(string); ok && c != "" {
			cmd = c
		}
	}
	return tool, cmd
}

// WriteTaskManifest enumerates the files in slotDir, fills m.Files, and writes m
// as JSON to slotDir/manifest.json. It is always called after a plugin runs —
// even when the plugin produced no files — so every executed task has a manifest.
func WriteTaskManifest(slotDir string, m G3Manifest) error {
	entries, err := os.ReadDir(slotDir)
	if err != nil {
		return err
	}
	m.Files = []G3ManifestFile{}
	for _, entry := range entries {
		// TODO: subdirectories a plugin creates are not recursed into; only
		// top-level files in the slot are listed. Revisit if a plugin ever
		// needs a nested artifact layout.
		if entry.IsDir() || entry.Name() == ManifestFilename {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		m.Files = append(m.Files, G3ManifestFile{
			Name:     entry.Name(),
			Size:     info.Size(),
			Modified: info.ModTime().Unix(),
		})
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(slotDir, ManifestFilename), data, 0o644)
}
