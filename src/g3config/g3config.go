package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-jsonnet"
	"github.com/spf13/pflag"

	"github.com/golismero/g3/src/g3lib"
	"github.com/golismero/g3/src/g3model"
	log "github.com/golismero/g3/src/g3log"
)

func main() {

	// Parse the command line options.
	quiet := false
	pflag.BoolVarP(&quiet, "quiet", "q", quiet, "quiet mode, do not output any messages")
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Golismero3 Plugins Cache Tool\nUsage:\n\t%s [OPTIONS] [DIR DIR DIR...]\n\n", os.Args[0])
		pflag.PrintDefaults()
	}
	pflag.ErrHelp = errors.New("\nThis command will parse all .g3p files and populate the plugins cache.")
	pflag.Parse()

	// Load the environment variables.
	g3lib.LoadDotEnvFile()

	// Suppress logs if we have a -q flag.
	if quiet {
		log.SetLogLevel("CRITICAL")
	}

	// Get the G3HOME directory.
	g3home := g3lib.GetHomeDirectory()
	if _, err := os.Stat(g3home); os.IsNotExist(err) {
		log.Error("Directory does not exist: \"" + g3home + "\"")
		os.Exit(1)
	}

	// Metadata caches.
	pluginsMetadataFile := filepath.Join(g3home, g3lib.G3CONFIG, g3lib.G3PLUGINS)

	// Initialize the Jsonnet parser.
	vm := jsonnet.MakeVM()

	// We'll be storing each plugin name and its metadata here.
	plugins := g3lib.G3PluginMetadata{}

	// Recursively traverse the G3HOME directory.
	err := filepath.WalkDir(filepath.Join(g3home, "plugins"), func(path string, _ fs.DirEntry, err error) error {

		// Stop everything if there was an error while traversing directories.
		if err != nil {
			return err
		}

		// Ignore files without the correct extension.
		if filepath.Ext(path) != ".g3p" {
			return nil
		}
		if !quiet {
			relPath, err := filepath.Rel(g3home, path)
			if err != nil {
				relPath = path
			}
			log.Info("Found: " + relPath)
		}

		// Read the file contents.
		dat, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Parse the file contents as Jsonnet.
		// This produces JSON data.
		jsonStr, err := vm.EvaluateAnonymousSnippet(path, string(dat))
		if err != nil {
			return err
		}

		// Parse the JSON data again as a struct since that's what we'll use internally.
		bytes := []byte(jsonStr)
		metadata := g3lib.G3Plugin{}
		err = g3model.DecodeJSON(bytes, &metadata)
		if err != nil {
			return err
		}

		// Validate the JSON data.
		if metadata.Importer != nil {
			for _, tpl := range metadata.Importer.Fingerprint {
				_, err = g3lib.BuildTemplate(tpl)
				if err != nil {
					return errors.New("ERROR! Cannot parse importer fingerprint: " + err.Error())
				}
			}
		}
		for cmdidx, cmd := range metadata.Commands {
			_, err = g3lib.BuildTemplate(cmd.Condition)
			if err != nil {
				return fmt.Errorf("ERROR! Cannot parse command %d condition: %s", cmdidx, err.Error())
			}
			for _, tpl := range cmd.Command {
				_, err = g3lib.BuildTemplate(tpl)
				if err != nil {
					return fmt.Errorf("ERROR! Cannot parse command %d: %s", cmdidx, err.Error())
				}
			}
			for _, tpl := range cmd.Fingerprint {
				_, err = g3lib.BuildTemplate(tpl)
				if err != nil {
					return fmt.Errorf("ERROR! Cannot parse command %d fingerprint: %s", cmdidx, err.Error())
				}
			}
		}

		// Validate the reporter phase if present.
		if metadata.Reporter != nil {
			seen := map[string]struct{}{}
			for _, cmd := range metadata.Reporter.Commands {
				if _, dup := seen[cmd.Name]; dup {
					return fmt.Errorf("ERROR! Duplicated reporter command name: %s", cmd.Name)
				}
				seen[cmd.Name] = struct{}{}
			}
			if metadata.Reporter.Default != "" {
				if _, ok := seen[metadata.Reporter.Default]; !ok {
					return fmt.Errorf("ERROR! Reporter default %q does not match any command name", metadata.Reporter.Default)
				}
			}
		}

		// If the name is missing, add it based on the filename.
		if metadata.Name == "" {
			name := filepath.Base(path)
			name = strings.TrimSuffix(name, filepath.Ext(name))
			metadata.Name = name
		}

		// Make sure we don't have any duplicates.
		if _, dup := plugins[metadata.Name]; dup {
			return errors.New("ERROR! Duplicated plugin: " + metadata.Name)
		}

		// If the image is missing, add it based on the plugin name.
		if metadata.Image == "" {
			metadata.Image = "ghcr.io/golismero/" + metadata.Name
		}

		// If the plugin category is missing, use the name of the parent directory.
		if metadata.Category == "" {
			category := filepath.Base(filepath.Dir(filepath.Join(path, "..")))
			if category == "." {
				category = "unknown"
			}
			metadata.Category = category
		}

		// If the tool description is missing, add a default description.
		if metadata.Description == "" {
			metadata.Description = "Golismero3 integration with " + metadata.Name + "."
		}

		// If the tool URL is missing, just point to the GitHub repository.
		if metadata.URL == "" {
			metadata.URL = "https://github.com/golismero/g3"
		}

		// Validate the existence of the Docker image, either local or remote.
		if metadata.Image == "" || metadata.Image[0:1] == "-" {
			return errors.New("ERROR! Invalid Docker image: " + metadata.Image)
		}
		var output []byte
		output, err = exec.Command("docker", "images", "-q", metadata.Image).Output()
		if err != nil || string(output) == "" {
			_, err = crane.Manifest(metadata.Image)
		}
		if err != nil {
			return errors.New("ERROR! Docker image (" + metadata.Image + ") not found: " + err.Error())
		}

		// Store the plugin name and metadata as a map.
		plugins[metadata.Name] = metadata
		return nil
	})
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	// Error out if no plugins were found.
	if len(plugins) == 0 {
		log.Error("No plugins found!")
		os.Exit(1)
	}

	// Convert the filenames to relative just to show them to the user.
	// For writing we will actually use the absolute paths.
	relPluginsMetadataFile, err := filepath.Rel(g3home, pluginsMetadataFile)
	if err != nil {
		relPluginsMetadataFile = pluginsMetadataFile
	}

	// Store the plugins metadata in JSON format.
	jsonBytes, err := g3model.EncodeJSON(plugins)
	if err != nil {
		log.Error("Encoding error writing to file " + relPluginsMetadataFile + ": " + err.Error())
		os.Exit(1)
	}
	err = os.WriteFile(pluginsMetadataFile, jsonBytes, 0644)
	if err != nil {
		log.Error("Error writing to file " + relPluginsMetadataFile + ": " + err.Error())
		os.Exit(1)
	}
	log.Info("Saved file: " + relPluginsMetadataFile)
}
