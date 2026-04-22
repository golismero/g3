package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"

	"github.com/go-playground/validator/v10"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-jsonnet"
	"github.com/spf13/pflag"

	"golismero.com/g3lib"
	log "golismero.com/g3log"
)

// Parse i18n strings for Golismero.
func ParseLanguageFiles(i18npath string) (g3lib.G3TranslatedStrings, error) {
	loadedStringsCache := g3lib.G3TranslatedStrings{}
	err := filepath.WalkDir(i18npath, func(path string, _ fs.DirEntry, err error) error {

		// Stop everything if there was an error while traversing directories.
		if err != nil {
			return err
		}

		// Ignore non JSON files.
		if filepath.Ext(path) != ".json" {
			return nil
		}

		// Get the language from the filename.
		lang := strings.TrimSuffix(filepath.Base(path), ".json")

		// Read the file contents.
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Parse the file contents.
		loadedStrings := g3lib.G3TranslatedStringsForLanguage{}
		err = json.Unmarshal(bytes, &loadedStrings)
		if err != nil {
			return err
		}

		// Save the strings.
		loadedStringsCache[lang] = loadedStrings
		return nil
	})

	// Return the strings.
	return loadedStringsCache, err
}

// Find and parse i18n templates for plugins.
func ParsePluginTemplates(i18npath string) (g3lib.G3PluginTemplates, error) {
	loadedStrings := g3lib.G3PluginTemplates{}

	// Check if the i18n directory exists.
	// Ignore the error if it doesn't, since it's not mandatory for plugins to have one.
	fi, err := os.Stat(i18npath)
	if err != nil {
		if os.IsNotExist(err) {
			return loadedStrings, nil
		}
		return loadedStrings, err
	}
	if !fi.IsDir() {
		return loadedStrings, fmt.Errorf("should be a directory: %s", i18npath)
	}

	// Traverse the i18n directory.
	re := regexp.MustCompile(`^[a-zA-Z0-9_\-]*$`)
	err = filepath.WalkDir(i18npath, func(path string, _ fs.DirEntry, err error) error {

		// Stop everything if there was an error while traversing directories.
		if err != nil {
			return err
		}

		// Ignore non JSON files.
		if filepath.Ext(path) != ".json" {
			return nil
		}

		// Get the language from the filename.
		lang := strings.TrimSuffix(filepath.Base(path), ".json")

		// Read the file contents.
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Parse the file contents.
		pluginTemplates := map[string]string{}
		err = json.Unmarshal(bytes, &pluginTemplates)
		if err != nil {
			return err
		}

		// Fix missing templates with their default values when possible.
		if _, ok := pluginTemplates["affects"]; !ok {
			pluginTemplates["affects"] = "{{range .affects}}* {{.}}\n{{end}}"
		}
		if _, ok := pluginTemplates["references"]; !ok {
			pluginTemplates["references"] = "{{range .references}}* [{{.}}[({{.}})\n{{end}}"
		}
		if _, ok := pluginTemplates["summary"]; !ok {
			if value, ok := pluginTemplates["description"]; !ok {
				pluginTemplates["summary"] = value
			}
		}
		if _, ok := pluginTemplates["description"]; !ok {
			if value, ok := pluginTemplates["summary"]; !ok {
				pluginTemplates["description"] = value
			}
		}

		// Validate the templates and save them.
		template := ""
		for name, tpl := range pluginTemplates {
			if ! re.Match([]byte(name)) {
				return errors.New("invalid template name: " + name)
			}
			tpl = fmt.Sprintf("{{define \"%s\"}}%s{{end}}", name, tpl)
			_, e := g3lib.BuildTemplate(tpl)
			if e != nil {
				return fmt.Errorf("bad template \"%s\": %s", name, e.Error())
			}
			template = template + tpl
		}
		loadedStrings[lang] = template
		return nil
	})
	return loadedStrings, err
}

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
	pluginTemplatesFile := filepath.Join(g3home, g3lib.G3CONFIG, g3lib.G3TEMPLATES)
	i18nStringsFile := filepath.Join(g3home, g3lib.G3CONFIG, g3lib.G3STRINGS)

	// Initialize the validator.
	var validate *validator.Validate = validator.New()

	// Initialize the JSONnet parser.
	vm := jsonnet.MakeVM()

	// This regular expression will validate plugin names.
	re := regexp.MustCompile(`^[a-zA-Z0-9_\-]*$`)

	// This regular expression will validate data types.
	re_type := regexp.MustCompile(`^[a-z]+$`)

	// We'll be storing each plugin name and its metadata here.
	plugins := g3lib.G3PluginMetadata{}

	// We'll store the plugin templates here.
	pluginTemplates := g3lib.G3PluginTemplatesCache{}

	// Parse the G3 i18n strings.
	mainFilepath := filepath.Join(g3home, "i18n")
	if !quiet {
		relMainPath, err := filepath.Rel(g3home, mainFilepath)
		if err != nil {
			relMainPath = mainFilepath
		}
		log.Info("Found: " + relMainPath + string(filepath.Separator))
	}
	mainStrings, err := ParseLanguageFiles(mainFilepath)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	if !quiet {
		for lang, _ := range mainStrings {
			langTag, err := language.Parse(lang)
			if err != nil {
				log.Error(err.Error())
				os.Exit(1)
			}
			log.Info("  Language: " + display.Self.Name(langTag))
		}
	}

	// Recursively traverse the G3HOME directory.
	err = filepath.WalkDir(filepath.Join(g3home, "plugins"), func(path string, _ fs.DirEntry, err error) error {

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

		// Parse the file contents as JSONnet.
		// This produces JSON data.
		jsonStr, err := vm.EvaluateAnonymousSnippet(path, string(dat))
		if err != nil {
			return err
		}

		// Parse the JSON data again as a struct since that's what we'll use internally.
		bytes := []byte(jsonStr)
		metadata := g3lib.G3Plugin{}
		err = json.Unmarshal(bytes, &metadata)
		if err != nil {
			return err
		}

		// Validate the JSON data.
		err = validate.Struct(metadata)
		if err != nil {
			return err
		}
		if metadata.Importer != nil {
			if metadata.Importer.Returns != "" && !re_type.MatchString(metadata.Importer.Returns) {
				return errors.New("ERROR! Invalid return data type for importer: " + metadata.Importer.Returns)
			}
			for _, tpl := range metadata.Importer.Fingerprint {
				_, err = g3lib.BuildTemplate(tpl)
				if err != nil {
					return errors.New("ERROR! Cannot parse importer fingerprint: " + err.Error())
				}
			}
		}
		for cmdidx, cmd := range metadata.Commands {
			if cmd.Returns != "" && !re_type.MatchString(cmd.Returns) {
				return fmt.Errorf("ERROR! Invalid return data type for command %d: %s", cmdidx, cmd.Returns)
			}
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

		// If the name is missing, add it based on the filename.
		if metadata.Name == "" {
			name := filepath.Base(path)
			name = strings.TrimSuffix(name, filepath.Ext(name))
			metadata.Name = name
		}

		// Validate the plugin name.
		if metadata.Name == "g3" || !re.MatchString(metadata.Name) {
			return errors.New("ERROR! Invalid plugin name: " + metadata.Name)
		}

		// Make sure we don't have any duplicates.
		if _, dup := plugins[metadata.Name]; dup {
			return errors.New("ERROR! Duplicated plugin: " + metadata.Name)
		}

		// If the image is missing, add it based on the plugin name.
		if metadata.Image == "" {
			metadata.Image = "ghcr.io/golismero/" + metadata.Name
		}

		// If the tool description is missing, add a default description.
		if len(metadata.Description) == 0 {
			metadata.Description["en"] = "Golismero3 integration with " + metadata.Name + "."
		}

		// If the tool URL is missing, just point to the GitHub repository.
		if metadata.URL == "" {
			metadata.URL = "https://github.com/golismero/g3"
		}

		// Validate the existence of the Docker image, either local or remote.
		// FIXME: use docker client libraries instead of an external command
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

		// Parse any associated i18n strings for this plugin.
		i18npath := filepath.Join(filepath.Dir(path), "i18n")
		loadedStrings, err := ParsePluginTemplates(i18npath)
		if err != nil {
			return err
		}
		if !quiet {
			for lang, _ := range loadedStrings {
				langTag, err := language.Parse(lang)
				if err != nil {
					return err
				}
				log.Info("  Language: " + display.Self.Name(langTag))
			}
		}

		// Store the plugin name and metadata as a map.
		// Make sure the English language is implemented, since this is our default.
		plugins[metadata.Name] = metadata
		if len(loadedStrings) > 0 {
			if _, ok := loadedStrings["en"]; !ok {
				return errors.New("ERROR! Missing English language")
			}
			pluginTemplates[metadata.Name] = loadedStrings
		}
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
	relPluginTemplatesFile, err := filepath.Rel(g3home, pluginTemplatesFile)
	if err != nil {
		relPluginTemplatesFile = pluginTemplatesFile
	}
	reli18nStringsFile, err := filepath.Rel(g3home, i18nStringsFile)
	if err != nil {
		reli18nStringsFile = i18nStringsFile
	}

	// Store the plugins metadata in JSON format.
	jsonBytes, err := json.Marshal(plugins)
	if err != nil {
		log.Error("Error writing to file " + relPluginsMetadataFile + ": " + err.Error())
		os.Exit(1)
	}
	err = os.WriteFile(pluginsMetadataFile, jsonBytes, 0644)
	if err != nil {
		log.Error("Error writing to file " + relPluginsMetadataFile + ": " + err.Error())
		os.Exit(1)
	}
	log.Info("Saved file: " + relPluginsMetadataFile)

	// Store the plugins i18n templates in JSON format.
	jsonBytes, err = json.Marshal(pluginTemplates)
	if err != nil {
		log.Error("Error writing to file " + relPluginTemplatesFile + ": " + err.Error())
		os.Exit(1)
	}
	err = os.WriteFile(pluginTemplatesFile, jsonBytes, 0644)
	if err != nil {
		log.Error("Error writing to file " + relPluginTemplatesFile + ": " + err.Error())
		os.Exit(1)
	}
	log.Info("Saved file: " + relPluginTemplatesFile)

	// Save the G3 i18n strings in JSON format.
	jsonBytes, err = json.Marshal(mainStrings)
	if err != nil {
		log.Error("Error writing to file " + reli18nStringsFile + ": " + err.Error())
		os.Exit(1)
	}
	err = os.WriteFile(i18nStringsFile, jsonBytes, 0644)
	if err != nil {
		log.Error("Error writing to file " + reli18nStringsFile + ": " + err.Error())
		os.Exit(1)
	}
	log.Info("Saved file: " + reli18nStringsFile)
}
