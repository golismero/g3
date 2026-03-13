package g3lib

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/joho/godotenv"

	log "golismero.com/g3log"
)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Environment variable pointing to the data directory.
// Required for most commands.
const G3HOME = "G3HOME"

// Configuration directory name.
const G3CONFIG = "config"

// Plugins cache file name.
const G3PLUGINS = "g3plugins.json"

// Golismero i18n strings file name.
const G3STRINGS = "g3strings.json"

// Plugins i18n strings file name.
const G3TEMPLATES = "g3templates.json"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Get the G3HOME directory.
func GetHomeDirectory() string {

	// Ideally we should have a G3HOME environment variable already present.
	g3home := os.Getenv(G3HOME)
	if g3home != "" {
		return g3home
	}

	// If the environment variable is missing, we'll have to get creative.
	// We can use the real location of the binary (resolving all symlinks).
	ex, err := os.Executable()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	if target, err := filepath.EvalSymlinks(ex); err != nil {
		ex = target
	}
	ex, err = filepath.Abs(ex)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	dir := filepath.Dir(ex)
	if bin := filepath.Base(dir); bin == "bin" {
		dir = filepath.Dir(dir)
	}

	// Save the calculated path into the environment.
	// This will make future calls quicker.
	os.Setenv(G3HOME, dir)

	// Return the calculated path.
	return dir
}

// Load the .env file.
func LoadDotEnvFile() error {
	g3home := GetHomeDirectory()
	if g3home != "" {
		godotenv.Load(filepath.Join(g3home, ".env"))
	}
	return godotenv.Load()
}

// Get the environment variables as a map.
// https://stackoverflow.com/a/29294251/426293
func GetEnvironmentMap() map[string]string {
	m := make(map[string]string)
	for _, e := range os.Environ() {
		if i := strings.Index(e, "="); i >= 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	return m
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// i18n strings for Golismero.
type G3TranslatedStringsForLanguage map[string]string              // ID -> strings
type G3TranslatedStrings map[string]G3TranslatedStringsForLanguage // language -> strings map

// Load the i18 strings for Golismero.
// Note that unlike the i18n strings for plugins, these are not templates (mostly).
func LoadG3Strings() G3TranslatedStrings {

	// Get the G3HOME directory.
	g3home := GetHomeDirectory()

	// Load the plugin templates cache JSON file.
	path := filepath.Join(g3home, G3CONFIG, G3STRINGS)
	data, err := os.ReadFile(path)
	if err != nil {
		log.Error("Failed to process " + path + ": " + err.Error())
		os.Exit(1)
	}

	// Parse the JSON file.
	loadedStrings := G3TranslatedStrings{}
	err = json.Unmarshal(data, &loadedStrings)
	if err != nil {
		log.Error("Failed to process " + path + ": " + err.Error())
		os.Exit(1)
	}

	// Return the parsed strings.
	return loadedStrings
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// JSON data from and to plugins.

// The Golismero data model is intentionally very lax, to provide the greatest possible flexibility when developing plugins.
// We only enforce a few properties, all of them starting with an underscore, which the engine uses internally.
//
//   _type   (string): Identifies the data type. For example: "host".
//   _tool   (string): Name of the plugin that generated this object (prevents infinite loop).
//	 _fp   ([]string): Array of fingerprints for the command that produced this object. Cannot be empty.
//
// The following are optional:
//
//   _id        (int): Database ID of the object (if stored in a database).
//   _scanid (string): Scan ID (used to correlate logs).
//   _taskid (string): Task ID (used to correlate logs).
//   _cmd    (string): Command line that was executed to generate this object.
//   _start     (int): Unix timestamp of the moment the command started.
//   _end       (int): Unix timestamp of the moment the command ended.
//
type G3Data map[string]interface{}

func (data G3Data) String() string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "<invalid G3Data object>"
	}
	return string(jsonBytes)
}

// Very rudimentary data integrity check.
// TODO: In the future we could have a fully fledged data model here.
//       If that happens, the G3Data stuff could be moved to a new module "g3model".
func IsValidData(data G3Data) (bool, error) {

	// This ensures if a panic happens here we can recover and return false.
	defer func() { recover() }()

	// Verify the mandatory fields are all present.
	mandatory := []string{								// add more here
		"_type",
		"_tool",
		"_fp",
	}
	for _, field := range mandatory {
		if value, ok := data[field]; !ok || value == nil {
			return false, errors.New("Missing mandatory field: " + field)
		}
	}

	// Verify no unknown underscore field is present.
	for field := range data {
		if len(field) > 0 && field[0:1] == "_" {
			switch field {								// add more here

			case "_type":
			case "_tool":
			case "_fp":

			case "_id":
			case "_taskid":
			case "_scanid":
			case "_cmd":
			case "_start":
			case "_end":

			default:
				return false, errors.New("Unknown underscore field: " + field)
			}
		}
	}

	// Validate the type at least looks correct.
	// (We have no way of checking, since there is no comprehensive list of data types).
	re_type := regexp.MustCompile(`^[a-z]+$`)
	if val := data["_type"].(string); len(val) == 0 || !re_type.Match([]byte(val)) {
		return false, errors.New("Invalid _type field: " + val)
	}

	// Validate the tool name at least looks correct.
	// (We have no way of checking without introducing a circular dependency,
	// also we shouldn't assume we always have the full list of plugins).
	re_tool := regexp.MustCompile(`^[a-zA-Z0-9_\\-]+$`)
	if val := data["_tool"].(string); len(val) == 0 || !re_tool.Match([]byte(val)) {
		return false, errors.New("Invalid _tool field: " + val)
	}

	// Validate the fingerprint at least looks correct.
	// (Checking all plugins would be unwise, again).
	fp := data["_fp"].([]interface{})
	for i := 0; i < len(fp); i++ {
		token := fp[i].(string)
		if token == "" || !strings.Contains(token, " ") || !re_tool.Match([]byte(strings.Split(token, " ")[0])) {
			return false, errors.New("Invalid _fp field: " + token)
		}
	}

	// If this is an issue, check the issue properties valid.
	if data["_type"].(string) == "issue" {
		if value, ok := data["severity"]; !ok || value == nil {
			return false, fmt.Errorf("invalid severity field: %s", value)
		}
		severity := int(data["severity"].(float64))
		if severity < 0 || severity > 3 {
			return false, fmt.Errorf("invalid severity field: %d", severity)
		}
	}

	// Everything is ok!
	return true, nil
}

// Read an array of G3Data objects from a file.
func LoadDataFromFile(filepath string) ([]G3Data, error) {
	var inputJson []G3Data
	var err error

	// Open the file.
	var fd *os.File
	if filepath == "-" {
		fd = os.Stdin
	} else {
		fd, err = os.Open(filepath)
		if err != nil {
			return inputJson, errors.New("Error reading file " + filepath + ": " + err.Error())
		}
		defer fd.Close()
	}

	// Parse the JSON data from the file.
	err = json.NewDecoder(bufio.NewReader(fd)).Decode(&inputJson)
	if err != nil {
		return inputJson, errors.New("Error parsing input JSON data from file " + filepath + ": " + err.Error())
	}

	// Do some minimal validation.
	for index, data := range inputJson {
		if ok, err := IsValidData(data); !ok {
			if err != nil {
				return inputJson, fmt.Errorf("malformed data received, file: %s, index %d: %s", filepath, index, err.Error())
			}
			return inputJson, fmt.Errorf("malformed data received, file: %s, index %d", filepath, index)
		}
	}

	// Return the input array.
	return inputJson, nil
}

// Write an array of G3Data objects into a file.
func SaveDataToFile(filepath string, outputArray []G3Data, beautify bool) error {

	// Save the combined output in JSON format.
	var jsonOutput []byte
	var err error
	if beautify {
		jsonOutput, err = json.MarshalIndent(outputArray, "", "  ")
	} else {
		jsonOutput, err = json.Marshal(outputArray)
	}
	if err != nil {
		return errors.New("error parsing output data: " + err.Error())
	}
	if beautify {
		jsonOutput = append(jsonOutput, []byte("\n")...)
	}

	// Save the output data where requested.
	if filepath == "-" {
		fmt.Print(string(jsonOutput))
	} else {
		err = os.WriteFile(filepath, jsonOutput, 0644)
		if err != nil {
			return errors.New("Error writing to file " + filepath + ": " + err.Error())
		}
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// A string set type for Golang.

type StringSetInterface interface {
	Add(s string)
	AddMulti(a []string)
	Exists(s string) bool
	AnyExist(a []string) bool
	AllExist(a []string) bool
	Delete(s string)
	DeleteMulti(a []string)
	Length() int
	ToArray() []string
}

type void struct{}
var member void

// Non-concurrent version (faster).
type StringSet map[string]void

func (ss StringSet) Add(s string) {
	ss[s] = member
}
func (ss StringSet) AddMulti(a []string) {
	for i := 0; i < len(a); i++ {
		ss[a[i]] = member
	}
}
func (ss StringSet) Exists(s string) bool {
	_, ok := ss[s]
	return bool(ok)
}
func (ss StringSet) AnyExist(a []string) bool {
	for i := 0; i < len(a); i++ {
		if _, ok := ss[a[i]]; ok {
			return true
		}
	}
	return false
}
func (ss StringSet) AllExist(a []string) bool {
	for i := 0; i < len(a); i++ {
		if _, ok := ss[a[i]]; !ok {
			return false
		}
	}
	return true
}
func (ss StringSet) Delete(s string) {
	delete(ss, s)
}
func (ss StringSet) DeleteMulti(a []string) {
	for i := 0; i < len(a); i++ {
		delete(ss, a[i])
	}
}
func (ss StringSet) Length() int {
	return len(ss)
}
func (ss StringSet) Clear() {
	ss.DeleteMulti(ss.ToArray())
}
func (ss StringSet) ToArray() []string {
	keys := make([]string, len(ss))
	i := 0
	for k := range ss {
		keys[i] = k
		i++
	}
	return keys
}
func (ss StringSet) String() string {
	return fmt.Sprintf("%v", ss.ToArray())
}

// Concurrent version (safe for use in goroutines).
type SyncStringSet struct {
	sync.RWMutex
	internal StringSet
}
func NewSyncStringSet() *SyncStringSet {
	return &SyncStringSet{
		internal: make(StringSet),
	}
}
func (sss *SyncStringSet) Add(s string) {
	sss.Lock()
	sss.internal.Add(s)
	sss.Unlock()
}
func (sss *SyncStringSet) AddMulti(a []string) {
	sss.Lock()
	sss.internal.AddMulti(a)
	sss.Unlock()
}
func (sss *SyncStringSet) Exists(s string) bool {
	sss.Lock()
	value := sss.internal.Exists(s)
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) AnyExist(a []string) bool {
	sss.Lock()
	value := sss.internal.AnyExist(a)
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) AllExist(a []string) bool {
	sss.Lock()
	value := sss.internal.AllExist(a)
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) Delete(s string) {
	sss.Lock()
	sss.internal.Delete(s)
	sss.Unlock()
}
func (sss *SyncStringSet) DeleteMulti(a []string) {
	sss.Lock()
	sss.internal.DeleteMulti(a)
	sss.Unlock()
}
func (sss *SyncStringSet) Length() int {
	sss.Lock()
	value := sss.internal.Length()
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) Clear() {
	sss.Lock()
	sss.internal.Clear()
	sss.Unlock()
}
func (sss *SyncStringSet) ToArray() []string {
	sss.Lock()
	value := sss.internal.ToArray()
	sss.Unlock()
	return value
}
func (sss *SyncStringSet) String() string {
	return fmt.Sprintf("%v", sss.ToArray())
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Miscellaneous helper functions.

// Remove duplicates from a string slice.
// https://stackoverflow.com/a/66751055/426293
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// Removes a string from a string slice.
// https://stackoverflow.com/a/34070691/426293
func RemoveStr(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

// Checks if a string exists in a string slice.
func ContainsStr(s []string, r string) bool {
	for _, v := range s {
		if v == r {
			return true
		}
	}
	return false
}

// Remove ANSI escapes from a string.
// https://github.com/acarl005/stripansi/blob/master/stripansi.go
var RE_ANSI = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))")
func StripAnsi(s string) string {
	return RE_ANSI.ReplaceAllString(s, "")
}

// Pretty print a JSON object. Ignores errors.
func PrettyPrintJSON(data interface{}) string {
	var jsonOutput []byte
	var err error
	jsonOutput, err = json.MarshalIndent(data, "", "  ")
	if err == nil {
		return string(jsonOutput)
	}
	return `{\n  "error": "Could not JSON encode the data!"\n}\n`
}

// Asks the user for confirmation.
// https://gist.github.com/r0l1/3dcbb0c8f6cfe9c66ab8008f55f8f28b
func AskForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [y/N]: ", s)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" {
			return true
		} else if response == "" || response == "n" || response == "no" {
			return false
		}
	}
}
