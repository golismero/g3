package g3model

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

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
//   _id          (int): Database ID of the object (if stored in a database).
//   _scanid   (string): Scan ID (used to correlate logs).
//   _taskid   (string): Task ID (used to correlate logs).
//   _cmd      (string): Command line that was executed to generate this object.
//   _start       (int): Unix timestamp of the moment the command started.
//   _end         (int): Unix timestamp of the moment the command ended.
//   _artifacts ([]string): Relative filenames (under /artifacts/) the producing
//                          command wrote. Used by the worker to build the per-
//                          task manifest. Absent / empty / partial is allowed.
//                          Claimed-but-missing files cause a loud task ERROR.
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
func (data G3Data) Validate() error {

	// This ensures if a panic happens here we can recover and return false.
	defer func() { recover() }() //nolint:errcheck

	// Verify the mandatory fields are all present.
	mandatory := []string{								// add more here
		"_type",
		"_tool",
		"_fp",
	}
	for _, field := range mandatory {
		if value, ok := data[field]; !ok || value == nil {
			return errors.New("Missing mandatory field: " + field)
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
			case "_artifacts":

			default:
				return errors.New("Unknown underscore field: " + field)
			}
		}
	}

	// Validate the type at least looks correct.
	// (We have no way of checking, since there is no comprehensive list of data types).
	re_type := regexp.MustCompile(`^[a-z]+$`)
	if val := data["_type"].(string); len(val) == 0 || !re_type.Match([]byte(val)) {
		return errors.New("Invalid _type field: " + val)
	}

	// Validate the tool name at least looks correct.
	// (We have no way of checking without introducing a circular dependency,
	// also we shouldn't assume we always have the full list of plugins).
	re_tool := regexp.MustCompile(`^[a-zA-Z0-9_\\-]+$`)
	if val := data["_tool"].(string); len(val) == 0 || !re_tool.Match([]byte(val)) {
		return errors.New("Invalid _tool field: " + val)
	}

	// Validate the fingerprint at least looks correct.
	// (Checking all plugins would be unwise, again).
	fp := data["_fp"].([]interface{})
	for i := 0; i < len(fp); i++ {
		token := fp[i].(string)
		if token == "" || !strings.Contains(token, " ") || !re_tool.Match([]byte(strings.Split(token, " ")[0])) {
			return errors.New("Invalid _fp field: " + token)
		}
	}

	// Everything is ok!
	return nil
}
