package g3lib

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"
)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Builds the template parser using our custom functions.
func BuildTemplate(token string) (*template.Template, error) {

	// Define the function map with our custom functions.
	funcMap := template.FuncMap{
		"find":         FindValueInData,    // Recursive property search function.
		"match":        MatchProperty,      // Recursive property match function.
		"eslice":       ExtendedSlice,      // Extended slice syntax.
		"stripAnsi":    StripAnsi,          // Remove ANSI escape characters.
		"fields":       strings.Fields,
		"contains":     strings.Contains,
		"hasPrefix":    strings.HasPrefix,
		"hasSuffix":    strings.HasSuffix,
		"join":         StringsJoin,
		"int":          ConvertToInt,
		"sum":          Sum,
		"times":        Multiply,
		"minus":        Minus,
		"timestamp":    FormatUnixTime,     // Convert Unix timestamp to human readable string.
		"codeblock":    MarkdownCodeBlock,  // Generate a Markdown code block.

		// TODO add more here
	}

	// Create the text template parser.
	return template.New("").Funcs(funcMap).Parse(token)
}

// Expands a text template using our custom functions.
func ExpandTemplate(token string, data any) (string, error) {

	// Build the template parser.
	tmpl, err := BuildTemplate(token)
	if err != nil {
		//return "", fmt.Errorf("parsing error: %s; template: %s", err.Error(), token)
		return "", fmt.Errorf("parsing error: %s", err.Error())
	}

	// Execute the text template against the data.
	var buffer bytes.Buffer
	err = tmpl.Execute(&buffer, &data)
	if err != nil {
		//return "", fmt.Errorf("parsing error: %s; template: %s", err.Error(), token))
		return "", fmt.Errorf("parsing error: %s", err.Error())
	}

	// Validate the template expansion and return the expanded string.
	expanded := buffer.String()
	if strings.Contains(expanded, "<no value>") {
		return expanded, errors.New("missing values in template: " + token)
	}
	return expanded, nil
}

// Expands an array of template strings.
func ExpandTemplateArray(templateArray []string, data any) ([]string, []error) {
	var errorArray []error
	var parsedArray []string
	for _, template := range templateArray {
		value, err := ExpandTemplate(template, data)
		if err != nil {
			errorArray = append(errorArray, err)
		} else if value != "" {
			parsedArray = append(parsedArray, value)
		}
	}
	return parsedArray, errorArray
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Recursive property search function.
func FindValueInData(data any, propname string) interface{} {
	_, value, _ := _findInData(data, []string{}, propname)
	return value
}
func FindPathInData(data any, propname string) []string {
	path, _, _ := _findInData(data, []string{}, propname)
	return path
}
func _findInData(data any, path []string, propname string) ([]string, interface{}, bool) {
	//fmt.Fprintf(os.Stderr, "PATH: %v\n", path)
	v := reflect.ValueOf(data)
	t := v.Kind()
	//fmt.Fprintf(os.Stderr, "TYPE: %v\n", t)
	switch t {
	case reflect.Slice:
		for index, child := range data.([]interface{}) {
			key := strconv.Itoa(index)
			//fmt.Fprintf(os.Stderr, "KEY: %v\n", key)
			path = append(path, key)
			rpath, value, found := _findInData(child, path, propname)
			if found {
				return rpath, value, true
			}
			path = path[:len(path)-1]
		}
	case reflect.Map:
		switch typedData := data.(type) {
		case map[string]interface{}:
			for key, value := range typedData {
				//fmt.Fprintf(os.Stderr, "KEY: %v\n", key)
				if key == propname {
					return path, value, true
				}
				path = append(path, key)
				rpath, rvalue, found := _findInData(value, path, propname)
				if found {
					return rpath, rvalue, true
				}
				path = path[:len(path)-1]
			}
		case G3Data:
			for key, value := range typedData {
				//fmt.Fprintf(os.Stderr, "KEY: %v\n", key)
				if key == propname {
					return path, value, true
				}
				path = append(path, key)
				rpath, rvalue, found := _findInData(value, path, propname)
				if found {
					return rpath, rvalue, true
				}
				path = path[:len(path)-1]
			}
		default:
			//fmt.Fprintln(os.Stderr, "WRONG KIND OF MAP")
		}
	}
	return path, nil, false
}

// Recursive property match function.
func MatchProperty(data any, propname string, value any) bool {
	return _matchProperty(data, propname, value)
}
func _matchProperty(data interface{}, propname string, wanted any) bool {
	v := reflect.ValueOf(data)
	t := v.Kind()
	switch t {
	case reflect.Slice:
		for _, child := range data.([]interface{}) {
			found := _matchProperty(child, propname, wanted)
			if found {
				return true
			}
		}
	case reflect.Map:
		switch typedData := data.(type) {
		case map[string]interface{}:
			for key, value := range typedData {
				if key == propname && value == wanted {
					return true
				}
				found := _matchProperty(value, propname, wanted)
				if found {
					return true
				}
			}
		case G3Data:
			for key, value := range typedData {
				if key == propname && value == wanted {
					return true
				}
				found := _matchProperty(value, propname, wanted)
				if found {
					return true
				}
			}
		default:
		// 	fmt.Fprintln(os.Stderr, "WRONG KIND OF MAP")
		}
	}
	return false
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Extended slice syntax. This makes slices more useful on templates.
// If p or q are negative, we count from the end of the array.
// If q is zero, it means the end of the array.
func ExtendedSlice(iterable []interface{}, p int, q int) []interface{} {
	l := len(iterable)
	if p < 0 {
		p = l - p
	}
	if q < 0 {
		q = l - q
	} else if q == 0 {
		q = l
	}
	return iterable[p:q]
}

// Wrapper over strings.Join().
func StringsJoin(s []interface{}, sep string) string {
	c := make([]string, len(s))
	for i, x := range s {
		c[i] = x.(string)
	}
	return strings.Join(c, sep)
}

// Force conversion of numbers to integers.
// This was originally needed because Golang's JSON parser uses flaot64 by default.
// It was later extended to support more types to make it more usable in other cases.
func ConvertToInt(num interface{}) int {
	switch v := num.(type) {
	case bool:
		if v {
			return 1
		}
		return 0
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		val, err := strconv.Atoi(v)
		if err != nil {
			panic(err)
		}
		return val
	}
	return 0
}

// Some arithmetic operations.
func Sum(nums ...int) int {
	total := 0
	for _, num := range nums {
        total += num
    }
	return total
}
func Multiply(nums ...int) int {
	total := 0
	for _, num := range nums {
        total = total * num
    }
	return total
}
func Minus(a int) int {
	return -a
}

// Format Unix timestamps into a human readable string.
func FormatUnixTime(timestamp interface{}) string {
	var unixTime int64 = int64(ConvertToInt(timestamp))
	t := time.Unix(unixTime, 0)
	strDate := t.Format(time.UnixDate)
	return strDate
}

// Format code blocks in Markdown.
// See: https://stackoverflow.com/questions/31825237/how-do-i-escape-three-backticks-surrounded-by-a-codeblock-in-markdown
func MarkdownCodeBlock(codeblock string) string {
	if !strings.HasSuffix(codeblock, "\n") {
		codeblock = codeblock + "\n"
	}
	escaped := codeblock
	must_escape := false
	for _, line := range strings.Split(codeblock, "\n") {
		if strings.HasPrefix(line, "```") {
			must_escape = true
			break
		}
	}
	if must_escape {
		escaped = ""
		for _, line := range strings.Split(codeblock, "\n") {
			escaped = escaped + "    " + line + "\n"
		}
	}
	return "```\n" + escaped + "```\n"
}
