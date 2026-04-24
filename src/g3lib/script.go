package g3lib

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/kballard/go-shellquote"
)

type ParsedImport struct {
	Tool string             `json:"tool"                validate:"required"`
	Path string             `json:"path"                validate:"required"`
}
type ParsedScript struct {
	Targets []string        `json:"targets,omitempty"   validate:"omitempty"`
	Imports []ParsedImport  `json:"imports,omitempty"   validate:"omitempty,dive"`
	Mode string             `json:"mode,omitempty"      validate:"omitempty"`
	Pipelines [][]string    `json:"pipelines,omitempty" validate:"omitempty"`
}
func (parsed ParsedScript) String() string {
	text := ""
	if parsed.Mode != "" {
		text = text + "mode " + parsed.Mode + "\n"
	}
	if len(parsed.Targets)  > 0 {
		if text != "" {
			text = text + "\n"
		}
		for _, token := range parsed.Targets {
			text = text + "target " + token + "\n"
		}
	}
	if len(parsed.Imports)  > 0 {
		if text != "" {
			text = text + "\n"
		}
		for _, parsedImport := range parsed.Imports {
			text = text + "import " + parsedImport.Tool + " \"" + parsedImport.Path + "\"\n"
		}
	}
	if len(parsed.Pipelines) > 0 {
		if text != "" {
			text = text + "\n"
		}
		for _, pipeline := range parsed.Pipelines {
			text = text + strings.Join(pipeline, " | ") + "\n"
		}
	}
	return text
}

// On this very early version of the parser we're only going to support the most basic syntax possible.
//
//   # comment
//   mode parallel
//   target 192.168.1.1 example.com
//   import nmap samples/nmap.xml
//   dnsrecon
//   nmap | testssl
//
func ParseScript(plugins G3PluginMetadata, script string) (ParsedScript, error) {
	var parsed ParsedScript
	for lineno, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)

		// Skip empty and comment lines.
		if len(line) == 0 {
			continue
		}
		if len(line) > 1 && line[0] == byte(35) {	// #
			continue
		}

		// Each line is split using a shell-like parser.
		commands, err := shellquote.Split(line)
		if err != nil {
			err = fmt.Errorf("syntax error on line %d: %s", lineno+1, err.Error())
			return ParsedScript{}, err
		}
		if len(commands) == 0 {
			continue
		}

		// The "target" command adds a target for scanning.
		// These are executed locally before starting the scan.
		if commands[0] == "target" {
			if len(commands) < 2 {
				err = fmt.Errorf("syntax error on line %d: invalid targets", lineno+1)
				return ParsedScript{}, err
			}
			for _, token := range commands {
				if token == "|" {
					err = fmt.Errorf("syntax error on line %d: cannot mix pipelines and targets", lineno+1)
					return ParsedScript{}, err
				}
			}

			// Check that the targets parse correctly.
			_, err = BuildTargets(commands[1:])
			if err != nil {
				err = fmt.Errorf("syntax error on line %d: %s", lineno+1, err.Error())
				return ParsedScript{}, err
			}

			// Add the target to the parsed structure.
			parsed.Targets = append(parsed.Targets, commands[1:]...)
			continue
		}

		// The "import" command loads an output file from a third party tool into the scan data.
		// These are executed locally before starting the scan.
		if commands[0] == "import" {
			if len(commands) < 3 {
				err = fmt.Errorf("syntax error on line %d: invalid import", lineno+1)
				return ParsedScript{}, err
			}
			for _, token := range commands {
				if token == "|" {
					err = fmt.Errorf("syntax error on line %d: cannot mix pipelines and imports", lineno+1)
					return ParsedScript{}, err
				}
			}
			if plugins != nil {
				if _, ok := plugins[commands[1]]; !ok {
					err = fmt.Errorf("runtime error on line %d: tool not found: %s", lineno+1, commands[1])
					return ParsedScript{}, err
				}
			}

			// Check that the files to import actually exist.
			// We don't need to be very through here since we can also error out later when importing,
			// but it is useful to do some minimal checking here where we can report the script line number.
			for _, token := range commands[2:] {
				if govalidator.IsUUIDv4(token) {
					continue
				}
				if _, err := os.Stat(token); err != nil {
					err = fmt.Errorf("runtime error on line %d: %s", lineno+1, err.Error())
					return ParsedScript{}, err
				}
			}

			// Add the import files to the parsed structure.
			for _, token := range commands[2:] {
				var parsedImport ParsedImport
				parsedImport.Tool = commands[1]
				parsedImport.Path = token
				parsed.Imports = append(parsed.Imports, parsedImport)
			}
			continue
		}

		// The "mode" command sets the execution mode of the script.
		// It can only be used once in the script.
		if commands[0] == "mode" {
			if len(commands) != 2 {
				err = fmt.Errorf("syntax error on line %d: invalid mode command", lineno+1)
				return ParsedScript{}, err
			}
			if parsed.Mode != "" {
				err = fmt.Errorf("syntax error on line %d: mode command can only be used once in a script", lineno+1)
				return ParsedScript{}, err
			}
			parsed.Mode = commands[1]
			if parsed.Mode != "sequential" && parsed.Mode != "parallel" {
				err = fmt.Errorf("syntax error on line %d: unknown mode", lineno+1)
				return ParsedScript{}, err
			}
			continue
		}

		// Any other command must be part of a pipeline.
		// Re-parse the script line using a simpler tokenizer.
		// We don't support arguments to tools and tools can't have spaces in their names.
		var pipeline []string
		for _, token := range strings.Split(line, "|") {
			token = strings.TrimSpace(token)
			if token == "" {
				err = fmt.Errorf("syntax error on line %d: missing tool in pipeline", lineno+1)
				return ParsedScript{}, err
			}
			if strings.Contains(token, " ") {
				err = fmt.Errorf("syntax error on line %d: tools do not take arguments", lineno+1)
				return ParsedScript{}, err
			}
			if plugins != nil {
				if _, ok := plugins[token]; !ok {
					err = fmt.Errorf("runtime error on line %d: tool not found: %s", lineno+1, token)
					return ParsedScript{}, err
				}
			}
			pipeline = append(pipeline, token)
		}

		// Add the pipeline to the parsed structure.
		parsed.Pipelines = append(parsed.Pipelines, pipeline)
	}

	// If no "mode" command was used, set it to the default.
	if parsed.Mode == "" {
		parsed.Mode = "parallel"
	}

	// Return the object with the parsed script.
	// This is not exactly the same object that is sent to g3scanner later,
	// since targets and imports are executed locally, and pipelines remotely.
	return parsed, nil
}

// Parse each target string and generate a corresponding JSON array.
func BuildTargets(arguments []string) ([]G3Data, error) {
	var err error
	jsonArray := []G3Data{}
	timestamp := time.Now().Unix()
	knownFingerprints := StringSet{}
	for _, target := range arguments {
		data := G3Data{}
		data["_tool"] = "g3"
		data["_start"] = timestamp
		data["_end"] = timestamp

		// IPv4 and IPv6 addresses get turned into host.
		// We need to test for IPv6 first if we want IPv4-to-IPv6 addresses to work as IPv6.
		// Otherwise they get automatically converted to IPv4.
		// TODO: reevaluate this, do we want this to work or not?
		if govalidator.IsIPv6(target) {
			ip, err := netip.ParseAddr(target)
			if err != nil {
				err = errors.New("bad IPv6 address: " + target)
				return []G3Data{}, err
			}
			if ip.IsLoopback() {
				err = errors.New("loopback IPv6 address not allowed: " + target)
				return []G3Data{}, err
			}
			target = ip.String()
			data["_type"] = "host"
			data["ipv6"] = target
		} else if govalidator.IsIPv4(target) {
			ip := net.ParseIP(target)
			if ip == nil {
				err = errors.New("bad IPv4 address: " + target)
				return []G3Data{}, err
			}
			if ip.IsLoopback() {
				err = errors.New("loopback IPv4 address not allowed: " + target)
				return []G3Data{}, err
			}
			target = ip.String()
			data["_type"] = "host"
			data["ipv4"] = target

		// IP ranges get turned into cidr.
		} else if ipaddr, iprange, err := net.ParseCIDR(target); err == nil {
			target = iprange.String()
			ipstr := ipaddr.String()
			ip := net.ParseIP(ipstr)
			if ip == nil {
				err = errors.New("bad IP address range: " + target)
				return []G3Data{}, err
			}
			if ip.IsLoopback() {
				err = errors.New("loopback IP address range not allowed: " + target)
				return []G3Data{}, err
			}
			data["_type"] = "cidr"
			if govalidator.IsIPv4(ipstr) {
				data["ipv4"] = target
			} else if govalidator.IsIPv6(ipstr) {
				data["ipv6"] = target
			} else {
				err = errors.New("internal error")
				return []G3Data{}, err
			}

		// URLs get turned into url. The resulting URL must be canonicalized.
		} else if url, err := url.Parse(target); err == nil && url.Host != "" && url.Scheme != "file" {
			if url.Hostname() == "localhost" {
				err = errors.New("localhost domain not allowed: " + target)
				return []G3Data{}, err
			}
			if ip := net.ParseIP(url.Hostname()); ip != nil && ip.IsLoopback() {
				err = errors.New("loopback IP address range not allowed: " + target)
				return []G3Data{}, err
			}
			if url.Scheme == "" {
				url.Scheme = "https"
			}
			if url.Path == "" {
				url.Path = "/"
			}
			url.Fragment = ""
			url.RawFragment = ""
			target = url.String()
			data["_type"] = "url"
			data["url"] = target
			data["scheme"] = url.Scheme
			if url.User.Username() != "" {
				data["username"] = url.User.Username()
			}
			if password, ok := url.User.Password(); ok {
				data["password"] = password
			}
			data["host"] = url.Host
			data["path"] = url.Path

		/////////////////////////////
		// TODO add new types here //
		/////////////////////////////

		// Domain names get turned into domain.
		// This check must go last since it may accidentally match something else.
		} else if target == "localhost" {
			err = errors.New("localhost domain not allowed: " + target)
			return []G3Data{}, err
		} else if govalidator.IsDNSName(target) && strings.Contains(target, ".") {
			data["_type"] = "domain"
			data["domain"] = target

		// If we got here, we could not figure out what it was. :(
		} else {
			err = errors.New("unknown target type: " + target)
			return []G3Data{}, err
		}

		// Generate the fingerprint and check for duplicates.
		fpstr := "g3 target " + target
		if knownFingerprints.Exists(fpstr) {
			continue
		}
		knownFingerprints.Add(fpstr)

		// Add the fingerprint to the object.
		fparr := make([]string, 1)
		fparr[0] = fpstr
		fpiarr := make([]interface{}, 1)
		for i, v := range fparr {
			fpiarr[i] = v
		}
		data["_fp"] = fpiarr

		// Sanity check.
		if ok, err := IsValidData(data); !ok {
			if err != nil {
				return []G3Data{}, err
			} else {
				err = errors.New("internal error")
				return []G3Data{}, err
			}
		}

		// Add the parsed object into the output array.
		jsonArray = append(jsonArray, data)
	}
	return jsonArray, err
}

// Load a list of targets from a file.
func LoadTargetsFromFile(filepath string) ([]string, error) {
	targets := []string{}
	var fd *os.File
	var err error
	if filepath == "-" {
		fd = os.Stdin
	} else {
		fd, err = os.Open(filepath)
		if err != nil {
			return targets, err
		}
		defer fd.Close()
	}
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Trim(line, " \t\r\n")
		if len(line) > 1 && line[0:1] == "#" {		// only entire line comments are supported
			continue
		}
		if len(line) >= 2 && line[0:1] == "\"" && line[len(line)-1:] == "\"" {	// remove ""
			line = line[1:len(line)-1]
		}
		if len(line) == 0 {		// skip empty lines
			continue
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}
