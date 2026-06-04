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

// Default ports per URI scheme, used for RFC 3986 §6.2.3 scheme-based
// normalization (strip the default port so equivalent URLs canonicalize
// identically). Stripping is safe because any conformant client re-applies
// the scheme default when a port is absent. Add entries as new authority-based
// schemes appear in scan targets. Schemes without an authority component
// (mailto, data, javascript, file, urn, etc.) deliberately stay out, as do
// schemes with no standardized default port (rediss, rtsps).
var SchemeDefaultPorts = map[string]string{
	// Web
	"http":  "80",  // RFC 9110
	"https": "443", // RFC 9110
	"ws":    "80",  // RFC 6455
	"wss":   "443", // RFC 6455

	// Mail
	"imap":   "143", // RFC 5092
	"pop":    "110", // RFC 2384
	"smtp":   "25",  // draft-melnikov-smime-msa-to-mda
	"submit": "587", // SMTP submission

	// Directory & naming
	"ldap":  "389", // RFC 4516
	"ldaps": "636", // de facto
	"dns":   "53",  // RFC 4501
	"acap":  "674", // RFC 2244

	// News & messaging
	"nntp": "119",  // RFC 5538
	"irc":  "6667", // de facto — IANA assigns 194, but clients universally default to 6667
	"ircs": "6697", // de facto (IANA service "ircs-u")
	"xmpp": "5222", // RFC 5122 (IANA service "xmpp-client")

	// File transfer & sharing
	"ftp":   "21",   // RFC 1738
	"sftp":  "22",   // SSH File Transfer; IANA "sftp" (115) is an unrelated legacy protocol
	"ssh":   "22",   // de facto; scp shares this
	"tftp":  "69",   // RFC 3617
	"rsync": "873",  // RFC 5781
	"nfs":   "2049", // RFC 2224

	// Streaming & remote access
	"rtsp":   "554",  // RFC 2326
	"rtsps":  "322",  // IANA service registry (RTSPS over TLS)
	"vnc":    "5900", // RFC 7869 (IANA service "rfb")
	"telnet": "23",   // RFC 4248

	// VoIP & realtime
	"sip":   "5060", // RFC 3261
	"sips":  "5061", // RFC 3261
	"h323":  "1720", // de facto
	"iax":   "4569", // RFC 5456
	"stun":  "3478", // RFC 7064
	"stuns": "5349", // RFC 7064
	"turn":  "3478", // RFC 7065
	"turns": "5349", // RFC 7065

	// IoT / M2M
	"coap":      "5683", // RFC 7252
	"coaps":     "5684", // RFC 7252
	"coap+tcp":  "5683", // RFC 8323
	"coaps+tcp": "5684", // RFC 8323
	"mqtt":      "1883", // de facto
	"mqtts":     "8883", // de facto

	// Misc protocols
	"snmp":    "161",  // RFC 4088
	"gopher":  "70",   // RFC 4266
	"dict":    "2628", // RFC 2229
	"finger":  "79",   // de facto
	"icap":    "1344", // RFC 3507
	"ipp":     "631",  // RFC 3510
	"ipps":    "631",  // RFC 7472 (not 443 — keeps the IPP port)
	"sieve":   "4190", // RFC 5804
	"service": "427",  // RFC 2609 (SLP)

	// Source control
	"svn": "3690", // de facto
	"git": "9418", // de facto

	// Databases
	"mongodb": "27017", // de facto
	"redis":   "6379",  // de facto

	// Diameter (IANA service names "diameter" / "diameters")
	"aaa":  "3868", // RFC 6733
	"aaas": "5868", // RFC 6733 (Diameter over TLS)
}

type ParsedImport struct {
	Tool string             `json:"tool"                validate:"required"`
	Path string             `json:"path"                validate:"required"`
}

type ParsedReport struct {
	Tool   string             `json:"tool"                validate:"required"`
	Preset string             `json:"preset,omitempty"`
}

type ParsedScript struct {
	Targets []string        `json:"targets,omitempty"   validate:"omitempty"`
	Imports []ParsedImport  `json:"imports,omitempty"   validate:"omitempty,dive"`
	Mode string             `json:"mode,omitempty"      validate:"omitempty"`
	Pipelines [][]string    `json:"pipelines,omitempty" validate:"omitempty"`
	Report *ParsedReport    `json:"report,omitempty"    validate:"omitempty"`
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
	if parsed.Report != nil {
		if text != "" {
			text = text + "\n"
		}
		if parsed.Report.Preset != "" {
			text = text + "report " + parsed.Report.Tool + ":" + parsed.Report.Preset + "\n"
		} else {
			text = text + "report " + parsed.Report.Tool + "\n"
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

		// Once a report directive has been parsed, no further directives are allowed
		// — report must be the LAST line of the script.
		if parsed.Report != nil {
			err = fmt.Errorf("syntax error on line %d: report directive must be the last line of the script", lineno+1)
			return ParsedScript{}, err
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
			// We don't need to be very thorough here since we can also error out later when importing,
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

		// The "report" command declares a reporter to invoke after the pipeline finishes.
		// Must be the LAST directive in the script. At most one per script.
		// Syntax:
		//   report                      → magenta reporter plugin (the default)
		//   report <tool>[:<preset>]    → reporter plugin (dispatched to a worker)
		// The built-in reporter has been removed; reporting is always delegated
		// to a reporter plugin (magenta by default).
		if commands[0] == "report" {
			if parsed.Report != nil {
				err = fmt.Errorf("syntax error on line %d: only one report directive per script is allowed", lineno+1)
				return ParsedScript{}, err
			}
			if len(commands) > 2 {
				err = fmt.Errorf("syntax error on line %d: report directive takes at most one argument: <tool>[:<preset>]", lineno+1)
				return ParsedScript{}, err
			}
			// Resolve <tool>[:<preset>]. A bare "report" defaults to magenta.
			tool := "magenta"
			preset := ""
			if len(commands) == 2 {
				toolArg := commands[1]
				tool = toolArg
				if i := strings.Index(toolArg, ":"); i >= 0 {
					tool = toolArg[:i]
					preset = toolArg[i+1:]
					if tool == "" {
						err = fmt.Errorf("syntax error on line %d: missing tool name in report directive", lineno+1)
						return ParsedScript{}, err
					}
				}
			}
			// Plugin validation (mirrors /scan/task/dispatch validation in g3api).
			if plugins != nil {
				plugin, ok := plugins[tool]
				if !ok {
					err = fmt.Errorf("runtime error on line %d: tool not found: %s", lineno+1, tool)
					return ParsedScript{}, err
				}
				if plugin.Reporter == nil {
					err = fmt.Errorf("runtime error on line %d: tool %s does not implement a reporter", lineno+1, tool)
					return ParsedScript{}, err
				}
				if preset != "" {
					if len(plugin.Reporter.Commands) == 0 {
						err = fmt.Errorf("runtime error on line %d: tool %s declares no reporter presets", lineno+1, tool)
						return ParsedScript{}, err
					}
					found := false
					for _, c := range plugin.Reporter.Commands {
						if c.Name == preset {
							found = true
							break
						}
					}
					if !found {
						err = fmt.Errorf("runtime error on line %d: unknown preset for tool %s: %s", lineno+1, tool, preset)
						return ParsedScript{}, err
					}
				}
			}
			parsed.Report = &ParsedReport{Tool: tool, Preset: preset}
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

			// Scheme-based normalization (RFC 3986 §6.2.3): strip the default
			// port so equivalent URLs canonicalize identically. Go's net/url
			// preserves whatever port was in the input, unlike JavaScript's URL.
			if defaultPort, ok := SchemeDefaultPorts[url.Scheme]; ok && url.Port() == defaultPort {
				hostname := url.Hostname()
				if strings.Contains(hostname, ":") {
					url.Host = "[" + hostname + "]" // IPv6 literal needs brackets
				} else {
					url.Host = hostname
				}
			}

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
