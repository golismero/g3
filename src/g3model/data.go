package g3model

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"strconv"
	"time"
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
type Data map[string]interface{}

func (data Data) String() string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "<invalid Data object>"
	}
	return string(jsonBytes)
}

// Very rudimentary data integrity check.
func (data Data) Validate() error {

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
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Convert user-supplied strings to Data objects as scan targets.

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

// Parse each target string and generate a corresponding JSON array.
func BuildTargets(arguments []string) ([]Data, error) {
	var err error
	jsonArray := []Data{}
	timestamp := time.Now().Unix()
	knownFingerprints := StringSet{}
	for _, target := range arguments {
		data := Data{}
		data["_tool"] = "g3"
		data["_start"] = timestamp
		data["_end"] = timestamp

		// IPv4 and IPv6 addresses get turned into "host".
		// We need to test for IPv6 first if we want IPv4-to-IPv6 addresses to work as IPv6.
		// Otherwise they get automatically converted to IPv4.
		// If someone specifically used this syntax, they're trying to force IPv6.
		if Validate.Var(target, "required,ipv6") == nil {
			ip, err := netip.ParseAddr(target)
			if err != nil {
				err = errors.New("bad IPv6 address: " + target)
				return []Data{}, err
			}
			if ip.IsLoopback() {
				err = errors.New("loopback IPv6 address not allowed: " + target)
				return []Data{}, err
			}
			target = ip.String()
			data["_type"] = "host"
			data["ipv6"] = target
		} else if Validate.Var(target, "required,ipv4") == nil  {
			ip := net.ParseIP(target)
			if ip == nil {
				err = errors.New("bad IPv4 address: " + target)
				return []Data{}, err
			}
			if ip.IsLoopback() {
				err = errors.New("loopback IPv4 address not allowed: " + target)
				return []Data{}, err
			}
			target = ip.String()
			data["_type"] = "host"
			data["ipv4"] = target

		// IP ranges get turned into "cidr".
		// We also need to parse IPv6 before IPv4 to prevent conversion.
		} else if ipaddr, iprange, err := net.ParseCIDR(target); err == nil {
			target = iprange.String()
			ipstr := ipaddr.String()
			ip := net.ParseIP(ipstr)
			if ip == nil {
				err = errors.New("bad IP address range: " + target)
				return []Data{}, err
			}
			if ip.IsLoopback() {
				err = errors.New("loopback IP address range not allowed: " + target)
				return []Data{}, err
			}
			data["_type"] = "cidr"
			if Validate.Var(ipstr, "required,ipv6") == nil {
				data["ipv6"] = target
			} else if Validate.Var(ipstr, "required,ipv4") == nil  {
				data["ipv4"] = target
			} else {
				err = errors.New("internal error")
				return []Data{}, err
			}

		// URLs get turned into "url". The resulting URL must be canonicalized.
		} else if url, err := url.Parse(target); err == nil && url.Host != "" && url.Scheme != "file" && url.Path != "*" {
			if url.Hostname() == "localhost" {
				err = errors.New("localhost domain not allowed: " + target)
				return []Data{}, err
			}
			if ip := net.ParseIP(url.Hostname()); ip != nil && ip.IsLoopback() {
				err = errors.New("loopback IP address range not allowed: " + target)
				return []Data{}, err
			}
			if url.Scheme == "" {
				url.Scheme = "https"
			}
			if url.Path == "" {
				url.Path = "/"
			}

			// Strip the fragment - it's unusable outside of a browser context.
			url.Fragment = ""
			url.RawFragment = ""

			// I'm gonna reuse this one a lot below.
			hostname := url.Hostname()

			// Scheme-based normalization (RFC 3986 §6.2.3): strip the default
			// port so equivalent URLs canonicalize identically. Go's net/url
			// preserves whatever port was in the input, unlike JavaScript's URL.
			if defaultPort, ok := SchemeDefaultPorts[url.Scheme]; ok && url.Port() == defaultPort {
				if strings.Contains(hostname, ":") {
					url.Host = "[" + hostname + "]" // IPv6 literal needs brackets
				} else {
					url.Host = hostname
				}
			}

			// Start building the "url" type object.
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

			// Split domain and port for easier handling.
			if ip := net.ParseIP(hostname); ip == nil && strings.Contains(hostname, ".") {
				if url.Port() != "" {
					data["domain"] = hostname
					data["port"], _ = strconv.Atoi(url.Port())
				} else if defaultPort, ok := SchemeDefaultPorts[url.Scheme]; ok {
					data["domain"] = hostname
					data["port"], _ = strconv.Atoi(defaultPort)
				}
			}

		/////////////////////////////
		// TODO add new types here //
		/////////////////////////////

		// Domain names get turned into "domain".
		// This check must go last since it may accidentally match something else.
		// We're intentionally not allowing local hostnames (without a dot).
		} else if target == "localhost" {
			err = errors.New("localhost domain not allowed: " + target)
			return []Data{}, err
		} else if strings.Contains(target, ".") && Validate.Var(target, "required,hostname_rfc1123") == nil {
			data["_type"] = "domain"
			data["domain"] = target

		// If we got here, we could not figure out what it was. :(
		} else {
			err = errors.New("unknown target type: " + target)
			return []Data{}, err
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
		if err = data.Validate(); err != nil {
			return []Data{}, err
		}

		// Add the parsed object into the output array.
		jsonArray = append(jsonArray, data)
	}
	return jsonArray, err
}
