"""The G3Data type primer — descriptive reference for LLM consumers."""

G3DATA_PRIMER: str = """\
g3 tools exchange data using objects called G3Data — JSON dictionaries with a
small mandatory envelope plus arbitrary domain fields. Every object carries:

  _type   : string   — the object's kind (e.g. "host", "url", "issue")
  _tool   : string   — the plugin that produced it (g3 itself for targets)
  _fp     : [string] — non-empty fingerprint identifying how it was produced

Optional envelope fields, populated by the framework:

  _id        : string — Mongo ObjectId, present once the object is saved
  _scanid    : string — owning scan UUID
  _taskid    : string — the dispatched task that produced it
                        (NIL UUID "00000000-..." for targets and imports)
  _cmd       : string — the command line that produced it
  _start     : int    — Unix timestamp when the producing command started
  _end       : int    — Unix timestamp when the producing command ended
  _artifacts : [string] — relative paths of files written to the task's
                          artifact slot

Common `_type` values and their typical domain fields:

  host     — ipv4, ipv6, mac, vendor, services (array of {port, protocol,
             state, service, ...}), os_matches (array of {name, accuracy,
             cpe}), hostnames (array of strings).
  url      — url (string), scheme ("http"/"https"), host, port, path.
  domain   — domain (string), tld.
  cidr     — cidr (string).
  service  — host, port, protocol, service, banner.
  issue    — title, level (e.g. "info", "low", "medium", "high"),
             description, url (where it was observed), references, evidence.

When dispatching a tool, the `dataid` you pass to `run_tool()` is the Mongo
`_id` of one of these objects. The plugin's contract
(`describe_tool().accepts`) tells you which `_type` values the tool consumes.
Its `.produces` tells you what type the tool will write back.
"""
