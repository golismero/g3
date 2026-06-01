"""The G3Data type primer — descriptive reference text for LLM consumers."""

DATA_PRIMER: str = """\
g3 tools exchange data using objects called G3Data — JSON dictionaries with a
small mandatory envelope plus arbitrary domain fields. Every object carries:

  _type   : string   — the object's kind (e.g. "host", "url", "issue")
  _tool   : string   — the plugin that produced it (g3 itself for targets)
  _fp     : [string] — non-empty fingerprint identifying how it was produced

Additional envelope fields, populated by the framework:

  _id        : string — Mongo ObjectId, present once the object is saved
  _scanid    : string — owning scan UUID
  _taskid    : string — the dispatched task that produced it
                        (NIL UUID "00000000-..." for targets and imports)
  _cmd       : string — the command line that produced it
  _start     : int    — Unix timestamp when the producing command started
  _end       : int    — Unix timestamp when the producing command ended
  _artifacts : [string] — relative paths of files written to the task's
                          artifact slot

You acquire G3Data objects in three ways:
  - add_target(string)  — canonicalises a URL / host / domain / CIDR string
                          into a G3Data object;
  - run(obj, tool)      — returns the G3Data objects the tool produced;
  - import_file(path)   — parses tool-output files into G3Data.

You should NOT construct G3Data objects yourself. The framework owns the
canonical shape; manual constructions that don't conform to the envelope
contract are rejected at insert time. Pass objects between calls by handing
the dictionaries you received from one method into the next.

Common `_type` values you will encounter and their typical domain fields:

  host     — ipv4, ipv6, mac, vendor, services (array of {port, protocol,
             state, service, ...}), os_matches (array of {name, accuracy,
             cpe}), hostnames (array of strings).
  url      — url (string), scheme ("http"/"https"), host, port, path.
  domain   — domain (string), tld.
  cidr     — cidr (string).
  service  — host, port, protocol, service, banner.
  issue    — title, level (e.g. "info", "low", "medium", "high"),
             description, url (where it was observed), references, evidence.

These field listings are descriptive ("you will commonly see these"), not
prescriptive ("you must construct objects with exactly these"). Per-type
fields evolve as tools and their importers improve.

When invoking a tool, pass it an object whose `_type` is listed in the
plugin's `accepts`. The tool's `produces` lists the `_type` values it may
emit; multi-type producers (nmap emits both `host` and `issue`; dig emits
both `domain` and `host`) split their output across multiple objects in
the returned data list.
"""
