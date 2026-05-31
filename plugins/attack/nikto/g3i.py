#!/usr/local/bin/python3

# Nikto importer: parse Nikto CSV output into G3Data issue objects.
#
# Ported from the Magenta Nikto parser (parsers/nikto/nikto.py): the reference
# classifier and CSV reader are shared logic; only the final emit step differs,
# producing G3Data (severity int, _cmd/_fp/_artifacts) instead of Magenta's
# issue contract. JSON and XML readers are added in later tiers; this tier
# handles the live CSV wrapper output only.

import io
import re
import csv
import sys
import json
import shlex
from collections import namedtuple

# Set to True to include informational findings (those with no specific
# vulnerability tag) in the report. g3 uses Nikto to surface known (tagged)
# vulnerabilities only; tag-less findings (missing headers, BREACH, etc.) are
# dropped by default. Mirrors the old OSVDB-0 behaviour.
INCLUDE_INFO = False

# Load the OSVDB to CVE map. Keys are colon-form: "OSVDB:<n>". The file is
# generated at build time (misc/osvdb2cve.py) and copied next to the wrapper
# (Dockerfile WORKDIR /app); load it relative to the current directory.
osvdb2cve = {}
try:
    with open("osvdb2cve.json") as fd:
        osvdb2cve = json.load(fd)
    del fd
except Exception:
    sys.stderr.write(
        "Warning: could not load osvdb2cve.json; OSVDB ids will not be translated.\n"
    )

# A normalized finding produced by every format reader.
Finding = namedtuple(
    "Finding", ["host_url", "path", "method", "refs_str", "nikto_id", "msg"]
)

# --- reference token patterns -------------------------------------------------
# Specific-vulnerability identifiers (go in the per-finding "cve" column).
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
_MS_RE = re.compile(r"^MS\d{2}-\d+$")  # Microsoft bulletins, e.g. MS00-078
_CNVD_RE = re.compile(r"^CNVD(?:-C)?-\d{4}-\d+$")  # incl. the -C- sub-series
_OSVDB_RE = re.compile(r"^OSVDB-(\d+)$", re.I)
# General-concept / other taxonomy (go in issue-level taxonomy only).
_CWE_RE = re.compile(r"^CWE-\d+$")
_CAPEC_RE = re.compile(r"^CAPEC-\d+$")
_RFC_RE = re.compile(r"^RFC-(\d+)$", re.I)
_MSKB_RE = re.compile(r"^MSKB:Q?(\d+)$", re.I)
_BID_RE = re.compile(r"^BID-\d+$", re.I)
_URL_RE = re.compile(r"^https?://", re.I)

# Unicode hyphens/dashes Nikto's DB occasionally uses inside ids (e.g.
# "CVE‑2002‑1929" with U+2011). Normalized to ASCII "-" before matching so the
# id regexes above still fire instead of dropping a real CVE as "unknown".
_UNICODE_HYPHENS = re.compile("[‐-―−]")

# Taxonomy-derived URLs: a URL that is merely a linkified id collapses to that
# id (the reporter linkifies tags itself), instead of becoming a standalone
# reference. Order matters; host-specific patterns avoid CWE/CAPEC confusion.
# Each entry: (compiled regex, bucket, prefix) where bucket is
# "cve"/"taxonomy"/"osvdb"; the captured group is the id payload.
_URL_TAXONOMY_PATTERNS = [
    (
        re.compile(r"^https?://cwe\.mitre\.org/data/definitions/(\d+)\.html", re.I),
        "taxonomy",
        "CWE-",
    ),
    (
        re.compile(r"^https?://capec\.mitre\.org/data/definitions/(\d+)\.html", re.I),
        "taxonomy",
        "CAPEC-",
    ),
    (
        re.compile(r"^https?://(?:[\w.-]+\.)?vulners\.com/osvdb/OSVDB:(\d+)", re.I),
        "osvdb",
        "",
    ),
    (
        re.compile(
            r"^https?://(?:nvd\.nist\.gov|(?:www\.)?cve\.(?:mitre\.org|org))/\S*?"
            r"(CVE-\d{4}-\d+)",
            re.I,
        ),
        "cve",
        "",
    ),
]


def _url_to_tag(url):
    """Return (bucket, value) if url is a linkified taxonomy id, else None."""
    for pattern, bucket, prefix in _URL_TAXONOMY_PATTERNS:
        m = pattern.match(url)
        if m:
            return bucket, prefix + m.group(1).upper()
    return None


# Token-keyed overrides for known-bad upstream references. Each maps a token to
# (cve, taxonomy, references) contributions. Keyed on the token (not nikto_id),
# because CSV output carries no id column. Each token is unique to its test.
_TOKEN_OVERRIDES = {
    # Phorum 3.3.2a admin GLOBALS[message] XSS. main corrupted OSVDB-11144 into
    # OSVCVE-2011-339244 and mis-tagged the companion test with CVE-2011-3392
    # (a different, later Phorum 5.2.17 vuln). Correct CVE for both: CVE-2002-0764.
    "OSVCVE-2011-339244": (["CVE-2002-0764"], [], []),
    "CVE-2011-3392": (["CVE-2002-0764"], [], []),
}
# Concept-only hardcodes (no specific CVE exists). CA-2000-02 is the 2000 CERT
# advisory that introduced XSS as a concept; the only tests using it
# (000767/768/769) are ASP/ASP.NET reflected XSS -> CWE-79.
_CONCEPT_HARDCODE = {"CA-2000-02": "CWE-79"}
# Known DB-bug junk tokens: token -> the only nikto_id it legitimately appears on.
_KNOWN_JUNK = {"WS_FTP.LOG": "001353"}

# OSVDB lookup hit-rate counters (drift guard). Reset per run in main().
_osvdb_stats = {"mapped": 0, "unmapped": 0}


def reset_osvdb_stats():
    _osvdb_stats["mapped"] = 0
    _osvdb_stats["unmapped"] = 0


def _resolve_osvdb(num):
    # OSVDB-0 is Nikto's "no specific vulnerability" marker (informational),
    # not a real id. Drop it so the finding is treated as untagged.
    if num == "0":
        return []
    mapped = osvdb2cve.get("OSVDB:" + num)
    if mapped:
        _osvdb_stats["mapped"] += 1
        return list(mapped)
    _osvdb_stats["unmapped"] += 1
    return ["OSVDB-" + num]


def osvdb_hitrate_warning():
    total = _osvdb_stats["mapped"] + _osvdb_stats["unmapped"]
    if total >= 10 and _osvdb_stats["mapped"] == 0:
        sys.stderr.write(
            "WARNING: %d OSVDB ids seen but none mapped to a CVE; the "
            "osvdb2cve.json key format may have drifted (expected 'OSVDB:<n>').\n"
            % total
        )


def _dedup(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def classify_references(refs_str, nikto_id=None):
    """Split a Nikto references string into:
      - cve:        specific-vulnerability ids (CVE, MS bulletin, CNVD, OSVDB->CVE)
      - taxonomy:   general-concept tags (CWE, CAPEC, RFC, KB)
      - references: external URLs
    Tokens are split on whitespace and commas. Unknown tokens warn loudly."""
    cve, taxonomy, references = [], [], []
    if refs_str:
        for raw in re.split(r"[\s,]+", refs_str.strip()):
            tok = raw.strip().strip("\"'")
            if tok:
                _classify_token(tok, nikto_id, cve, taxonomy, references)
    return {
        "cve": _dedup(cve),
        "taxonomy": _dedup(taxonomy),
        "references": _dedup(references),
    }


def _classify_token(tok, nikto_id, cve, taxonomy, references):
    # URLs first — never strip trailing punctuation from a URL.
    if _URL_RE.match(tok):
        collapsed = _url_to_tag(tok)
        if collapsed is None:
            references.append(tok)
        elif collapsed[0] == "cve":
            cve.append(collapsed[1])
        elif collapsed[0] == "taxonomy":
            taxonomy.append(collapsed[1])
        elif collapsed[0] == "osvdb":
            cve.extend(_resolve_osvdb(collapsed[1]))
        return

    # Strip trailing sentence punctuation before any matching, so that e.g.
    # "CVE-2011-3392." still hits the overrides below and "CA-2000-02:" the
    # hardcodes. (None of the known special tokens end in . ; or :.)
    tok = tok.rstrip(".;:")
    if not tok:
        return

    # Normalize Unicode hyphens to ASCII "-" so ids like "CVE‑2002‑1929"
    # (U+2011) match the scheme regexes instead of being dropped as unknown.
    tok = _UNICODE_HYPHENS.sub("-", tok)

    # Token-keyed overrides for known-bad upstream references.
    if tok in _TOKEN_OVERRIDES:
        c, t, r = _TOKEN_OVERRIDES[tok]
        cve.extend(c)
        taxonomy.extend(t)
        references.extend(r)
        return

    # Known DB-bug junk tokens. Silent on the test that legitimately carries
    # them; loud anywhere else (we may have a new bug).
    if tok in _KNOWN_JUNK:
        expected = _KNOWN_JUNK[tok]
        if nikto_id is not None and nikto_id != expected:
            sys.stderr.write(
                "WARNING: junk reference token %r on unexpected nikto_id=%s; dropping.\n"
                % (tok, nikto_id)
            )
        return

    # Concept-only hardcodes (e.g. CA-2000-02 -> CWE-79).
    if tok in _CONCEPT_HARDCODE:
        taxonomy.append(_CONCEPT_HARDCODE[tok])
        return

    if _CVE_RE.match(tok) or _MS_RE.match(tok) or _CNVD_RE.match(tok):
        cve.append(tok)
        return
    if _CWE_RE.match(tok) or _CAPEC_RE.match(tok):
        taxonomy.append(tok)
        return
    m = _OSVDB_RE.match(tok)
    if m:
        cve.extend(_resolve_osvdb(m.group(1)))
        return
    m = _RFC_RE.match(tok)
    if m:
        taxonomy.append("RFC " + m.group(1))  # normalize dash->space for url_from_tag
        return
    m = _MSKB_RE.match(tok)
    if m:
        taxonomy.append("KB" + m.group(1))  # normalize MSKB:Q<n> -> KB<n>
        return
    if _BID_RE.match(tok):
        return  # dead taxonomy, no shipped map; drop (known class)

    # Anything else: do not guess. Warn loudly (future-version safety).
    sys.stderr.write(
        "WARNING: unrecognized Nikto reference token %r (nikto_id=%s); dropping.\n"
        % (tok, nikto_id)
    )


def _host_url(hostname, ip, port):
    host = hostname or ip
    use_ssl = str(port) == "443"
    scheme = "https" if use_ssl else "http"
    return "%s://%s:%s" % (scheme, host, port)


def _fp_host(host_url):
    """Fingerprint form of a host URL: drop the default port, add trailing /.
    "https://h:443" -> "https://h/"; "http://h:8080" -> "http://h:8080/"."""
    m = re.match(r"^(https?)://(.*):(\d+)$", host_url)
    if not m:
        return host_url.rstrip("/") + "/"
    scheme, host, port = m.group(1), m.group(2), m.group(3)
    default = "443" if scheme == "https" else "80"
    if port == default:
        return "%s://%s/" % (scheme, host)
    return "%s://%s:%s/" % (scheme, host, port)


def _strip_csv_injection(cell):
    # Nikto prefixes a "'" to cells starting with = + @ - (CSV-injection guard).
    if cell[:1] == "'" and cell[1:2] in ("=", "+", "@", "-"):
        return cell[1:]
    return cell


def read_csv(input_data):
    fd = io.StringIO(input_data)
    fd.readline()  # discard the '"Nikto - v..."' header line
    findings = []
    # Most recent host-start row's (ip, port). Used to recover the port for the
    # 2.1.5 6-field finding rows, where a runtime bug merged ip+SCALAR(...)+port
    # into one cell and dropped the port column from finding rows.
    last_host = None
    for row in csv.reader(fd):
        n = len(row)
        if n >= 7:
            hostname, ip, port, col_ref, method, uri, msg = (
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
                row[5],
                row[6],
            )
            # Host-start rows have empty method+uri (banner sits in col7).
            if not method and not uri:
                last_host = (ip, port)
                continue
        elif n == 6:
            # 2.1.5 port-merge bug: hostname, ip+junk+port, OSVDB, method, uri, msg.
            hostname, _ip_junk, col_ref, method, uri, msg = (
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
                row[5],
            )
            if not method and not uri:
                continue
            ip, port = last_host if last_host else ("", "80")
        else:
            continue  # blank/short line
        col_ref = _strip_csv_injection(col_ref)
        # SSL-info rows (2.6.0+) use the pseudo test id 000137 in the ref cell.
        if col_ref == "000137":
            continue
        findings.append(
            Finding(
                host_url=_host_url(hostname, ip, port),
                path=uri,
                method=method,
                refs_str=col_ref,
                nikto_id=None,  # CSV has no id column
                msg=msg,
            )
        )
    return findings


def _path_from_url(url, host_url):
    if url and url.startswith(host_url):
        return url[len(host_url) :] or "/"
    return url or "/"


def _findings_from_json_hosts(hosts):
    findings = []
    for host in hosts:
        host_url = _host_url(host.get("host"), host.get("ip"), host.get("port") or "80")
        for v in host.get("vulnerabilities", []):
            url = v.get("url", "")
            findings.append(
                Finding(
                    host_url=host_url,
                    path=_path_from_url(url, host_url),
                    method=v.get("method", ""),
                    refs_str=v.get("references", "") or "",
                    nikto_id=v.get("id"),
                    msg=v.get("msg", "") or "",
                )
            )
    return findings


def read_json(input_data):
    """Parse Nikto JSON output. 2.6.0+ emits a clean array of host objects;
    2.5.0 emitted concatenated per-host objects (invalid JSON for >1 host),
    which we repair by inserting commas and wrapping in an array."""
    try:
        data = json.loads(input_data)
    except ValueError:
        repaired = input_data.strip().replace("}{", "},{")
        if not repaired.startswith("["):
            repaired = "[" + repaired + "]"
        try:
            data = json.loads(repaired)
        except ValueError:
            sys.stderr.write(
                "WARNING: could not parse Nikto JSON (and 2.5.0 fragment "
                "repair failed); skipping.\n"
            )
            return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        sys.stderr.write("WARNING: unexpected Nikto JSON shape; skipping.\n")
        return []
    return _findings_from_json_hosts(data)


def build_issues(findings):
    by_host = {}  # host_url -> list[ {path, cve, msg} ]
    all_taxonomy = []
    all_references = []
    affects = []
    for f in findings:
        cls = classify_references(f.refs_str, f.nikto_id)
        tags = cls["cve"] + cls["taxonomy"]
        # Inclusion rule: report only findings carrying >=1 taxonomy tag.
        # Tag-less findings are informational (old OSVDB-0 behaviour).
        if not tags and not INCLUDE_INFO:
            continue
        entry = {"path": f.path, "cve": cls["cve"], "msg": f.msg}
        host_list = by_host.setdefault(f.host_url, [])
        if entry not in host_list:
            host_list.append(entry)
        affects.append(f.host_url + f.path)
        all_taxonomy.extend(tags)
        all_references.extend(cls["references"])
    if not by_host:
        return []

    # g3 provenance. When run from the wrapper (g3p), sys.argv carries the Nikto
    # command line and the artifacts exist on disk; standalone there is no cmd.
    if len(sys.argv) > 1:
        cmd = shlex.join(["nikto.pl"] + sys.argv[1:])
        artifacts = ["nikto.txt", "nikto.csv"]
    else:
        cmd = None
        artifacts = []

    issue = {
        "_fp": ["nikto " + _fp_host(h) for h in sorted(by_host)],
        "_artifacts": artifacts,
        "severity": 2,  # high
        "affects": sorted(set(affects)),
        "taxonomy": sorted(set(all_taxonomy)),
        "references": sorted(set(all_references + ["https://github.com/sullo/nikto"])),
        "issues": by_host,
    }
    if cmd is not None:
        issue["_cmd"] = cmd
    if not issue["taxonomy"]:
        del issue["taxonomy"]
    return [issue]


def main():
    input_data = sys.stdin.read()

    # Trivial case: the file is empty.
    if not input_data.strip():
        json.dump([], sys.stdout)
        return

    reset_osvdb_stats()
    stripped = input_data.lstrip()

    # CSV: the first line is the Nikto version banner.
    if re.match(r'"Nikto - v.*"', stripped):
        findings = read_csv(input_data)
    # JSON: 2.6.0 array of host objects, or 2.5.0 concatenated-fragment.
    elif stripped[:1] in ("[", "{"):
        findings = read_json(input_data)
    # XML reader arrives in Tier 4; the live wrapper emits CSV.
    elif stripped.startswith("<?xml") or stripped.startswith("<niktoscan"):
        sys.stderr.write(
            "Nikto XML parsing is not supported yet (Tier 4); only CSV and JSON are handled.\n"
        )
        json.dump([], sys.stdout)
        return
    else:
        sys.stderr.write(
            "Invalid file type, are you sure this was generated by nikto.pl?\n"
        )
        json.dump([], sys.stdout)
        return

    output = build_issues(findings)
    osvdb_hitrate_warning()
    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
