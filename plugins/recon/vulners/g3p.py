#!/usr/local/bin/python3

import os
import sys
import json
import sqlite3
import traceback

import redis
import vulners

# Check these prefixes for taxonomies we can understand.
known_tag_prefixes = (
    "CVE-",
    "CWE-",
    "CAPEC-",
    "CNVD-",
    "JVNDB-",
    "JVN",
    "BDU:",
    "USN-",
    "RHSA-",
    "DSA-",
    "KB",
    "MS",
    "MFSA",
    "EDB-ID:",
    "1337DAY-ID-",
    "SECURITYVULNS:DOC:",
    "RFC ",
)

def main():

    # We must have a Golismero object in stdin. Parse it.
    input_data = json.load(sys.stdin)

    # Initialize the Vulners API.
    vulners_api = init_vulners()

    # If the object is a host, parse it as a host.
    # TODO if the object is an issue, add extra references
    # Any other object type will trigger an error.
    datatype = input_data.get("_type", "unknown")
    if datatype == "host":
        issue = report_for_host(vulners_api, input_data)
    else:
        raise Exception("Cannot process object of type: " + datatype)

    # Send the issue to stdout, if we have it.
    if issue:
        json.dump([issue], sys.stdout)
    else:
        json.dump([], sys.stdout)

# Initialize the Vulners API.
def init_vulners():
    api_key_var = "VULNERS_API_KEY"
    api_key = os.getenv(api_key_var)
    if not api_key:
        sys.stderr.write("Missing environment variable %s\n" % api_key_var)
        json.dump([], sys.stdout)
        exit(1)
    proxy_host_var = "VULNERS_PROXY_HOST"
    proxy_host = os.getenv(proxy_host_var)
    if proxy_host:
        proxy_port_var = "VULNERS_PROXY_PORT"
        proxy_port = os.getenv(proxy_port_var)
        if not proxy_port:
            proxy_port = 8000
        else:
            proxy_port = int(proxy_port)
        server_url = "http://%s:%d" % (proxy_host, proxy_port)
        sys.stderr.write("Using proxy: %s\n" % server_url)
        vulners_api = vulners.VulnersApi(api_key=api_key, server_url=server_url)
    else:
        vulners_api = vulners.VulnersApi(api_key=api_key)
    return vulners_api

# Report known vulnerabilities for a host based on its CPE.
def report_for_host(vulners_api, input_data):

    # Get the IP address.
    ipv4 = input_data.get("ipv4", None)
    ipv6 = input_data.get("ipv6", None)
    if not ipv4 and not ipv6:
        sys.stderr.write("Error: received host without IPv4 or IPv6!\n")
        json.dump([], sys.stdout)
        exit(1)
    host = (ipv4 + " / " + ipv6) if ipv4 and ipv6 else (ipv4 if ipv4 else ipv6)

    # This list will contain all the CPE strings we will query.
    targets = []

    # I've commented out the OS matches parsing because the results thrown by
    # nmap are way too generic to be of any use for this particular plugin.
    # Also, Vulners seems to struggle with queries like these.
    """
    # Hosts have CPE strings in the OS matches.
    # We're only going to test for the most likely match and ignore the rest.
    # Also ignore this host if the OS match has less than 50% accuracy.
    best_match = None
    accuracy = 0
    for match in input_data.get("os_matches", []):
        if match["accuracy"] > accuracy:
            best_match = match
            accuracy = match["accuracy"]
    if best_match is None or accuracy < 50:
        sys.stderr.write("Skipped host %s, no OS matches with more than 50%% accuracy.\n" % (ipv4 if ipv4 else ipv6))
        return
    for cpe in best_match.get("cpe", []):
        targets.append( (host, cpe) )
    """

    # Hosts have CPE strings in the services.
    # We don't have accuracy information here so let's just grab all of them.
    for service in input_data.get("services", []):
        if "cpe" in service:
            for cpe in service["cpe"]:
                if "protocol" in service:
                    targets.append( ("%s:%d (%s)" % (host, service["port"], service["protocol"]), cpe) )
                else:
                    targets.append( ("%s:%d" % (host, service["port"]), cpe) )

    # If we didn't find any CPE strings, complain about it.
    if not targets:
        sys.stderr.write("No CPE strings found!\n")
        return

    # This will be the G3 issue object.
    issue = {
        "severity": 0,
        "affects": [],
        "taxonomy": [],
        "references": [],
        "software": {},         # cpe -> software
        "vulnerabilities": {},  # cpe -> [cve, href, severity, description]
        "exploits": {},         # cpe -> [exploit, href]
    }

    # Get the vulnerabilities for each detected CPE.
    for affects, cpe in targets:

        # If the CPE is not specific enough to get info on it (ie does not have version info)
        # the Vulners API will raise an exception. We don't want to crash the plugin if that
        # happens so we catch it here and just skip the CPE value.
        try:
            sys.stderr.write("Querying Vulners API for CPE: %s\n" % cpe)
            cpe_results = vulners_api.get_cpe_vulnerabilities(cpe)

            # cpe_results = json.load(open("mock.json", "r"))             # XXX DEBUG

            # x = json.load(open("mock2.json", "r"))                      # XXX DEBUG
            # cpe_results = {"exploit": []}                               # XXX DEBUG
            # for k,v in x.items():                                       # XXX DEBUG
            #     cpe_results["exploit"].extend(v)                        # XXX DEBUG

            if not cpe_results:
                sys.stderr.write("No results for CPE: %s\n" % cpe)
                continue
        except Exception as e:
            sys.stderr.write("Skipping CPE %s - %s\n" % (cpe, e))
            continue
        sys.stderr.write("Parsing %d results for CPE: %s\n" % (len(cpe_results), cpe))

        # Parse the data from the National Vulnerability Database.
        for item in cpe_results.get("NVD", []):
            tag = item.get("id")
            if tag:
                issue["taxonomy"].append(tag)

            # Collect CWE tags.
            cwe = item.get("cwe", [])
            cwe = [x for x in cwe if x != "NVD-CWE-noinfo"]
            issue["taxonomy"].extend(cwe)

            # Collect the CVE description.
            parsed = {"cve": tag}
            description = item.get("description")
            if description:
                parsed["description"] = description

            # Collect the reference link.
            href = item.get("href")
            if href:
                parsed["href"] = href

            # Collect CVSS vectors.
            # Use the highest score to set the severity of the issue.
            severity = 0    # LOW
            if "cvss" in item:
                vector = item["cvss"].get("vector")
                if vector:
                    parsed["cvss"] = vector
                score = item["cvss"].get("score", None)
                if score is not None:
                    if score < 4.0:
                        severity = 0    # LOW
                    elif score < 7.0:
                        severity = 1    # MEDIUM
                    elif score < 9.0:
                        severity = 2    # HIGH
                    else:
                        severity = 3    # CRITICAL
                    if severity > issue["severity"]:
                        issue["severity"] = severity
            parsed["severity"] = severity

            # Add the CVE data to the issue.
            if cpe not in issue["vulnerabilities"]:
                issue["vulnerabilities"][cpe] = []
            if parsed not in issue["vulnerabilities"][cpe]:
                issue["vulnerabilities"][cpe].append(parsed)
                issue["affects"].append(affects)

        # Get any publicly available exploits.
        for item in cpe_results.get("exploit", []):

            # Get the title and link to the exploit.
            # If there is no link, then the exploit is not public, so ignore it.
            title = item.get("title")
            href = item.get("href")
            sourceHref = item.get("sourceHref")
            if not href and not sourceHref:
                continue
            if not sourceHref:
                sourceHref = href
            if not href:
                href = sourceHref
            if not title:
                title = sourceHref
            issue["references"].append(href)

            # Add the exploit data to the issue.
            exploit = {"exploit": title, "href": sourceHref}
            if cpe not in issue["exploits"]:
                issue["exploits"][cpe] = []
            if exploit not in issue["exploits"][cpe]:
                issue["exploits"][cpe].append(exploit)
                issue["affects"].append(affects)

        # Try to parse the rest of the data as best we can.
        for key in cpe_results.keys():
            if key in ("NVD", "exploit", "info", "blog", "bugbounty"):
                continue
            for item in cpe_results[key]:
                tag = item.get("id")
                if tag:
                    for prefix in known_tag_prefixes:
                        if tag.startswith(prefix):
                            issue["taxonomy"].append(tag)
                            break

    # Add extra info from the CPE database.
    # TODO is the CPE is not found maybe check the nmap output for more details
    for cpe in issue["vulnerabilities"].keys():
        title, refs = get_cpe_info(cpe)
        if title:
            issue["software"][cpe] = title
        if refs:
            issue["references"].extend(refs)
    for cpe in issue["exploits"].keys():
        title, refs = get_cpe_info(cpe)
        if title:
            issue["software"][cpe] = title
        if refs:
            issue["references"].extend(refs)

    # Clean up duplicated elements in the issue.
    issue["affects"] = sorted(set(issue["affects"]))
    issue["taxonomy"] = sorted(set(issue["taxonomy"]))
    issue["references"] = sorted(set(issue["references"]))

    # Clean up missing elements in the issue.
    for cpe in list(issue["vulnerabilities"].keys()):
        if not issue["vulnerabilities"][cpe]:
            del issue["vulnerabilities"][cpe]
    if not issue["software"]:
        del issue["software"]
    if not issue["vulnerabilities"]:
        del issue["vulnerabilities"]
    if not issue["exploits"]:
        del issue["exploits"]

    # Return the issue object only if we have any known vulnerabilities or public exploits.
    if "vulnerabilities" in issue or "exploits" in issue:
        return issue
    sys.stderr.write("No issues to report.\n")

# Get the human friendly name and reference links for a CPE.
_cpe_query_cache = {}
def get_cpe_info(cpe):
    if cpe in _cpe_query_cache:
        return _cpe_query_cache[cpe]
    try:
        sys.stderr.write("Querying CPE database for: %s\n" % cpe)
        con = sqlite3.connect("/app/cpe.db")
        cur = con.cursor()
        res = cur.execute("SELECT title FROM titles WHERE cpe = ? LIMIT 1", [cpe])
        rows = res.fetchone()
        if rows:
            title = rows[0]
        else:
            title = None
        res = cur.execute("SELECT href FROM refs WHERE cpe = ?", [cpe])
        refs = res.fetchall()
        cur.close()
        con.close()
        result = (title, [x[0] for x in refs])
        _cpe_query_cache[cpe] = result
        return result
    except Exception:
        traceback.print_exc()
        return (None, [])

if __name__ == "__main__":
    main()
