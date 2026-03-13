#!/usr/bin/python3

import csv
import sys
import json
import traceback

# When importing, we get the data from stdin.
# When scanning, we get the path to the file with the data.
if len(sys.argv) == 1:
    raw_input = sys.stdin.read()
else:
    with open(sys.argv[1], "r") as fd:
        raw_input = fd.read()

# If we got no data, just ignore it.
# This should not happen.
if not raw_input:
    sys.stdout.write("[]")
    exit(0)

# This dictionary collects the testssl.sh data in a unified format.
items = {}

# Parse an output generated with the -oJ switch.
if raw_input[0] == "{":
    input = json.loads(raw_input)
    cmd = input["Invocation"]
    start = int(input["startTime"])
    try:
        end = start + int(input["scanTime"])
    except Exception:
        end = start
    for result in input["scanResult"]:
        try:
            if "id" in result and result["id"] == "scanProblem":
                break
            ip = result["targetHost"] + "/" + result["ip"]
            port = result["port"]
            key = result["ip"] + ":" + result["port"]
            for section in ("pretest", "protocols", "grease", "ciphers", "serverPreferences", "fs", "serverDefaults", "vulnerabilities", "rating"):
                for item in result[section]:
                    item["ip"] = ip
                    item["port"] = port
                    if key not in items:
                        items[key] = []
                    items[key].append(item)
        except Exception:
            traceback.print_exc()

# Parse an output generated with the -oj switch.
elif raw_input[0] == "[":
    cmd = None
    start = None
    end = None
    input = json.loads(raw_input)
    for item in input:
        try:
            ip = item["ip"].split("/")[1]
            port = item["port"]
            key = item["ip"] + ":" + item["port"]
            if key not in items:
                items[key] = []
            items[key].append(item)
        except Exception:
            traceback.print_exc()

# Parse an output generated with the -oC switch.
elif raw_input[0] == "\"":
    cmd = None
    start = None
    end = None
    reader = csv.reader(raw_input.split("\n")[1:])
    for row in reader:
        if not row: continue
        row = list(row)
        if len(row) < 7:
            row.extend( [""] * (7 - len(row)) )
        id, ip, port, severity, finding, cve, cwe = row[:7]
        item = {
            "id": id,
            "ip": ip,
            "port": port,
            "severity": severity,
            "finding": finding,
            "cve": cve,
            "cwe": cwe,
        }
        key = item["ip"] + ":" + item["port"]
        if key not in items:
            items[key] = []
        items[key].append(item)

# We could not recognize the file format.
else:
    raise Exception("Unsupported output type")

# Parse the client simulations file.
# If we fail to do this, simply ignore the client simulations in the resulting output.
# We will output a warning to the logs, however.
try:
    client_simulation_names = {}
    with open("/home/testssl/etc/client-simulation.txt", "r") as fd:
        for line in fd:
            line = line.strip()
            if line.startswith("names+="):
                value = line[9:-2]
            elif line.startswith("short+="):
                key = line[9:-2]
                client_simulation_names[key] = value
except Exception:
    client_simulation_names = None
    traceback.print_exc()

# Additional reference links per vulnerability.
additional_references = {
    "GREASE": ["https://www.ietf.org/archive/id/draft-ietf-tls-grease-01.txt"],
    "SSLv2": ["https://datatracker.ietf.org/doc/html/rfc6176"],
    "SSLv3": ["https://datatracker.ietf.org/doc/html/rfc7568"],
    "TLS1": ["https://datatracker.ietf.org/doc/html/rfc8996"],
    "TLS1_1": ["https://datatracker.ietf.org/doc/html/rfc8996"],
    "HTST": ["https://datatracker.ietf.org/doc/html/rfc6797"],
    "OSCP_stapling": ["https://www.rfc-editor.org/rfc/rfc6066#section-8"],
    "DNS_CAArecord": ["https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization",
                      "https://docs.digicert.com/en/certcentral/manage-certificates/dns-caa-resource-record-check.html"],
    "cipherlist_3DES_IDEA": ["https://en.wikipedia.org/wiki/Triple_DES"],
    "cipherlist_EXPORT": ["https://www.virtuesecurity.com/kb/export-ciphers-enabled"],
    "cipher_order": ["https://crashtest-security.com/configure-ssl-cipher-order/"],
    "FS": ["https://en.wikipedia.org/wiki/Forward_secrecy"],
    "TLS_session_ticket": ["https://en.wikipedia.org/wiki/Forward_secrecy"],
    "pwnedkeys": ["https://pwnedkeys.com"],
    "heartbleed": ["https://heartbleed.com/"],
    "ticketbleed": ["https://filippo.io/Ticketbleed/"],
    "ROBOT": ["https://robotattack.org/"],
    "secure_client_renego": ["https://myakamai.force.com/customers/s/article/How-to-test-Client-TLS-Renegotiation",
                             "https://www.kali.org/tools/thc-ssl-dos/"],
    "CRIME_TLS": ["https://en.wikipedia.org/wiki/CRIME"],
    "BEAST": ["https://www.acunetix.com/blog/web-security-zone/what-is-beast-attack/",
              "https://web.archive.org/web/20140603102506/https://bug665814.bugzilla.mozilla.org/attachment.cgi?id=540839"],
    "POODLE": ["https://www.acunetix.com/blog/web-security-zone/what-is-poodle-attack/"],
    "SWEET32": ["https://sweet32.info/"],
    "FREAK": ["https://www.cisa.gov/news-events/alerts/2015/03/06/freak-ssltls-vulnerability"],
    "DROWN": ["https://drownattack.com/drown-attack-paper.pdf",
              "https://censys.io/ipv4?q=5EF2F214260AB8F58E55EEA42E4AC04B0F171807D8D1185FDDD67470E9AB6096"],
    "LOGJAM": ["https://weakdh.org/"],
    "LUCKY13": ["https://web.archive.org/web/20200324101422/http://www.isg.rhul.ac.uk/tls/Lucky13.html",
                "https://en.wikipedia.org/wiki/Lucky_Thirteen_attack"],
    "RC4": ["https://datatracker.ietf.org/doc/html/rfc7465",
            "https://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html"],
}

# These lists will be populated when parsing below.
affects = []
references = ["https://ssl-config.mozilla.org"]
taxonomy = []
hosts = []

# The final severity will be the highest one found.
severity = 0

# Severity rating names in testssl. They happen to be the same ones we use. ;)
ratings = ("LOW", "MEDIUM", "HIGH", "CRITICAL")     # must be only low and above

# This is the G3 object containing all vulnerabilities for this host.
# Since testssl.sh detects a ton of vulnerabilities, but they're all intrinsically connected to SSL,
# it makes more sense to report them all as a single issue in G3 and put all the details together.
issue = {}

# Parse the testssl.sh results and generate a G3 issue.
# The same issue will try to merge all of the affected hosts.
for key, results in items.items():
    affects.append(key)

    # Parse the testssl.sh data.
    # We're going to treat the vulnerable ciphers and grade rating as special cases.
    # Everything else gets treated in a pretty generic manner.
    # A lot of the magic here happens when reporting using the i18n templates.
    bad_ciphers = []
    grade = None
    grade_cap = []
    client_sims = []
    rating_spec = None
    problems = {}
    for item in results:

        # We'll use the testssl.sh ID as additional properties we can look up later from the templates.
        # This should work nicely since we know for a fact they cannot collide.
        id = item["id"]

        # Use the highest rating as the overall rating of the issue.
        # Evaluating this here at the top ensures we always pick up
        # all of the severity values, even if we don't have a specific
        # paragraph in the issue details later on.
        if item["severity"] in ratings:
            sev = ratings.index(item["severity"])
            if sev > severity:
                severity = sev

        # Collect vulnerable ciphers.
        if id.startswith("cipher-"):
            if item["severity"] in ratings:
                txt = item["finding"]
                if txt.startswith("TLSv1 "):
                    txt = "TLSv1.0 " + txt[6:]
                elif txt.startswith("SSLv2 "):
                    txt = "SSLv2  " + txt[5:]
                elif txt.startswith("SSLv3 "):
                    txt = "SSLv3  " + txt[5:]
                bad_ciphers.append(txt)

        # Collect the grade rating data.
        elif id == "overall_grade":
            grade = item["finding"]
        elif id.startswith("grade_cap_reason_"):
            grade_cap.append(item["finding"])
        elif id == "rating_spec":
            rating_spec = item["finding"]

        # Collect the client simulations data.
        elif id.startswith("clientsimulation-"):
            csim_name = id[17:]
            if client_simulation_names is not None:
                csim_name = client_simulation_names.get(csim_name, csim_name)
            txt = csim_name + ": " + item["finding"]
            client_sims.append(txt)

        # For every other vulnerability we just copy the data we need.
        # The assumption here is for every testssl.sh ID we have a matching i18n template.
        # Possibly some of this data won't be used by the templates, but actually checking
        # is a bit more work than I feel is needed right now. Definitely doable though.
        elif item["severity"] in ratings:

            # Skip some redundant items.
            if id.startswith("BEAST_") or id.startswith("cipher_order-"):
                continue

            # Use the highest rating as the overall rating of the issue.
            sev = ratings.index(item["severity"])
            if sev > severity:
                severity = sev

            # Some IDs will contain suffixes if, for example, there is more than one certificate.
            # Since parsing that is too complicated we will just append everything to a single ID.
            if " " in id:
                tag = id.split(" ", 1)[0]
            else:
                tag = id

            # Add the findings as additional properties the paragraph template can access.
            if "finding" in item and item["finding"]:
                if tag in problems:
                    problems[tag] += " " + item["finding"]
                else:
                    problems[tag] = item["finding"]

            # Add CVE and CWE IDs.
            cve = item.get("cve", "")
            if cve:
                taxonomy.extend(cve.split(" "))
            cwe = item.get("cwe", "")
            if cwe:
                taxonomy.extend(cwe.split(" "))

            # Add any additional reference links if we have any for this vulnerability.
            if id in additional_references:
                references.extend(additional_references[id])

            # Some vulnerability specific details follow.
            if id == "winshock":
                taxonomy.append("MS14-066")

    # If the issue is empty, this means testssl.sh did not find anything to report on this host.
    # Usually this happens when there was an error during the scan. ;)
    if not (bad_ciphers or problems or client_sims or grade):
        continue

    # Create the host details object.
    host = {
        "host": key,
    }
    if bad_ciphers:
        host["bad_ciphers"] = bad_ciphers
    if problems:
        host["problems"] = problems
    if client_sims:
        host["clientsimulations"] = client_sims
    if grade:
        host["grade"] = grade
        host["grade_cap"] = grade_cap
        references.append("https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide")
    if rating_spec:
        host["rating_spec"] = rating_spec

    # Add the host to the list.
    hosts.append(host)

output_data = []

# If we have vulnerable hosts...
if hosts:

    # Sort the CVE, CWE and reference links alphabetically and remove duplicates.
    taxonomy = sorted(set(taxonomy))
    references = sorted(set(references))

    # Set the basic issue properties.
    issue["severity"] = severity
    if cmd: issue["_cmd"] = cmd
    if start: issue["_start"] = start
    if end: issue["_end"] = end

    # Add the collected paragraphs to the issue.
    if affects: issue["affects"] = affects
    if taxonomy: issue["taxonomy"] = taxonomy
    if references: issue["references"] = references

    # Add the hosts to the issue.
    if hosts: issue["hosts"] = hosts

    # Output the issue.
    output_data.append(issue)

# Send the G3 object array back to the caller.
json.dump(output_data, sys.stdout)
