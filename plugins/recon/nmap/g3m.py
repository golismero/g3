#!/usr/local/bin/python3

import sys
import json

def main():

    # We must have a Golismero object array in stdin. Parse it.
    input_array = json.load(sys.stdin)

    # Trivial case, we were given an empty array. This should not happen, realistically.
    if not input_array:
        sys.stderr.write("Warning, issue merger received an empty list of issues!\n")
        json.dump([], sys.stdout)
        return

    # Trivial case, we were given a single object. This should not happen, realistically.
    if len(input_array) == 1:
        sys.stderr.write("Warning, issue merger received a single issue to be merged!\n")
        json.dump(input_array, sys.stdout)
        return

    # Some basic sanity checks.
    for issue in input_array:
        assert "_type" in issue and issue["_type"] == "issue", "Wrong data type for object: " + json.dumps(issue)
        for propname in ("_cmd", "_fp", "_start", "_end", "severity", "affects", "taxonomy", "references", "plaintext_ports"):
            assert propname in issue, "Missing %s in data object: %s" % (propname, json.dumps(issue))

    # Since this plugin can only generate a single type of issue, we will output a single object.
    merged_issue = {
            "_type": "issue",
            "_fp": [],
            "_start": 0,
            "_end": 0,
            "severity": 0,
            "affects": [],
            "taxonomy": [],
            "references": [],
            "plaintext_ports": [],
        }

    # Collect all of the properties we want to merge.
    ids = []
    pp = []
    for issue in input_array:
        if "_id" in issue:
            ids.append(issue["_id"])
        if issue["severity"] > merged_issue["severity"]:
            merged_issue["severity"] = issue["severity"]
        if merged_issue["_start"] == 0 or issue["_start"] < merged_issue["_start"]:
            merged_issue["_start"] = issue["_start"]
        if merged_issue["_end"] == 0 or issue["_end"] > merged_issue["_end"]:
            merged_issue["_end"] = issue["_end"]
        for x in issue["plaintext_ports"]:
            pp.append((x["address"], x["port"], x["service"]))
        merged_issue["_fp"].extend(issue["_fp"])
        merged_issue["affects"].extend(issue["affects"])
        merged_issue["taxonomy"].extend(issue["taxonomy"])
        merged_issue["references"].extend(issue["references"])

    # Remove duplicates and sort.
    if ids:
        merged_issue["_cmd"] = "g3 merge " + " ".join(sorted(set(ids)))
    else:
        merged_issue["_cmd"] = "g3 merge"
    merged_issue["_fp"] = sorted(set(merged_issue["_fp"]))
    merged_issue["affects"] = sorted(set(merged_issue["affects"]))
    merged_issue["taxonomy"] = sorted(set(merged_issue["taxonomy"]))
    merged_issue["references"] = sorted(set(merged_issue["references"]))
    pp = sorted(set(pp))
    for x in pp:
        merged_issue["plaintext_ports"].append({
            "address": x[0],
            "port": x[1],
            "service": x[2],
        })

    # Check if the resulting issue is identical to one of the issues in the input array.
    # This will happen if the merger was run more than once.
    # By outputting the same object we prevent it being added twice to the database.
    for issue in input_array:
        found = True
        for key in ("severity", "affects", "taxonomy", "references", "plaintext_ports"):
            if key not in issue:
                found = False
                break
            if key not in merged_issue:
                found = False
                break
            if issue[key] != merged_issue[key]:
                found = False
                break
        if found:
            merged_issue = issue

    # Write the output array to stdout.
    json.dump([merged_issue], sys.stdout)

if __name__ == "__main__":
    main()
