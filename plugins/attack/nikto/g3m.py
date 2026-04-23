#!/usr/local/bin/python3

import sys
import json

def main():

    # We must have a Golismero object array in stdin. Parse it.
    input_array = json.load(sys.stdin)

    # Trivial case, we were given an empty array. This should not happen, realistically.
    if not input_array:
        sys.stderr.write("Warning, nikto issue merger received an empty list of issues!\n")
        json.dump([], sys.stdout)
        return

    # Trivial case, we were given a single object. This should not happen, realistically.
    if len(input_array) == 1:
        sys.stderr.write("Warning, nikto issue merger received a single issue to be merged!\n")
        json.dump(input_array, sys.stdout)
        return

    # Some basic sanity checks.
    for issue in input_array:
        assert "_type" in issue and issue["_type"] == "issue", "Wrong data type for object: " + json.dumps(issue)
        for propname in ("_cmd", "_fp", "_start", "_end", "severity", "affects", "taxonomy", "references", "issues"):
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
            "issues": {},
        }

    # Collect all of the properties we want to merge.
    ids = []
    for issue in input_array:
        if "_id" in issue:
            ids.append(issue["_id"])
        if issue["severity"] > merged_issue["severity"]:
            merged_issue["severity"] = issue["severity"]
        if merged_issue["_start"] == 0 or issue["_start"] < merged_issue["_start"]:
            merged_issue["_start"] = issue["_start"]
        if merged_issue["_end"] == 0 or issue["_end"] > merged_issue["_end"]:
            merged_issue["_end"] = issue["_end"]
        merged_issue["_fp"].extend(issue["_fp"])
        merged_issue["affects"].extend(issue["affects"])
        merged_issue["taxonomy"].extend(issue["taxonomy"])
        merged_issue["references"].extend(issue["references"])
        for key, value in issue["issues"].items():
            if key not in merged_issue["issues"]:
                merged_issue["issues"][key] = value
            else:
                array = merged_issue["issues"][key]
                for item in value:
                    if item not in array:
                        array.append(item)

    # Remove duplicates and sort.
    if ids:
        merged_issue["_cmd"] = "g3 merge " + " ".join(sorted(set(ids)))
    else:
        merged_issue["_cmd"] = "g3 merge"
    merged_issue["_fp"] = sorted(set(merged_issue["_fp"]))
    merged_issue["affects"] = sorted(set(merged_issue["affects"]))
    merged_issue["taxonomy"] = sorted(set(merged_issue["taxonomy"]))
    merged_issue["references"] = sorted(set(merged_issue["references"]))

    # Write the output array to stdout.
    json.dump([merged_issue], sys.stdout)

if __name__ == "__main__":
    main()
