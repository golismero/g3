#!/usr/bin/env python3

import json
import os
import os.path
import sys
import vulners      # pip3 install vulners

api_key_var = "VULNERS_API_KEY"
api_key = os.getenv(api_key_var)
if not api_key:
    sys.stderr.write("Missing environment variable %s\n" % api_key_var)
    exit(1)
server_url_var = "VULNERS_SERVER_URL"
server_url = os.getenv(server_url_var)
if server_url:
    vulners_api = vulners.VulnersApi(api_key=api_key, server_url=server_url)
else:
    vulners_api = vulners.VulnersApi(api_key=api_key)

if not os.path.exists("vulners-rules.json"):
    rules = vulners_api.get_web_application_rules()
    with open("vulners-rules.json", "w") as fd:
        json.dump(rules, fd)

if not os.path.exists("vulners-cve.json"):
    all_cve = vulners_api.get_collection("cve")
    with open("vulners-cve.json", "w") as fd:
        json.dump(all_cve, fd)
