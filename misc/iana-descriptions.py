#!/usr/bin/env python3

# Script to download SSL/TLS enabled ports from the IANA database.

from csv import reader
from io import StringIO
from os import unlink
from os.path import dirname, join, realpath
from json import dump
from urllib.request import urlopen, Request

data_dir = dirname(realpath(__file__))
csv_file = join(data_dir, "service-names-port-numbers.csv")
try:
    with open(csv_file, "r") as fd:
        raw = fd.read()
    assert raw
except Exception:
    url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
    headers={
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
    }
    print("Downloading: " + url)
    req = Request(url, headers=headers)
    resp = urlopen(req)
    try:
        raw = resp.read().decode("utf8")
        assert raw
    finally:
        resp.close()
    try:
        with open(csv_file, "w") as fd:
            fd.write(raw)
    except:
        unlink(csv_file)
        raise

r = reader(StringIO(raw))
next(r) # Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Unauthorized Use Reported,Assignment Notes
descriptions = []
for row in r:
    entry = {}
    if row[0]: entry["name"] = row[0]
    if row[1]: entry["port"] = row[1]
    if row[2]: entry["protocol"] = row[2]
    if row[3]: entry["description"] = row[3]
    if entry:
        descriptions.append(entry)
with open("iana-descriptions.json", "w") as fd:
    dump(descriptions, fd)
