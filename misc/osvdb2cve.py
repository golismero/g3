#!/usr/bin/env python3

# Script to download the OSVDB to CVE map from MITRE and serialize it in JSON format.

from os import unlink
from os.path import dirname, join, realpath
from json import dump
from bs4 import BeautifulSoup           # pip install beautifulsoup4
from urllib.request import urlopen

html_file = join(dirname(realpath(__file__)), "source-OSVDB.html")
try:
    with open(html_file, "r") as fd:
        html = fd.read()
    assert html
except Exception:
    url = "https://cve.mitre.org/data/refs/refmap/source-OSVDB.html"
    r = urlopen(url)
    try:
        html = r.read()
        assert html
    finally:
        r.close()
    try:
        with open(html_file, "w") as fd:
            fd.write(html.decode("utf8"))
    except:
        unlink(html_file)
        raise

soup = BeautifulSoup(html, "html.parser")
o2c_map = {}
for tag in soup.find_all():
    name = tag.name
    value = tag.text.strip()
    if name == "td" and value.startswith("OSVDB:"):
        osvdb = value
    elif name == "a" and value.startswith("CVE-"):
        cve = [ x.strip() for x in value.split(" ") ]
        if osvdb in o2c_map:
            o2c_map[osvdb].extend(cve)
        else:
            o2c_map[osvdb] = cve

with open("osvdb2cve.json", "w") as fd:
    dump(o2c_map, fd)
