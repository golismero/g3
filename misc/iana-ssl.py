#!/usr/bin/env python3

# Script to download SSL/TLS enabled ports from the IANA database.

from time import sleep
from os import unlink
from os.path import dirname, join, realpath
from json import dump
from bs4 import BeautifulSoup
from urllib.request import urlopen

data_dir = dirname(realpath(__file__))
services = {}
descriptions = {}
for keyword in ("tls", "ssl", "https", "ssh"):
    page = 0
    done = False
    while not done:
        page += 1
        html_file = join(data_dir, "iana-%s-%d.html" % (keyword, page))
        try:
            with open(html_file, "r") as fd:
                html = fd.read()
            assert html
        except Exception:
            url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=%s&page=%d" % (keyword, page)
            print("Downloading: " + url)
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
            sleep(1)
        soup = BeautifulSoup(html, "html.parser")
        done = True
        for row in soup.find_all("tr"):
            col = row.findChildren("td")
            if col and len(col) == 12:
                name = col[0].text
                port = col[1].text
                proto = col[2].text
                desc = col[3].text
                if not name or not port or not proto:
                    continue
                port_proto = "%s/%s" % (port, proto)
                if name not in services:
                    services[name] = set()
                services[name].add(port_proto)
                if desc:
                    descriptions[name] = desc
                done = False
for name in list(services.keys()):
    services[name] = sorted(services[name])
print(sorted(services.keys()))
with open("tls_services.json", "w") as fd:
    dump(services, fd)
