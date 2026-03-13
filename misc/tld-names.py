#!/usr/bin/env python3

# Script to download the TLD database from publicsuffix.org.
# We dump the results in a simplified format that misses some of the subtleties but is good enough for us.

import os
import json
import os.path
import urllib.request

try:
    import cPickle as pickle
except ImportError:
    import pickle

tld_filename = "effective_tld_names.dat"
tld_url = "https://publicsuffix.org/list/" + tld_filename
txt_filename = "tld-names.txt"
pickle_filename = "tld-names.pickle"
json_filename = "tld-names.json"

if not os.path.exists(tld_filename):
    print("Downloading " + tld_url)
    r = urllib.request.urlopen(tld_url)
    try:
        data = r.read()
        assert data
    finally:
        r.close()
    with open(tld_filename, "w") as fd:
        try:
            fd.write(data.decode("utf8"))
        except:
            os.unlink(tld_filename)
            raise

if not os.path.exists(txt_filename) or not os.path.exists(pickle_filename) or not os.path.exists(json_filename):

    print("Parsing " + tld_filename)
    tld_names = set()
    with open(tld_filename, "r") as fd:
        for line in fd:
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("*") or line.startswith("!"):
                continue
            tld_names.add("." + line)
    sorted_tld_names = sorted(tld_names)

    if not os.path.exists(txt_filename):
        print("Saving to: " + txt_filename)
        with open(txt_filename, "w") as fd:
            try:
                for line in sorted_tld_names:
                    fd.write(line + "\n")
            except Exception:
                fd.close()
                os.unlink(txt_filename)
                raise

    if not os.path.exists(pickle_filename):
        print("Saving to: " + pickle_filename)
        with open(pickle_filename, "wb") as fd:
            try:
                pickle.dump(tld_names, fd, protocol=pickle.HIGHEST_PROTOCOL)
            except Exception:
                fd.close()
                os.unlink(pickle_filename)
                raise

    if not os.path.exists(json_filename):
        print("Saving to: " + json_filename)
        with open(json_filename, "w") as fd:
            try:
                json.dump(sorted_tld_names, fd, indent=None, separators=(",", ":"))
            except Exception:
                fd.close()
                os.unlink(json_filename)
                raise
