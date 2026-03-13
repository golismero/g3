#!/usr/bin/env python3

import os
import os.path
import sys

mods = set()
for root, dirs, files in os.walk("src"):
    for name in files:
        filename = os.path.join(root, name)
        if name == "go.sum":
            with open(filename, "r") as fd:
                for line in fd:
                    line = line.strip()
                    if not line:
                        continue
                    module, version = line.split(" ")[:2]
                    if version.endswith("/go.mod"):
                        continue
                    mods.add("%s@%s" % (module, version))
        elif name == "go.mod":
            with open(filename, "r") as fd:
                start_collecting = False
                for line in fd:
                    line = line.strip()
                    if not start_collecting and line == "require (":
                        start_collecting = True
                    elif start_collecting and line == ")":
                        start_collecting = False
                    elif start_collecting and not line.startswith("golismero.com/"):
                        module, version = line.split(" ")[:2]
                        mods.add("%s@%s" % (module, version))
with open(sys.argv[1], "w") as fd:
    fd.write("\n".join(sorted(mods)))
