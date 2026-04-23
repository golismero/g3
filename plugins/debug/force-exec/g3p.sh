#!/bin/sh
# Debug/stress-test plugin: read a G3Data JSON object from stdin and emit it
# as a single-item list on stdout. Same behaviour as passthrough; the twist
# is in the .g3p fingerprint template (fresh UUID per dispatch).
printf '[%s]' "$(cat)"
