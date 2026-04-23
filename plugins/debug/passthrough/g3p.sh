#!/bin/sh
# Debug/stress-test plugin: read a G3Data JSON object from stdin and emit it
# as a single-item list on stdout to satisfy the plugin output contract.
printf '[%s]' "$(cat)"
