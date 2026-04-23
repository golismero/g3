#!/bin/sh
# Debug/stress-test plugin: always fails, regardless of input.
echo "error: intentional failure" 1>&2
exit 1
