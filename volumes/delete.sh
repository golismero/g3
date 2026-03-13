#!/bin/bash
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
set -x
rm -fr ${SCRIPT_DIR}/mariadb/data
rm -fr ${SCRIPT_DIR}/mongo
rm -fr ${SCRIPT_DIR}/mosquitto/data
rm -fr ${SCRIPT_DIR}/mosquitto/log
rm -fr ${SCRIPT_DIR}/redis
rm -fr ${SCRIPT_DIR}/tmp/*/
rm -fr ${SCRIPT_DIR}/vulners-proxy