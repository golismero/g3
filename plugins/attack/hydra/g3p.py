#!/usr/bin/env python3

import os
import sys
import json
import shlex
import socket
import tempfile
import subprocess

# Supported protocols. There are special cases for http, ldap, smtp.
SUPPORTED_PROTOCOLS = "adam6500 asterisk cisco cisco-enable cvs firebird ftp fpts icq imap imaps irc memcached mongodb mssql mysql nntp oracle-listener oracle-sid pcanywhere pcnfs pop3 pop3s postgres radmin2 rdp redis rexec rlogin rpcap rsh rtsp s7-300 sip smb snmp socks5 ssh svn teamspeak telnet telnets vmauthd vnc xmpp".split(" ")

# Base arguments for hydra.
assert "HYDRA_LOGIN_FILE" in os.environ, "Missing environment variable HYDRA_LOGIN_FILE"
assert "HYDRA_PASSWORD_FILE" in os.environ, "Missing environment variable HYDRA_PASSWORD_FILE"
base_args = ["hydra", "-L", os.environ["HYDRA_LOGIN_FILE"], "-P", os.environ["HYDRA_PASSWORD_FILE"]]
if "HYDRA_MAX_TASKS" in os.environ:
    base_args.append("-t")
    base_args.append(os.environ["HYDRA_MAX_TASKS"])

# Here we will have the output data.
output_data = []

# Get the G3 data object.
input_data = json.load(sys.stdin)

# Process the IP addresses.
# We should be getting either an IPv4 or an IPv6 address, but not both.
# If g3 ever starts mixing them up on the same object, this logic needs to change.
# It's written as a loop to make it more future-proof (at least it'll do something right-ish).
for ip in (input_data.get("ipv4", ""), input_data.get("ipv6", "")):
    if not ip: continue
    host = input_data

    # This code assumes only the first hostname is the "good" one.
    # It will generally be true if the command pipeline is sane.
    try:
        hostname = host["hostnames"][0]
    except Exception:
        sys.stderr.write("[G3] Warning: no hostname found!\n")
        hostname = ip

    # Scan each port individually.
    # This will result in a slower scan altogether but it's also more likely to be accurate.
    # TODO this could be run in parallel using the multiprocessing library.
    for service in host["services"]:

        # Skip if the port number is unknown (should not happen).
        if "port" not in service:
            continue
        port = int(service["port"])

        # Try to get the protocol as detected by the port scanner.
        # If not detected, take a guess based on the IANA port number assignation.
        protocol = service.get("service", "")
        if not protocol:
            try:
                protocol = socket.getservbyport(port)
            except Exception:
                sys.stderr.write("[G3] Warning: unknown protocol on port %d, skipped\n" % port)
                continue

        # Determine if hydra supports this protocol.
        # FIXME review this logic, reality is probably more complicated
        # TODO implement the missing protocols
        if protocol == "http":
            sys.stderr.write("[G3] Warning: HTTP not supported yet.\n")
            continue
        if protocol == "ldap":
            sys.stderr.write("[G3] Warning: LDAP not supported yet.\n")
            continue
        if protocol == "smtp":
            sys.stderr.write("[G3] Warning: SMTP not supported yet.\n")
            continue
        if protocol not in SUPPORTED_PROTOCOLS:
            sys.stderr.write("[G3] Protocol not supported by Hydra: %s (port %d)\n" % (protocol, port))
            continue

        # Create a temporary file for the tool output.
        fd, tmp = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'r') as tmpfd:

                # Build the command line for Hydra.
                args = list(base_args)
                args.append("%s://%s:%d" % (protocol, hostname, port))
                args.append("-o")
                args.append(tmp)

                # Run Hydra, piping stdout and stderr directly to our stderr.
                # This will send all of the text output into the G3 logs.
                # On error an exception is raised.
                result = subprocess.run(args, stdout = sys.stderr, stderr = sys.stderr, check=False)

                # Call the importer on the output file.
                # Capture stdout so we can parse it later.
                process = subprocess.Popen(["/usr/bin/g3i", tmp], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
                stdout, stderr = process.communicate()
                if stderr:
                    sys.stderr.write(stderr)
                if not stdout:
                    continue

                # Parse the output file as JSON.
                output_data.extend( json.loads(stdout) )

        # Delete the temporary file when we're done.
        finally:
            os.unlink(tmp)

# Send the JSON output array over stdout.
json.dump(output_data, sys.stdout)
