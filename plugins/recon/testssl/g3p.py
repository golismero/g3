#!/usr/bin/python3

import os
import sys
import json
import socket
import tempfile
import traceback
import subprocess
import urllib.parse

# Base arguments for testssl.
# TODO some of this could come from environment variables
base_args = ["testssl.sh", "--sneaky", "--phone-out", "--hints", "-6", "--connect-timeout", "10", "--openssl-timeout", "10", "--wide"]

# Here we will have the output data.
output_data = []

# Get the G3 data object.
input_data = json.load(sys.stdin)

# Process URLs. This means we are running a web test.
# TODO this could be run in parallel using the multiprocessing library, would need to resolve IPs manually.
if "url" in input_data:
    url = input_data["url"]
    fd, tmp = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'r') as tmpfd:
            args = list(base_args)
            args.extend(["-oJ", tmp, "--overwrite", "--", url])
            result = subprocess.run(args, stdout = sys.stderr, stderr = sys.stderr, check=False)
            process = subprocess.Popen(["/usr/bin/g3i", tmp], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            stdout, stderr = process.communicate()
            if stderr:
                sys.stderr.write(stderr)
            if stdout:
                output_data.extend( json.loads(stdout) )
    finally:
        os.unlink(tmp)

# Process hosts. This means we are running a network test.
# Process IPv4 and IPv6 separately since we can only pass one using "--ip".
else:
    for ip in (input_data.get("ipv4", ""), input_data.get("ipv6", "")):
        if not ip: continue
        host = input_data

        # This code assumes only the first hostname is the "good" one.
        # It will generally be true if the command pipeline is sane.
        try:
            hostname = host["hostnames"][0]
        except Exception:
            sys.stderr.write("Warning: no hostname found!\n")
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
            name = service.get("service", "")
            if not name:
                try:
                    name = socket.getservbyport(port)
                except Exception:
                    name = ""

            # Start preparing the command line options for testssl.sh.
            # TODO some of this could come from environment
            args = list(base_args)

            # Determine if this is an SSL port, also add protocol specific options.
            # FIXME review this logic, reality is probably more complicated
            if name == "https" or service.get("ssl", False):
                pass        # no further args needed
            elif name in ("ftp", "smtp", "lmtp", "pop3", "imap", "sieve", "xmpp", "xmpp-server", "telnet", "ldap", "nntp", "postgres", "mysql"):
                args.append("-t")
                args.append(name)
                if name in ("xmpp", "xmpp-server"):
                    args.append("--xmpphost")
                    args.append(hostname)
            else:
                continue    # not an SSL port

            # Create a temporary file for the JSON output from testssl.sh.
            fd, tmp = tempfile.mkstemp()
            try:
                with os.fdopen(fd, 'r') as tmpfd:

                    # Add the output filename and target host and port.
                    args.extend(["--ip", ip, "-oJ", tmp, "--overwrite"])
                    args.append("--")
                    args.append("%s:%d" % (hostname, port))

                    # Run testssl.sh, piping stdout and stderr directly to our stderr.
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

            # Make sure to delete the temporary file on exit.
            finally:
                os.unlink(tmp)

# Send the JSON output array over stdout.
json.dump(output_data, sys.stdout)
