#!/usr/bin/python3

import os
import os.path
import sys
import json
import shutil
import socket
import tempfile
import subprocess


# Slug an IP for safe use in artifact filenames: dots/colons become dashes;
# anything outside [0-9a-fA-F-] returns None (defense against malformed upstream data).
_IP_SLUG_ALLOWED = set("0123456789abcdefABCDEF-")

def ip_slug(ip):
    slug = ip.replace(":", "-").replace(".", "-")
    if not slug or not all(c in _IP_SLUG_ALLOWED for c in slug):
        return None
    return slug

# Base arguments for testssl.
# TODO some of this could come from environment variables
base_args = [
    "testssl.sh",
    "--warnings=batch",
    "--sneaky",
    "--nodns=min",
    "--phone-out",
    "--hints",
    "--show-each",
    "--connect-timeout",
    "10",
    "--openssl-timeout",
    "10",
    "--wide",
    "--color",
    "2",
]

# Disable IPv6 unless explicitly enabled.
is_ipv6_enabled = os.getenv("G3_ENV_IPV6_SUPPORTED")
is_ipv6_enabled = is_ipv6_enabled and (is_ipv6_enabled.strip().lower() == "true")

# Worst exit code seen across all testssl invocations (URL branch or the
# per-target host loop). testssl exits 0 on a normal run even when sub-tests
# fail; a non-zero code is a genuine failure. Fold: any non-zero → non-zero.
worst_rc = 0

# Get the G3 data object.
input_data = json.load(sys.stdin)

# Generated artifacts (if any) in this run.
artifacts = []

# Process URLs. This means we are running a web test.
# TODO this could be run in parallel using the multiprocessing library, would need to resolve IPs manually.
if "url" in input_data:
    url = input_data["url"]
    fd, tmp = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "r") as tmpfd:
            args = list(base_args)
            if is_ipv6_enabled:
                args.append("-6")
            args.extend(["-oJ", tmp, "--overwrite", "--", url])
            # Run testssl, tee'ing combined stdout/stderr to both stderr (live) and the artifacts log.
            with open("/artifacts/testssl.txt", "wb") as logfile:
                proc = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                )
                for line in proc.stdout:
                    sys.stderr.buffer.write(line)
                    sys.stderr.buffer.flush()
                    logfile.write(line)
                proc.wait()
            if proc.returncode and not worst_rc:
                worst_rc = proc.returncode
            input_data["_artifacts"] = ["testssl.txt", "testssl.json"]

        # Copy the temporary file to the artifacts folder.
        shutil.copy(tmp, "/artifacts/testssl.json")

        # Testssl writes its output json with very strict permissions.
        # This can cause artifact retrieval later to fail.
        os.chmod("/artifacts/testssl.json", 0o644)

    finally:
        os.unlink(tmp)

# Process hosts. This means we are running a network test.
# Process IPv4 and IPv6 separately since we can only pass one using "--ip".
else:
    for ip in (
        input_data.get("ipv4", ""),
        input_data.get("ipv6", "") if is_ipv6_enabled else "",
    ):
        if not ip:
            continue
        slug = ip_slug(ip)
        if slug is None:
            sys.stderr.write(
                "Warning: skipping testssl for malformed IP value %r\n" % ip
            )
            continue
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
                pass  # no further args needed
            elif name in (
                "ftp",
                "smtp",
                "lmtp",
                "pop3",
                "imap",
                "sieve",
                "xmpp",
                "xmpp-server",
                "telnet",
                "ldap",
                "nntp",
                "postgres",
                "mysql",
            ):
                args.append("-t")
                args.append(name)
                if name in ("xmpp", "xmpp-server"):
                    args.append("--xmpphost")
                    args.append(hostname)
            else:
                continue  # not an SSL port

            # Per-target artifact filenames so multiple (ip, port) tuples don't clobber.
            txt_path = "/artifacts/testssl.%s.%d.txt" % (slug, port)
            json_path = "/artifacts/testssl.%s.%d.json" % (slug, port)

            # Add the output filename and target host and port.
            args.extend(["--ip", ip, "-oJ", json_path, "--overwrite"])
            args.append("--")
            args.append("%s:%d" % (hostname, port))

            # Run testssl.sh, tee'ing combined stdout/stderr to both stderr (live)
            # and the artifacts log. This will send all of the text output into the G3 logs.
            with open(txt_path, "wb") as logfile:
                proc = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                )
                for line in proc.stdout:
                    sys.stderr.buffer.write(line)
                    sys.stderr.buffer.flush()
                    logfile.write(line)
                proc.wait()
            if proc.returncode and not worst_rc:
                worst_rc = proc.returncode

            # Claim the artifacts.
            if os.path.exists(txt_path):
                artifacts.append(os.path.basename(txt_path))
            if os.path.exists(json_path):
                artifacts.append(os.path.basename(json_path))

                # Testssl writes its output json with very strict permissions.
                # This can cause artifact retrieval later to fail.
                os.chmod(json_path, 0o644)

# Send the JSON output array over stdout.
json.dump([{"_type": "nil", "_artifacts": artifacts}] if artifacts else [], sys.stdout)
sys.stdout.flush()

# Propagate testssl's exit code (folded across all invocations). 0 = clean;
# non-zero = a genuine failure. The worker turns non-zero + data → WARNING,
# non-zero + no data → ERROR.
sys.exit(1 if worst_rc else 0)
