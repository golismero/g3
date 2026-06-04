#!/usr/local/bin/python3

import sys
import json

from libnmap.parser import NmapParser


# This function parses a single host from the Nmap output.
def parse_host(nmap_report, nmap_host, host=None):
    # Ignore hosts that are down.
    if not nmap_host.is_up():
        return

    # Generate the host object and set the underscore properties.
    # Normally everything is set by the engine, however in this case we
    # want to preserve the data from the XML file instead.
    if host is None:
        host = {}
    else:
        for key in list(host.keys()):
            if key.startswith("_"):
                del host[key]
    host["_tool"] = "nmap"
    host["_cmd"] = nmap_report.commandline
    host["_start"] = nmap_report.started
    host["_end"] = nmap_report.endtime

    # Add the IPv4 and IPv6 addresses of the host.
    # If neither is present, ignore the host (should not happen).
    if not nmap_host.ipv4 and not nmap_host.ipv6:
        sys.stderr.write("WARNING: Skipped malformed host: %r\n" % nmap_host)
        return
    fp = []
    if nmap_host.ipv4:
        host["ipv4"] = nmap_host.ipv4
        fp.append("nmap " + nmap_host.ipv4)
    if nmap_host.ipv6:
        host["ipv6"] = nmap_host.ipv6
        fp.append("nmap " + nmap_host.ipv6)
    if fp:
        host["_fp"] = fp

    # Parse the port scanning data.
    services = []
    for srv in nmap_host.services:
        m = {}
        if srv.port:
            m["port"] = srv.port
        if srv.protocol:
            m["protocol"] = srv.protocol
        if srv.tunnel:
            m["ssl"] = srv.tunnel == "ssl"
        if srv.state:
            m["state"] = srv.state
        if srv.service and srv.service != "unknown":
            m["service"] = srv.service
        if srv.cpelist:
            m["cpe"] = [cpe.cpestring for cpe in srv.cpelist]
        services.append(m)

    # Parse the OS fingerprint data.
    os_matches = []
    for match in nmap_host.os_match_probabilities():
        m = {
            "name": match.name,
            "accuracy": match.accuracy,
            "cpe": [cpe for cpe in match.get_cpe()],
        }
        os_matches.append(m)

    # Add the scanned ports.
    if services:
        host["services"] = services

    # Add the OS fingerprint data.
    if os_matches:
        host["os_matches"] = os_matches
    if nmap_host.os_fingerprint:
        host["os_fingerprint"] = nmap_host.os_fingerprint

    # Add the hostnames associated with this host.
    if nmap_host.hostnames:
        if "hostnames" not in host:
            host["hostnames"] = []
        for name in nmap_host.hostnames:
            if name not in host["hostnames"]:
                host["hostnames"].append(name)

    # Add every other property we can find that is useful.
    if nmap_host.mac:
        host["mac"] = nmap_host.mac
    if nmap_host.vendor:
        host["vendor"] = nmap_host.vendor
    if nmap_host.starttime:
        host["starttime"] = nmap_host.starttime
    if nmap_host.uptime:
        host["uptime"] = nmap_host.uptime

    # Return the scanned host.
    return host


# Entry point.
def main():
    # If we have a Golismero object via the command line arguments, parse it.
    input_data = None
    cidr4 = None
    cidr6 = None
    if len(sys.argv) > 1:
        input_data = json.loads(sys.argv[1])
        if input_data["_type"] == "cidr":
            if "ipv4" in input_data:
                cidr4 = input_data["ipv4"]
            if "ipv6" in input_data:
                cidr6 = input_data["ipv6"]
            input_data = None

    # Parse the Nmap report using libnmap.
    # https://libnmap.readthedocs.io/en/latest/index.html
    nmap_report = NmapParser.parse(sys.stdin.read())

    # This will be our output array.
    output = []

    # If we got a Golismero object, there should be only one host in the Nmap scan.
    if input_data is not None:
        if len(nmap_report.hosts) > 0:
            assert len(nmap_report.hosts) == 1
            host = parse_host(nmap_report, nmap_report.hosts[0], input_data)
            if host is not None:
                host["_artifacts"] = ["nmap.xml", "nmap.txt"]
                output.append(host)

    # Otherwise, we are not running a scan but importing from a user provided report.
    else:
        for nmap_host in nmap_report.hosts:
            host = parse_host(nmap_report, nmap_host)
            if host is not None:
                if cidr4:
                    if "_fp" in host:
                        host["_fp"].append("nmap " + cidr4)
                    else:
                        host["_fp"] = ["nmap " + cidr4]
                if cidr6:
                    if "_fp" in host:
                        host["_fp"].append("nmap " + cidr6)
                    else:
                        host["_fp"] = ["nmap " + cidr6]
                output.append(host)

    # Convert the output array to JSON and send it over stdout.
    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
