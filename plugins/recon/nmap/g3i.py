#!/usr/local/bin/python3

import sys
import json
import socket
import traceback

from libnmap.parser import NmapParser

# Try to parse the IANA service descriptions.
# If missing just ignore this feature.
IANA_DESCRIPTIONS_FULL = {}
IANA_DESCRIPTIONS_PORTS = {}
IANA_DESCRIPTIONS_NAMES = {}
HTTP_DESC = None
HTTP_ALT_DESC = None
def parse_iana_descriptions(jsonObj):
    global IANA_DESCRIPTIONS_FULL
    global IANA_DESCRIPTIONS_PORTS
    global IANA_DESCRIPTIONS_NAMES
    for srv in jsonObj:
        n = srv.get("name", None)
        po = srv.get("port", None)
        pr = srv.get("protocol", None)
        d = srv.get("description", n)
        if not d:
            continue
        if n and po and pr:
            IANA_DESCRIPTIONS_FULL[(n, po, pr)] = d
        if n and po:
            IANA_DESCRIPTIONS_PORTS[(n, po)] = d
        if n:
            IANA_DESCRIPTIONS_NAMES[n] = d
def get_iana_description(name, port, proto):
    port = str(port)
    desc = IANA_DESCRIPTIONS_FULL.get((name, port, proto), None)
    if not desc:
        desc = IANA_DESCRIPTIONS_PORTS.get((name, port), None)
        if not desc:
            desc = IANA_DESCRIPTIONS_NAMES.get(name, None)
            if not desc:
                desc = name
    return desc
try:
    with open("iana-descriptions.json") as fd:
        parse_iana_descriptions(json.load(fd))
    HTTP_DESC = get_iana_description("http", 80, "tcp")
    HTTP_ALT_DESC = get_iana_description("http-alt", 8080, "tcp")
except:
    traceback.print_exc()

# This function parses a single host from the Nmap output.
def parse_host(nmap_report, nmap_host, host = None):

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
        if srv.port: m["port"] = srv.port
        if srv.protocol: m["protocol"] = srv.protocol
        if srv.tunnel: m["ssl"] = (srv.tunnel == 'ssl')
        if srv.state: m["state"] = srv.state
        if srv.service and srv.service != "unknown": m["service"] = srv.service
        if srv.cpelist: m["cpe"] = [cpe.cpestring for cpe in srv.cpelist]
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
    if services: host["services"] = services

    # Add the OS fingerprint data.
    if os_matches: host["os_matches"] = os_matches
    if nmap_host.os_fingerprint: host["os_fingerprint"] = nmap_host.os_fingerprint

    # Add the hostnames associated with this host.
    if nmap_host.hostnames:
        if "hostnames" not in host:
            host["hostnames"] = []
        for name in nmap_host.hostnames:
            if name not in host["hostnames"]:
                host["hostnames"].append(name)

    # Add every other property we can find that is useful.
    if nmap_host.mac: host["mac"] = nmap_host.mac
    if nmap_host.vendor: host["vendor"] = nmap_host.vendor
    if nmap_host.starttime: host["starttime"] = nmap_host.starttime
    if nmap_host.uptime: host["uptime"] = nmap_host.uptime

    # Return the scanned host.
    return host

# Look for vulnerabilities in the Nmap scan output.
TLS_IANA = ['3par-mgmt-ssl', 'amqps', 'amt-redir-tls', 'amt-soap-https', 'appserv-https', 'armcenterhttps', 'asap-sctp-tls', 'asap-tcp-tls', 'babel-dtls', 'bsfsvr-zn-ssl', 'can-ferret-ssl', 'can-nds-ssl', 'caspssl', 'coaps', 'commtact-https', 'compaq-https', 'cops-tls', 'corba-iiop-ssl', 'csvr-sslproxy', 'davsrcs', 'ddm-ssl', 'diameters', 'dicom-tls', 'docker-s', 'domain-s', 'ehs-ssl', 'enpp', 'enrp-sctp-tls', 'ethernet-ip-s', 'etlservicemgr', 'ftps', 'ftps-data', 'giop-ssl', 'gre-udp-dtls', 'hassle', 'hncp-dtls-port', 'https', 'https-alt', 'https-proxy', 'https-wmap', 'iadt-tls', 'ibm-diradm-ssl', 'ice-slocation', 'ice-srouter', 'icpps', 'ieee-mms-ssl', 'imaps', 'imqstomps', 'imqtunnels', 'inetfs', 'initlsmsad', 'intrepid-ssl', 'ipfixs', 'ipps', 'ircs-u', 'iss-mgmt-ssl', 'jboss-iiop-ssl', 'jt400-ssl', 'ldaps', 'linktest-s', 'llsurfup-https', 'lorica-in-sec', 'lorica-out-sec', 'mipv6tls', 'mpls-udp-dtls', 'msft-gc-ssl', 'netconf-ch-ssh', 'netconf-ch-tls', 'netconf-ssh', 'netconf-tls', 'netconfsoaphttp', 'networklenss', 'njenet-ssl', 'nntps', 'nsiiops', 'odette-ftps', 'onep-tls', 'oob-ws-https', 'opcua-tls', 'oracleas-https', 'orbix-cfg-ssl', 'orbix-loc-ssl', 'pcsync-https', 'plysrv-https', 'pon-ictp', 'pop3s', 'pt-tls', 'qmtps', 'radsec', 'restconf-ch-tls', 'rets-ssl', 'rid', 'rpki-rtr-tls', 'saphostctrls', 'sdo-ssh', 'sdo-tls', 'seclayer-tls', 'secure-ts', 'sips', 'sitewatch-s', 'smartcard-tls', 'snif', 'snmpdtls', 'snmpdtls-trap', 'snmpssh', 'snmpssh-trap', 'snmptls', 'snmptls-trap', 'spss', 'sqlexec-ssl', 'ssh', 'ssh-mgmt', 'sshell', 'sslp', 'ssm-cssps', 'ssm-els', 'ssslic-mgr', 'ssslog-mgr', 'stun-behaviors', 'stuns', 'submissions', 'sun-sr-https', 'sun-user-https', 'sunwebadmins', 'suucp', 'synapse-nhttps', 'syncserverssl', 'syslog-tls', 'telnets', 'tftps', 'tl1-raw-ssl', 'tl1-ssh', 'topflow-ssl', 'ttc-ssl', 'tungsten-https', 'turns', 'vipera-ssl', 'vt-ssl', 'wap-push-https', 'wbem-exp-https', 'wbem-https', 'wsm-server-ssl', 'wsmans', 'wso2esb-console', 'xnm-ssl', 'xtlserv', 'xtrms', 'z-wave-s']
def get_open_plaintext_ports(host):

    # Report open ports that do not use SSL.
    # 
    # This is tricky if we don't know for a fact the scan was run with service detection. My plan was:
    #
    #   1) if there is at least one "ssl" property, we can assume detection was performed.
    #   2) if not, we can assume otherwise, so let's use the IANA name to figure our if they're encrypted or not.
    #   3) if the IANA names are missing too, we can assume the default port mapping.
    #
    # This is slightly inaccurate but I don't know how to do better with the information given.

    ports = []
    services = host.get("services", [])
    if services:
        has_sv = False
        for srv in services:
            if "ssl" in srv:
                has_sv = True
                break
        for srv in services:
            if "state" not in srv or srv["state"] != "open":
                continue
            if "service" in srv:
                name = srv["service"]
            else:
                try:
                    name = socket.getservbyport(int(srv["port"]), srv["protocol"])
                except:
                    continue
            if (has_sv and "ssl" not in srv) or (not has_sv and name not in TLS_IANA):
                desc = get_iana_description(name, srv["port"], srv["protocol"])
                if not desc:
                    desc = name
                if "ipv4" in host:
                    ports.append((host["ipv4"], srv["port"], srv["protocol"], desc))
                if "ipv6" in host:
                    ports.append((host["ipv6"], srv["port"], srv["protocol"], desc))
    return ports

# Determine if http is available in this host.
def has_http(host):
    services = host.get("services", [])
    if services:
        for srv in services:
            if srv.get("service", None) == "http" or srv["port"] == 80:
                return True
            if srv.get("service", None) in ("http-alt", "http-proxy") or srv["port"] == 8080:
                return True
    return False

# Determine if https is available in this host.
def has_https(host):
    services = host.get("services", [])
    if services:
        for srv in services:
            if srv.get("service", None) == "https" or srv["port"] == 443:
                return True
            if srv.get("service", None) == ("https-alt", "https-proxy") or srv["port"] == 8443:
                return True
    return False

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
    vulns = []

    # If we got a Golismero object, there should be only one host in the Nmap scan.
    if input_data is not None:
        if len(nmap_report.hosts) > 0:
            assert len(nmap_report.hosts) == 1
            host = parse_host(nmap_report, nmap_report.hosts[0], input_data)
            if host is not None:
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

    # Report all plaintext open ports as a vulnerability.
    # If it's just port 80 and there is 443 open too, rate it as low.
    # In any other scenario rate it as high.
    severity = 0    # low
    plaintext_ports = []
    for host in output:
        ports_found = get_open_plaintext_ports(host)
        if not ports_found:
            continue
        plaintext_ports.extend(ports_found)
        if severity == 0:
            if has_http(host) and not has_https(host):
                severity = 2    # high
            else:
                if HTTP_DESC is not None and HTTP_ALT_DESC is not None:
                    for addr, port, proto, desc in ports_found:
                        if desc:
                            if desc not in (HTTP_DESC, HTTP_ALT_DESC):
                                severity = 2    # high
                                break
                        else:
                            if port not in (80, 8080):
                                severity = 2    # high
                                break
                else:
                    for addr, port, proto, desc in ports_found:
                        if port not in (80, 8080):
                            severity = 2    # high
                            break
    plaintext_ports.sort()
    if plaintext_ports:
        pp = []
        for addr, port, proto, desc in plaintext_ports:
            p = {
                "address": addr,
                "port": "%s/%s" % (port, proto),
            }
            if desc:
                p["service"] = desc
            pp.append(p)
        issue = {
            "_type": "issue",
            "_tool": "nmap",
            "_cmd": nmap_report.commandline,
            "severity": severity,
            "affects": ["%s:%s/%s" % x[:3] for x in plaintext_ports],
            "taxonomy": ["CWE-319"],
            "references": ["https://blog.netwrix.com/2022/08/04/open-port-vulnerabilities-list",
                           "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"],
            "plaintext_ports": pp,
        }
        vulns.append(issue)

    # Report vulnerabilities found by Nmap scripts.
    #
    #
    # TODO
    #
    #

    # Add the vulnerabilities to the output.
    output.extend(vulns)

    # Convert the output array to JSON and send it over stdout.
    json.dump(output, sys.stdout)

if __name__ == "__main__":
    main()
