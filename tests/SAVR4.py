import re
import ipaddress

# Matches the enriched "TCP connect" line emitted after ETW callback + DNS
# correlation. Present for both IPv4 (IPv6=0) and IPv6 (IPv6=1) connections.
TCP_CONNECT_RE = re.compile(
    r"TCP connect:\s+PID=(?P<pid>\d+)\s+"
    r"(?P<src>\S+)->(?P<dst>\S+)\s+"
    r"IPv6=(?P<ipv6_flag>[01])\s+"
    r"bytes_out=(?P<bytes_out>\d+)\s+bytes_in=(?P<bytes_in>\d+)\s+"
    r"rtt=(?P<rtt>\d+)ms\s+retrans=(?P<retrans>\d+)\s+syn=(?P<syn>\d+)\s+"
    r"domain=(?P<domain>\S+)\s+source=(?P<source>\S+)\s+url=(?P<url>\S+)"
)


def _split_ip_port(addr):
    """Split 'ip:port' for both IPv4 and IPv6 (IPv6 has extra colons, so
    only the final colon-separated segment is ever the port)."""
    ip_str, port_str = addr.rsplit(":", 1)
    return ip_str, port_str


class SAVR4:
    name = "SAVR4"

    def __init__(self, cfg, agents=None, sysinfo=None):
        self.quic_pid_procs = cfg.get("quic_heuristic_processes", ["chrome.exe"])
        self.udp_enumeration_shipped = cfg.get("udp_enumeration_shipped", False)

        self.ipv4_entries = []
        self.ipv6_entries = []
        self.malformed = []

    def offer(self, line, i, window):
        m = TCP_CONNECT_RE.search(line)
        if not m:
            return

        src_ip, src_port = _split_ip_port(m.group("src"))
        dst_ip, dst_port = _split_ip_port(m.group("dst"))

        try:
            src_parsed = ipaddress.ip_address(src_ip)
            dst_parsed = ipaddress.ip_address(dst_ip)
        except ValueError:
            self.malformed.append((i, m.group("src"), m.group("dst")))
            return

        ipv6_flag = m.group("ipv6_flag") == "1"
        actually_ipv6 = src_parsed.version == 6 and dst_parsed.version == 6

        entry = {
            "line": i,
            "pid": m.group("pid"),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "ipv6_flag": ipv6_flag,
            "flag_matches_actual": ipv6_flag == actually_ipv6,
            "domain": m.group("domain"),
        }

        if actually_ipv6:
            self.ipv6_entries.append(entry)
        else:
            self.ipv4_entries.append(entry)

    def resolve(self):
        self.results = []
        self._score_ipv4_table()
        self._score_ipv6_table()
        self._score_ipv6_cdn_mapping()
        self._score_quic_heuristic()

    def _score_ipv4_table(self):
        subject = "ipv4_tcp_table"
        expected = "at least one IPv4 TCP connect entry, well-formed src/dst ip:port"
        if not self.ipv4_entries:
            self.results.append((subject, expected, "", "NOT_DETECTED",
                                  "no IPv4 TCP connect lines found in window"))
            return

        bad = [e for e in self.ipv4_entries if not e["flag_matches_actual"]]
        actual = f"{len(self.ipv4_entries)} IPv4 entries found"
        if bad:
            self.results.append((subject, expected, actual, "FAIL",
                                  f"{len(bad)} entries had IPv6 flag mismatched with actual address family "
                                  f"(e.g. line {bad[0]['line']})"))
        else:
            self.results.append((subject, expected, actual, "PASS", ""))

    def _score_ipv6_table(self):
        subject = "ipv6_tcp_table"
        expected = "at least one IPv6 TCP connect entry, well-formed src/dst ip:port"
        if not self.ipv6_entries:
            self.results.append((subject, expected, "", "NOT_DETECTED",
                                  "no IPv6 TCP connect lines found in window -- "
                                  "GetExtendedTcp6Table entries not observed"))
            return

        bad = [e for e in self.ipv6_entries if not e["flag_matches_actual"]]
        actual = f"{len(self.ipv6_entries)} IPv6 entries found"
        if bad:
            self.results.append((subject, expected, actual, "FAIL",
                                  f"{len(bad)} entries had IPv6 flag mismatched with actual address family "
                                  f"(e.g. line {bad[0]['line']})"))
        else:
            self.results.append((subject, expected, actual, "PASS", ""))

    def _score_ipv6_cdn_mapping(self):
        subject = "ipv6_cdn_domain_mapping"
        expected = "IPv6 destination addresses resolved to a non-empty domain name"
        if not self.ipv6_entries:
            self.results.append((subject, expected, "", "NOT_DETECTED",
                                  "no IPv6 entries available to check domain mapping against"))
            return

        unmapped = [e for e in self.ipv6_entries if not e["domain"] or e["domain"] == "(none)"]
        mapped = [e for e in self.ipv6_entries if e not in unmapped]
        actual = f"{len(mapped)}/{len(self.ipv6_entries)} IPv6 entries had a resolved domain"

        if unmapped and not mapped:
            self.results.append((subject, expected, actual, "FAIL",
                                  "no IPv6 entries had a domain mapped -- CDN address -> domain resolution not working"))
        elif unmapped:
            self.results.append((subject, expected, actual, "PARTIAL",
                                  f"{len(unmapped)} IPv6 entries had domain=(none), e.g. "
                                  f"dst={unmapped[0]['dst_ip']}"))
        else:
            self.results.append((subject, expected, actual, "PASS", ""))

    def _score_quic_heuristic(self):
        subject = "quic_heuristic"
        expected = ("AI-matched PID with UDP socket + AI domain in DNS cache "
                    "=> is_quic=heuristic (e.g. chrome.exe)")
        if not self.udp_enumeration_shipped:
            self.results.append((subject, expected, "", "NOT_DETECTED",
                                  "UDP table enumeration (GetExtendedUdpTable/GetExtendedUdp6Table) "
                                  "not yet implemented -- heuristic cannot fire until UDP work ships"))
            return

        # Placeholder for once UDP enumeration ships: look for a logged
        # is_quic=heuristic marker tied to a QUIC-capable process.
        self.results.append((subject, expected, "", "NOT_DETECTED",
                              "udp_enumeration_shipped=true but no QUIC heuristic matcher implemented yet "
                              "in this test -- update once UDP log line format is known"))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
