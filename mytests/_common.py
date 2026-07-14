"""
_common.py - helpers shared by test files in mytests/.

Files starting with underscore are ignored by the runner's discovery,
so this is a safe home for utilities. Future ticket files import from
here instead of re-copying these.
"""

import json
import re

# log payload extraction ------------------------------------------------

def extract_json(line: str, marker: str):
    """Pull the JSON that follows `marker` in a log line.

    The service logs request payloads with doubled braces:  {{"k":"v"}}
    and responses as single-element arrays:                 [{"success":true}]
    Returns a dict, or None if the marker is absent / JSON won't parse.
    """
    idx = line.find(marker)
    if idx < 0:
        return None
    payload = line[idx + len(marker):].strip()
    if payload.startswith("{{"):
        payload = payload[1:]
    if payload.endswith("}}"):
        payload = payload[:-1]
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
        return parsed[0]
    return parsed if isinstance(parsed, dict) else None


# common regexes ---------------------------------------------------------

EPOCH_RE = re.compile(r"^\d{9,11}$")
ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

SCAN_COMPLETE_RE = re.compile(
    r"\[SCANNER\]\s+Scan complete:\s*(?P<n>\d+)\s+AI process\(es\) found")

CONF_RE = re.compile(
    r"\[SCANNER\]\s+Trusted AI process:\s*(?P<proc>\S+\.exe)\s*"
    r"\(PID\s+(?P<pid>\d+),.*?conf\s+(?P<conf>[0-9.]+)\)")

TCP_CONNECT_RE = re.compile(
    r"TCP connect:\s+PID=(?P<pid>\d+)\s+(?P<src>\S+)->(?P<dst>\S+)\s+"
    r"IPv6=(?P<ipv6>\d)\s+bytes_out=(?P<bytes_out>\d+)\s+"
    r"bytes_in=(?P<bytes_in>\d+)\s+rtt=(?P<rtt>\d+)ms\s+"
    r"retrans=(?P<retrans>\d+)\s+syn=(?P<syn>\d+)\s+"
    r"domain=(?P<domain>\S+)\s+source=(?P<source>\S+)\s+url=(?P<url>\S+)")

DNS_QUERY_RE = re.compile(
    r"\[ETW_DNS_MONITOR\]\s+q=(?P<q>\S+)\s+status=(?P<status>\d+)\s+"
    r"type=(?P<type>\d+)\s+transport=(?P<transport>\S+)\s+"
    r"answers=(?P<answers>\d+)\s+latency=(?P<latency>\d+)ms\s+"
    r"pid=(?P<pid>\d+)")
