"""
SAVR-43 test classes.

  Issue 1 - Device registration completes without any agent detection   (RegistrationTest)
  Issue 2 - Heartbeat payload contains ip_address (+ schema alignment)  (HeartbeatPayloadTest)
  Issue 3 - Combined (process+network) detection events carry both
            process fields and flow fields                              (CombinedFieldsTest)

Harness contract: name, __init__(cfg), offer(line, i, window), resolve(), rows().
Enable each test by adding its section to roster.json.
"""

import json
from pathlib import Path

from mytests._common import (
    extract_json as _extract_json,
    EPOCH_RE as _EPOCH_RE,
    ISO8601_RE as _ISO8601_RE,
    SCAN_COMPLETE_RE as _SCAN_COMPLETE_RE,
)

# =====================================================================
# Issue 1 - device registration with zero agent detections
# =====================================================================
class RegistrationTest:
    """Verifies the registration/authentication sequence completes even when
    no AI agent has been detected on the device.

    roster section:
      "registration_test": {
        "require_zero_agents": true      # assert no scan found an AI process
      }                                  # before registration completed
    """

    name = "registration_test"

    # ordered milestones we expect to see in the window
    _MILESTONES = [
        ("fingerprint",   "Successfully generated device fingerprint"),
        ("reg_request",   "Registration Request data"),
        ("reg_response",  "Registration response"),
        ("auth_request",  "Authentication Request data"),
        ("auth_response", "Authentication response"),
        ("heartbeat_ok",  "Successfully sent heartbeat request"),
    ]

    def __init__(self, cfg):
        self.require_zero_agents = bool(cfg.get("require_zero_agents", True))
        self.seen = {}            # key -> (line_index, line)   first sighting wins
        self.scan_counts = []     # (line_index, ai_process_count) for every scan
        self.reg_success = None   # parsed truthiness of registration response
        self.auth_success = None

    def offer(self, line, i, window):
        for key, needle in self._MILESTONES:
            if key not in self.seen and needle in line:
                self.seen[key] = (i, line)
                if key == "reg_response":
                    d = _extract_json(line, "Registration response :")
                    self.reg_success = bool(d and d.get("success"))
                elif key == "auth_response":
                    d = _extract_json(line, "Authentication response :")
                    self.auth_success = bool(d and d.get("success"))
        m = _SCAN_COMPLETE_RE.search(line)
        if m:
            self.scan_counts.append((i, int(m.group("n"))))

    def resolve(self):
        self.results = []

        # 1. every milestone present, in order
        prev_idx, in_order, missing = -1, True, []
        for key, _needle in self._MILESTONES:
            if key not in self.seen:
                missing.append(key)
                continue
            idx = self.seen[key][0]
            if idx < prev_idx:
                in_order = False
            prev_idx = idx
        if missing:
            self.results.append((
                "registration sequence", "all 6 milestones",
                f"missing: {', '.join(missing)}", "NOT_DETECTED",
                "registration/auth sequence not (fully) in run window; "
                "start the window at service install/restart to exercise it",
            ))
        else:
            self.results.append((
                "registration sequence", "all 6 milestones in order",
                "complete" if in_order else "out of order",
                "PASS" if in_order else "FAIL",
                "" if in_order else "milestones appeared out of expected order",
            ))

        # 2. server accepted registration and authentication
        for label, key, ok in (
                ("registration accepted", "reg_response", self.reg_success),
                ("authentication accepted", "auth_response", self.auth_success)):
            seen = key in self.seen
            result = "PASS" if ok else ("FAIL" if seen else "NOT_DETECTED")
            self.results.append((
                label, "success=true",
                "true" if ok else ("false/unparsed" if seen else "not seen"),
                result,
                "" if ok else ("server did not confirm success" if seen
                               else "response line not in run window"),
            ))

        # 3. Issue 1 core: registration completed with zero agent detections
        if self.require_zero_agents:
            if "reg_response" in self.seen:
                reg_idx = self.seen["reg_response"][0]
                pre = [n for i, n in self.scan_counts if i <= reg_idx]
                nonzero = [n for n in pre if n > 0]
                if not pre:
                    self.results.append((
                        "zero-agent precondition", "0 AI processes in all scans",
                        "no scans in window", "NOT_DETECTED",
                        "no [SCANNER] Scan complete lines before registration",
                    ))
                else:
                    ok = not nonzero
                    self.results.append((
                        "zero-agent precondition",
                        "0 AI processes in all scans before registration",
                        f"{len(pre)} scan(s), max count {max(pre)}",
                        "PASS" if ok else "FAIL",
                        "" if ok else
                        "an AI process was detected before registration; "
                        "this run does not exercise Issue 1",
                    ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)


# =====================================================================
# Issue 2 (+ Pawel's Swagger alignment) - heartbeat payload contents
# =====================================================================
class HeartbeatPayloadTest:
    """Parses the first Heartbeat Request in the window and validates its
    fields against a configurable schema, so the same test survives the
    sys_stats -> system_stats / cpu_percent -> cpu_usage renames.

    roster section:
      "heartbeat_payload_test": {
        "required_fields":  ["ip_address", "hostname", "device_token",
                             "agent_count", "status", "last_scan_time"],
        "forbidden_fields": [],
        "stats_key":        "sys_stats",
        "stats_required":   ["cpu_percent", "memory_mb", "disk_usage", "uptime"],
        "last_scan_time_format": "epoch",       # "epoch" | "iso8601"
        "require_response_success": true
      }
    """

    name = "heartbeat_payload_test"

    def __init__(self, cfg):
        self.required = cfg.get("required_fields", ["ip_address"])
        self.forbidden = cfg.get("forbidden_fields", [])
        self.stats_key = cfg.get("stats_key", "sys_stats")
        self.stats_required = cfg.get("stats_required", [])
        self.lst_format = cfg.get("last_scan_time_format")   # None = don't check
        self.require_resp = bool(cfg.get("require_response_success", True))
        self.payload = None          # first parsed heartbeat request
        self.resp_success = None     # first parsed heartbeat response

    def offer(self, line, i, window):
        if self.payload is None and "Heartbeat Request data" in line:
            d = _extract_json(line, "Heartbeat Request data :")
            if isinstance(d, dict):
                self.payload = d
        if self.resp_success is None and "Heartbeat response" in line:
            d = _extract_json(line, "Heartbeat response :")
            if isinstance(d, dict):
                self.resp_success = bool(d.get("success"))

    def resolve(self):
        self.results = []
        p = self.payload
        if p is None:
            self.results.append((
                "heartbeat request", "parseable JSON payload", "", "NOT_DETECTED",
                "no parseable Heartbeat Request data line in the run window",
            ))
            return

        # required top-level fields, present and non-empty
        for f in self.required:
            val = p.get(f, None)
            ok = val is not None and val != ""
            self.results.append((
                f"heartbeat field '{f}'", "present, non-empty",
                repr(val) if f != "device_token" else ("<set>" if ok else repr(val)),
                "PASS" if ok else "FAIL",
                "" if ok else "field missing or empty in heartbeat payload",
            ))

        # forbidden fields (e.g. legacy names after a rename ships)
        for f in self.forbidden:
            ok = f not in p
            self.results.append((
                f"heartbeat field '{f}'", "absent",
                "absent" if ok else "present",
                "PASS" if ok else "FAIL",
                "" if ok else "legacy/forbidden field still in heartbeat payload",
            ))

        # nested stats block
        if self.stats_key:
            stats = p.get(self.stats_key)
            if not isinstance(stats, dict):
                self.results.append((
                    f"stats block '{self.stats_key}'", "present (object)",
                    "missing", "FAIL",
                    "expected stats object not found "
                    "(check sys_stats vs system_stats naming)",
                ))
            else:
                for f in self.stats_required:
                    ok = f in stats
                    self.results.append((
                        f"{self.stats_key}.{f}", "present",
                        repr(stats.get(f)) if ok else "missing",
                        "PASS" if ok else "FAIL",
                        "" if ok else "stat field missing "
                        "(check cpu_percent/cpu_usage, memory_mb/memory_usage)",
                    ))

        # last_scan_time format
        if self.lst_format:
            raw = p.get("last_scan_time")
            s = str(raw) if raw is not None else ""
            if self.lst_format == "epoch":
                ok = bool(_EPOCH_RE.match(s))
            elif self.lst_format == "iso8601":
                ok = bool(_ISO8601_RE.match(s))
            else:
                ok = False
            self.results.append((
                "last_scan_time format", self.lst_format, repr(raw),
                "PASS" if ok else "FAIL",
                "" if ok else f"value does not match {self.lst_format} format",
            ))

        # server accepted the heartbeat
        if self.require_resp:
            ok = bool(self.resp_success)
            self.results.append((
                "heartbeat response", "success=true",
                "true" if ok else ("false" if self.resp_success is not None
                                   else "not seen"),
                "PASS" if ok else "FAIL",
                "" if ok else "no successful heartbeat response in run window",
            ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)


# =====================================================================
# Issue 3 - combined detection events carry process + flow fields
# =====================================================================
class CombinedFieldsTest:
    """Validates captured agent_detected event JSONs (exported from the
    backend or the output module) for combined process+network detections.

    This test does not consume the log window; it reads event files listed
    in the roster. It still plugs into the harness so results land in the
    same CSV.

    roster section:
      "combined_fields_test": {
        "event_files": ["Process-Data.txt", "LibraryAnalysis-Data.txt"],
        "event_dir":   null,                    # or a folder of *.json/*.txt
        "required_fields": ["os_name", "os_version", "logged_in_user",
                            "network_adapters", "route_table",
                            "working_set_bytes", "thread_count",
                            "handle_count", "process_start_time",
                            "flow_id", "src_ip", "dst_ip", "bytes_out"],
        "expect_event_type": "agent_detected",
        "expect_detection_method": "Combined"
      }
    """

    name = "combined_fields_test"

    DEFAULT_REQUIRED = [
        "os_name", "os_version", "logged_in_user", "network_adapters",
        "route_table", "working_set_bytes", "thread_count", "handle_count",
        "process_start_time", "flow_id", "src_ip", "dst_ip", "bytes_out",
    ]

    def __init__(self, cfg):
        self.files = [Path(f) for f in cfg.get("event_files", [])]
        event_dir = cfg.get("event_dir")
        if event_dir:
            d = Path(event_dir)
            if d.is_dir():
                self.files += sorted(
                    p for p in d.iterdir()
                    if p.suffix.lower() in (".json", ".txt")
                )
        self.required = cfg.get("required_fields", self.DEFAULT_REQUIRED)
        self.expect_type = cfg.get("expect_event_type", "agent_detected")
        self.expect_method = cfg.get("expect_detection_method")  # None = skip

    def offer(self, line, i, window):
        pass  # file-based test; nothing to match in the log

    def resolve(self):
        self.results = []
        if not self.files:
            self.results.append((
                "event files", ">=1 captured event", "0", "NOT_DETECTED",
                "no event_files/event_dir configured in roster",
            ))
            return

        for path in self.files:
            subject_base = path.name
            if not path.exists():
                self.results.append((
                    subject_base, "file exists", "missing", "NOT_DETECTED",
                    "captured event file not found on disk",
                ))
                continue
            try:
                ev = json.loads(path.read_text(encoding="utf-8",
                                               errors="replace"))
            except (json.JSONDecodeError, ValueError) as e:
                self.results.append((
                    subject_base, "valid JSON", f"parse error", "FAIL",
                    f"could not parse event file: {e}",
                ))
                continue

            agent = ev.get("agent_name") or ev.get("process_name") or "?"
            subject = f"{subject_base} ({agent})"

            # event type / detection method
            if self.expect_type:
                ok = ev.get("event_type") == self.expect_type
                self.results.append((
                    subject, f"event_type={self.expect_type}",
                    repr(ev.get("event_type")), "PASS" if ok else "FAIL",
                    "" if ok else "unexpected event type",
                ))
            if self.expect_method:
                ok = ev.get("detection_method") == self.expect_method
                self.results.append((
                    subject, f"detection_method={self.expect_method}",
                    repr(ev.get("detection_method")), "PASS" if ok else "FAIL",
                    "" if ok else "event is not a combined detection",
                ))

            # required fields present and non-null / non-empty
            bad = []
            for f in self.required:
                v = ev.get(f, None)
                if v is None or v == "" or v == []:
                    bad.append(f)
            ok = not bad
            self.results.append((
                subject,
                f"{len(self.required)} combined fields non-null",
                "all present" if ok else f"missing/null: {', '.join(bad)}",
                "PASS" if ok else "FAIL",
                "" if ok else "process/flow fields absent from combined event "
                "(Issue 3 regression)",
            ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
