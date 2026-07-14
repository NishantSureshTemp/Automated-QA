# SAVR-43 Test Cases — Registration, Heartbeat Payload, Combined Detection Fields

Automation file: `tests/SAVR43.py` (classes `RegistrationTest`, `HeartbeatPayloadTest`, `CombinedFieldsTest`)

## Integration into overall.py

```python
from tests.SAVR43 import RegistrationTest, HeartbeatPayloadTest, CombinedFieldsTest

TEST_CLASSES = [ConfidenceTest, TcpStatsTest, ScanLatencyTest,
                DnsCorrelationTest, SchannelTest,
                RegistrationTest, HeartbeatPayloadTest, CombinedFieldsTest]
```

Roster additions (see `roster_savr43.json` for a ready-to-merge snippet). A test only runs if its section is present in the roster, so include `registration_test` only for runs whose window starts at a service install/restart.

---

## Test Case SAVR43-1 — Device registration without agent detection (Issue 1)

**Objective:** Verify the device registers and authenticates with the controller even when no AI agent has been detected on the machine.

**Preconditions:** Clean machine state — no AI processes running (no Copilot, Cursor, python with AI libraries). Delete `C:\ProgramData\Cybersenz\config\agents\detected_agents.json` if present so agent_count starts at 0. If testing first-time registration rather than re-registration, also clear the saved controller/device config.

**Procedure**
1. Note timestamp X.
2. Restart the SecureAiService (or install it fresh). Do not launch any AI application.
3. Wait ~90 seconds — long enough for at least two scan cycles, the registration/authentication exchange, and the first heartbeat.
4. Note timestamp Y and run:
   `python overall.py --start "<X>" --roster roster.json --out results.csv`

**Expected results (automated by `registration_test`)**
- All six milestones appear in order: fingerprint generated → Registration Request → Registration response → Authentication Request → Authentication response → first heartbeat sent. → PASS
- Registration response and Authentication response both contain `success:true`. → PASS
- Every `[SCANNER] Scan complete` line before the registration response reports `0 AI process(es) found`, and the run is still accepted by the server. → PASS (this is the Issue 1 acceptance)
- On the dashboard, the device appears with Detection Records = 0 (manual check against the frontend, per the ticket screenshots).

**Fail conditions:** any milestone missing or out of order in a window that starts at service start; `success:false`; registration blocked/deferred until an agent is detected.

---

## Test Case SAVR43-2 — Heartbeat payload schema (Issue 2 + Swagger alignment)

**Objective:** Verify the heartbeat request payload contains `ip_address` (Issue 2) plus all agreed fields, and stays aligned with the Swagger contract as Paweł's renames land.

**Preconditions:** Service running and registered; controller reachable.

**Procedure**
1. Note timestamp X.
2. Let the service run through at least one heartbeat cycle (30 s interval).
3. Note timestamp Y and run overall.py as above.

**Expected results (automated by `heartbeat_payload_test`, current schema)**
- Top-level fields present and non-empty: `ip_address`, `hostname`, `device_token`, `agent_count`, `status`, `last_scan_time`. → PASS
- `sys_stats` object present with `cpu_percent`, `memory_mb`, `disk_usage`, `uptime`. → PASS
- `last_scan_time` matches epoch-seconds format. → PASS
- Heartbeat response contains `success:true`. → PASS

**After the Swagger alignment ships,** flip the roster to the target schema — the code doesn't change:
```json
"heartbeat_payload_test": {
  "required_fields": ["ip_address", "hostname", "device_token",
                      "agent_count", "status", "last_scan_time"],
  "forbidden_fields": ["sys_stats", "os_version"],
  "stats_key": "system_stats",
  "stats_required": ["cpu_usage", "memory_usage", "disk_usage", "uptime"],
  "last_scan_time_format": "iso8601",
  "require_response_success": true
}
```
(Confirm with Paweł whether `memory_usage` stays MB or becomes a percentage, and whether `os_version` is actually dropped, before enabling the forbidden list.)

**Reference behavior verified against real logs:** the 2026-06-03 ticket log FAILs `ip_address`/`hostname` (the reported bug); the 2026-06-25 log PASSes all current-schema checks (fix confirmed).

---

## Test Case SAVR43-3 — Combined detection carries process + flow fields (Issue 3)

**Objective:** Verify that an agent detected via process scanning that also makes network connections emits an event containing both process-context fields and network-flow fields.

**Preconditions:** Service running and registered. A way to capture the emitted `agent_detected` event JSON (backend export, output-module capture, or DB dump) — the two ticket attachments (`Process-Data.txt`, `LibraryAnalysis-Data.txt`) are examples of this capture.

**Procedure**
1. Note timestamp X.
2. Trigger a combined detection, either variant:
   a. Launch a known AI desktop app that goes online (e.g. `mscopilot.exe`) and interact with it, or
   b. Run `python.exe` with an AI library loaded (e.g. onnxruntime / openai) and make it call out (e.g. `api.openai.com`).
3. Wait for the scan + connection to be correlated and the event to be sent (`[OUTPUT_MODULE] Sent anomaly batch`).
4. Export the emitted event JSON(s) to files and reference them in the roster (`event_files` or `event_dir`).
5. Run overall.py.

**Expected results (automated by `combined_fields_test`, per event file)**
- `event_type = agent_detected` → PASS
- `detection_method = Combined` → PASS
- All 13 fields non-null/non-empty: `os_name`, `os_version`, `logged_in_user`, `network_adapters`, `route_table`, `working_set_bytes`, `thread_count`, `handle_count`, `process_start_time`, `flow_id`, `src_ip`, `dst_ip`, `bytes_out` → PASS

**Fail conditions:** `logged_in_user` null (the original bug Prasad worked), any flow field null on a process-detected agent that made connections, or vice versa.

**Reference behavior:** both ticket attachments (mscopilot.exe at conf 0.95, python.exe+onnxruntime at conf 0.75) pass all checks — they are the "fixed" examples.

---

## Result semantics
PASS — expectation met in the run window. FAIL — the relevant line/field was seen but wrong. NOT_DETECTED — the expected activity never appeared in the window (e.g. `registration_test` run against a window that starts mid-session); rerun with the correct window rather than treating as a product failure.
