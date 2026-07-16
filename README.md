# Anomaly Detection Engine — Test Case Documentation

## Test Cases Covered

### AI Process Confidence Scoring (SAVR-7)
Look for whether known AI programs get high confidence scores and non-AI programs get low ones.

- **File:** `tests/SAVR2SAVR7.py`
- **Roster key:** `confidence_test`
- **What it checks:** Matches each detected process against a roster of expected confidence ranges, either by process name or by PID. Original acceptance criteria: a known AI coding assistant (e.g. Cursor.exe) should score ≥ 0.9; a plain browser process with no AI activity (e.g. chrome.exe) should score < 0.5; a Python process with an AI library imported (e.g. python.exe + openai) should score ≥ 0.8.

### Scan Speed / Responsiveness (SAVR-13)
Look for the engine reacting to a new AI process within 50ms, instead of waiting for its next scheduled scan.

- **File:** `tests/SAVR2SAVR13.py`
- **Roster key:** `scan_latency_test` (no roster configuration required)
- **What it checks:** Measures the time gap between an AI process being flagged (ETW event) and the next scan actually running. Also profiles the overall scan interval pattern to distinguish event-driven dispatch (short, sub-5-second gaps) from a fixed polling loop (25–40 second gaps). Acceptance threshold: latency under 50ms (per TC-DET-09).

### Network Connection Stats (SAVR-14)
Look for accurate data-sent, data-received, and connection-speed numbers logged for an AI program's network connections.

- **File:** `tests/SAVR2SAVR14.py`
- **Roster key:** `tcp_stats_test`
- **What it checks:** For each expected process (matched by name or PID), verifies at least one logged TCP connection snapshot has non-zero bytes sent, non-zero bytes received, and a non-zero round-trip time simultaneously.

### Encrypted Connection Detection (SAVR-15)
Look for the domain, TLS version, and cipher being correctly captured for a secure connection made by an AI program.

- **File:** `tests/SAVR2SAVR15.py`
- **Roster key:** `schannel_test`
- **What it checks:** For each domain in the roster, verifies the captured TLS event includes a matching server name (SNI), a non-empty TLS version, and a non-empty cipher. Key exchange method and protocol list are checked as secondary fields. Requires the test traffic to be generated via PowerShell/.NET rather than Chrome/Edge, since those browsers use their own TLS stack rather than the OS Schannel provider.

### Domain Lookup Correlation (SAVR-18)
Look for a domain lookup (DNS query) being correctly linked to the connection that follows it, rather than logged as two unrelated events.

- **File:** `tests/SAVR2SAVR18.py`
- **Roster key:** `dns_correlation_test`
- **What it checks:** For each domain in the roster, confirms a successful DNS resolution (status 0, at least one answer) is followed by a TCP connection line attributing its domain source to that DNS lookup, and that the resulting URL field is populated rather than empty.

### Device Registration (SAVR-43, Issue 1)
Look for a device completing registration and authentication in the correct order, even when no AI activity has been detected yet.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `registration_test`
- **What it checks:** Confirms six milestones occur in order — fingerprint generated, registration request sent, registration accepted, authentication request sent, authentication accepted, first status report sent — and that every process scan completed before registration reported zero AI processes found.

### Status Report Contents (SAVR-43, Issue 2)
Look for each periodic status report containing all required fields (IP address, hostname, device token, stats, etc.).

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `heartbeat_payload_test`
- **What it checks:** Verifies the status report payload includes all required top-level fields, a valid stats block (CPU, memory, disk usage, uptime), a correctly formatted last-scan timestamp, and a successful server response.

### Detection Record Completeness (SAVR-43, Issue 3)
Look for a detection record on an AI program that's also using the network to include both the process details and the network details together, with nothing missing.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `combined_fields_test`
- **What it checks:** For each detected-agent record in the run window, verifies the event type and detection method are correct, and that all 13 required process- and network-level fields (OS details, logged-in user, network adapters, route table, process metrics, and flow/connection details) are present and non-empty.

### File Monitoring & Filtering (SAVR-16)
Look for the file-monitoring component only capturing activity from AI-related programs (ignoring everything else) and staying within its event-rate, CPU, and memory limits.

- **File:** `tests/SAVR2SAVR16.py`
- **Roster key:** `kernel_file_monitor_test`
- **What it checks:** Confirms the monitoring session starts correctly with the expected provider, that session statistics are logged with zero lost events or buffers, that the event rate stays under the configured limit, that CPU and memory usage stay within budget, that matched (AI-relevant) and dropped (non-AI) file events meet configured expectations, and that the session only stops after the parent service begins shutting down.

## Reading the Results

Each row in the results output gets one of these verdicts:

- **PASS** — worked as expected
- **FAIL** — did not work as expected (a real finding)
- **PARTIAL** — mostly worked, but part of it is missing or incomplete
- **NOT_DETECTED** — the activity we needed to check never happened during this run (usually means rerun with the right setup, not a product problem)
- **INCONCLUSIVE** — not enough information in this run to make a call either way
