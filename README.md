# Anomaly Detection Engine — Test Case Documentation

## Setup And Running the Suite

### Prerequisites
- SecureAiService must be installed and running
- Python 3.x with `requests`, `torch` packages installed
- PowerShell available (for Schannel fixture)
- Docker Desktop installed and running (for container detection tests)
- `curl` available on PATH (for OpenAI fixture)
- Run as Administrator (required for service restart via `net stop/start`)
- At least 7GB RAM allocated to Docker Desktop's Hyper-V VM (configure in Docker Desktop → Settings → Resources → Memory)
- `C:\models\tinyllama.gguf` present on disk (download from HuggingFace TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF)

### Automated Setup
The suite is fully automated via `setup.py`. A single command handles service restart, fixture launch, roster patching, and suite execution:

```
python setup.py
```

`setup.py` performs the following steps in order:

1. Records the start timestamp (intentionally before service restart, to capture the full shutdown/startup lifecycle)
2. Restarts SecureAiService (`net stop` then `net start`) to exercise the registration sequence and ETW session startup
3. Launches the httpbin fixture as a background process and patches `roster.json` with the live PID
4. Launches the chatgpt fixture for DNS/TCP correlation testing
5. Patches `roster.json` with the live httpbin PID
6. Launches the python+torch fixture as a background process for library detection and module enumeration tests, and patches `roster.json` with the live PID
7. Launches the OpenAI curl fixture for TCP connect testing and patches `roster.json` with the live PID
8. Launches the Anthropic fixture for IPv6 TCP testing
9. Waits for Docker to be ready, then pulls required images (`ollama/ollama`, `nginx`, `python:3.11`, `n8nio/n8n`)
10. Launches five Docker containers: `ollama_mount_test` (with model volume), `nginx_test`, `langchain_test`, `n8n_test`, `pyai_test`
11. Waits 120 seconds for scanner poll cycles, registration attempts, DNS cache refresh, and container detection
12. Runs two Schannel fixtures via PowerShell (`copilot.microsoft.com`, `chat.openai.com`)
13. Waits 20 seconds for TLS events to appear in the log
14. Invokes `overall.py` with the recorded start timestamp
15. Terminates all fixtures and cleans up Docker containers

Total runtime is approximately 280 seconds.

### Manual Run
If running `overall.py` directly without `setup.py`:

1. Launch httpbin fixture and note the PID:
```
python -c "import requests, time, os; print(f'PID: {os.getpid()}', flush=True); [requests.get('https://httpbin.org/get') or time.sleep(30) for _ in range(20)]"
```
2. Launch python+torch fixture and note the PID:
```
python -c "import torch, time, os; print(f'PID: {os.getpid()}', flush=True); time.sleep(300)"
```
3. Launch curl fixture and note the PID:
```
curl https://openai.com
```
4. Update `roster.json` `tcp_stats_test.by_pid` with the httpbin PID, `SAVR12.by_pid` with the curl PID, and `SAVR17.expected_agents[0].pid` with the python PID
5. Launch Docker containers:
```
docker run -d --name ollama_mount_test -v C:\models:/models ollama/ollama
docker run -d --name nginx_test nginx
docker run -d --name langchain_test python:3.11 python -c "import time; time.sleep(300)  # langchain"
docker run -d --name n8n_test n8nio/n8n
docker run -d --name pyai_test -e OPENAI_API_KEY=sk-test1234567890abcdef python:3.11 python -c "import time; time.sleep(300)  # langchain"
```
6. Run Schannel fixtures in PowerShell:
```powershell
Invoke-WebRequest -Uri "https://copilot.microsoft.com" -UseBasicParsing
Invoke-WebRequest -Uri "https://chat.openai.com" -UseBasicParsing
```
7. Wait 120 seconds then run:
```
python overall.py --start "YYYY-MM-DD HH:MM:SS.000" --roster roster.json --out results.csv
```
Set `--start` to just before you launched your fixtures.

### Known Environment Limitations
- **License limit exceeded** — the controller is rejecting registration with `"License limit exceeded"`. This blocks `registration_test` auth milestones and `heartbeat_payload_test` entirely until resolved on the controller side.
- **kernel_file_monitor_test** — stats, CPU, memory, and stop rows only appear when a service shutdown occurs within the run window. These rows will show NOT_DETECTED on normal runs. Additionally, the feature is not present in all builds — if no `SecureAIKernelFileMonitor` lines appear in the log at all, the feature is compiled out of the current build.
- **Docker Desktop memory** — Docker Desktop requires at least 2GB for its Hyper-V VM. On machines with limited RAM, reduce other running processes before starting Docker. The VM memory allocation can be configured in Docker Desktop → Settings → Resources → Memory; 7GB is recommended when the host has 16GB.
- **RTT always 0** — the service logs `rtt=0ms` on all TCP connect lines in the current build. This is a known defect and causes SAVR-14 to FAIL on the RTT check regardless of fixture behavior.
- **Event-driven dispatch not implemented** — the scanner runs on a fixed poll interval (25–40 seconds) and does not react to ETW process-added events. SAVR-13 will FAIL on all three checks until this is implemented.
- **DNS cache inserts absent** — `DnsCache::Insert` lines are not present in the current build's log, meaning the IP-to-domain cache is not being populated. SAVR-5's insert and IP cache lookup checks will FAIL until this is fixed.
- **Model mount detection** — the service detects ollama containers and boosts confidence to 1.0 when a model is actively loaded, but does not populate `model_mounts` in the agent entry. SAVR-27/28's model mount check will FAIL until this is implemented.
- **n8n confidence threshold** — a bare n8n container without active OpenAI API calls produces `confidence=0.50`, below the required 0.60 threshold. Reaching 0.60 requires the container to make actual OpenAI API calls.
- **M365Copilot persistence** — M365Copilot.exe is detected in the log with conf 0.95 but is not persisted to `detected_agents.json`. This is a confirmed product bug.

## Test Cases Covered

### DNS Cache and Localhost Resolution (SAVR-5)
Look for the DNS cache thread running, IP-to-domain mappings being inserted, localhost connections being correctly resolved, and ollama's endpoint being identified as localhost.

- **File:** `tests/SAVR2SAVR5.py`
- **Roster key:** `SAVR5` (empty object `{}` is sufficient)
- **What it checks:**
  - `DnsCache::TimerCallback` line present in log confirming the cache thread is running (fires every ~5 minutes; window must be long enough to capture a cycle)
  - `DnsCache::Insert` lines present confirming IP-to-domain mappings are being cached (currently absent — known gap in this build)
  - TCP connect line to `127.0.0.1` with `domain=localhost` confirming localhost mapping works
  - ollama's `endpoint` field in `detected_agents.json` contains `localhost:11434`
  - `DnsCacheLookup` lines with `source=ip_cache` confirming cache is used for domain correlation (currently absent — known gap in this build)
- **Known limitations:** DNS cache insert and IP cache lookup checks will FAIL on this build as the feature is not logging these operations

### AI Module Enumeration (SAVR-6)
Look for each detected AI process having its loaded DLL libraries correctly enumerated and recorded in the agent database.

- **File:** `tests/SAVR2SAVR11.py`
- **Roster key:** `module_enum_test`
- **What it checks:**
  - For each process in `expected_agents`: verifies an entry exists in `detected_agents.json` and that `loaded_ai_libraries` contains the expected library names (matched by `lib_name` field)
  - For processes with no expected libraries (e.g. native binaries like ollama.exe): verifies the field is present
  - For processes with expected libraries (e.g. python+torch): verifies `detection_method` is `LibraryAnalysis`
  - Flags any agent in `detected_agents.json` with a non-empty `loaded_ai_libraries` not covered by the roster
- **Fixture required:** python+torch fixture must be running during the scanner poll cycle

### AI Process Confidence Scoring (SAVR-7)
Look for whether known AI programs get correct confidence scores, are persisted to the agent database, and that non-AI system processes are correctly excluded.

- **File:** `tests/SAVR2SAVR7.py`
- **Roster key:** `confidence_test`
- **Config dependency:** reads `config.json` at runtime for whitelist confidence values, service types, and system process exclusions
- **What it checks:**
  - For each process in `expected_agents`: verifies scanner assigns a confidence score within the configured range, and that the entry is correctly persisted to `detected_agents.json`
  - For each process in `library_processes`: verifies the scanner detects the process via LibraryAnalysis
  - Cross-checks each JSON entry's confidence against the whitelist configured value in `config.json`
  - Verifies no processes from `exclusions.system_processes` in `config.json` appear in `detected_agents.json`
  - Verifies all JSON entries are above `minimum_confidence_threshold` from `config.json`
  - Flags unexpected entries in `detected_agents.json` not covered by the roster, with prefix-based exclusion for known container processes (`/bin/`, `python -c`) and deduplication across accumulated runs
- **Roster note:** add `"known_container_processes": ["/bin/", "python -c"]` to suppress expected Docker fixture entries from the unexpected entries check

### Process Token Properties (SAVR-9)
Look for each detected AI process having correct user SID, token type, privileges, integrity level, and elevation status recorded in sysinfo.

- **File:** `tests/SAVR2SAVR9.py`
- **Roster key:** `SAVR-9`
- **What it checks:**
  - For each process in `expected_agents`: finds the matching entry in the latest `sysinfo.jsonl` snapshot's `agent_process_info` array
  - Verifies `user_sid` is non-empty, `privileges` is non-empty, `token_type` is `Primary`
  - Verifies `integrity_level` and `is_elevated` match expected values from the roster
  - Reports PASS/PARTIAL/FAIL based on how many fields match

### TCP Connect Fixture (SAVR-12)
Look for a TCP connection from a specific PID to a specific domain being logged correctly.

- **File:** `tests/SAVR2SAVR12.py`
- **Roster key:** `SAVR12`
- **What it checks:** For the PID and domain configured in `by_pid`, verifies a TCP connect line appears in the log with matching PID and domain
- **Setup:** `setup.py` automatically patches `by_pid` with the live curl PID each run

### Scan Speed / Responsiveness (SAVR-13)
Look for the engine reacting to a new AI process within 50ms, instead of waiting for its next scheduled scan.

- **File:** `tests/SAVR2SAVR13.py`
- **Roster key:** `scan_latency_test` (no roster configuration required)
- **What it checks:** Measures the time gap between an AI process ETW event and the next scan. Also profiles the overall scan interval pattern to distinguish event-driven dispatch (sub-5-second gaps) from a fixed polling loop (25–40 second gaps). Acceptance threshold: latency under 50ms.
- **Known limitations:** event-driven dispatch is not implemented in the current build; all three checks will FAIL

### Network Connection Stats (SAVR-14)
Look for accurate data-sent, data-received, and connection-speed numbers logged for an AI program's network connections.

- **File:** `tests/SAVR2SAVR14.py`
- **Roster key:** `tcp_stats_test`
- **What it checks:** For each expected process (matched by name or PID), verifies at least one logged TCP connection snapshot has non-zero bytes sent, non-zero bytes received, and a non-zero round-trip time simultaneously.
- **Known limitations:** RTT is always 0 in the current build — the test will FAIL on the RTT check regardless of fixture behavior. Bytes are captured correctly on connections with actual data transfer.

### Encrypted Connection Detection (SAVR-15)
Look for the domain, TLS version, and cipher being correctly captured for a secure connection made by an AI program.

- **File:** `tests/SAVR2SAVR15.py`
- **Roster key:** `schannel_test`
- **What it checks:** For each domain in the roster, verifies the captured TLS event includes SNI, TLS version, and cipher. Key exchange method and ALPN are checked as secondary fields.
- **Known limitations:** `kex` field returns `?(255)` (unresolved) and `alpn` is never captured in the current build. Both domains will produce PARTIAL rather than PASS until these are fixed. Requires PowerShell/.NET fixtures — Chrome/Edge use their own TLS stack and bypass Schannel.

### File Monitoring & Filtering (SAVR-16)
Look for the file-monitoring component only capturing activity from AI-related programs and staying within its resource limits.

- **File:** `tests/SAVR2SAVR16.py`
- **Roster key:** `kernel_file_monitor_test`
- **What it checks:** Confirms the monitoring session starts correctly, session statistics are logged with zero lost events, event rate stays under the configured limit, CPU and memory usage stay within budget, and the session only stops after the parent service begins shutting down.
- **Known limitations:** feature is not present in all builds. If no `SecureAIKernelFileMonitor` lines appear in the full log (not just the window), the feature is compiled out of the current build and all rows will show NOT_DETECTED.

### AI Library and Module Detection (SAVR-17)
Look for the process module scanner and main scanner agreeing on the number of AI libraries loaded by a process.

- **File:** `tests/SAVR2SAVR17.py`
- **Roster key:** `SAVR-17`
- **What it checks:**
  - Finds the target process in `detected_agents.json` by `process_name` and `library_name`
  - Searches the log for `[PROCMOD]` and `[SCANNER]` lines matching the PID from the roster
  - Verifies both lines are present and that the module counts match
- **Setup:** `setup.py` automatically patches `expected_agents[0].pid` with the live python+torch fixture PID each run

### Domain Lookup Correlation (SAVR-18)
Look for a domain lookup (DNS query) being correctly linked to the connection that follows it.

- **File:** `tests/SAVR2SAVR18.py`
- **Roster key:** `dns_correlation_test`
- **What it checks:** For each domain in the roster, confirms a successful DNS resolution is followed by a TCP connection line with `source=dns_etw` and a populated URL field.
- **Known limitations:** `chatgpt.com` consistently produces PARTIAL — DNS resolution is captured but the TCP connect is not correlated, likely due to CDN redirection. This is a product-side IP-to-domain cache gap.

### Anomaly Pipeline (SAVR-29)
Look for the full anomaly detection pipeline firing in order: rule triggered, dispatched, and output sent.

- **File:** `tests/SAVR2SAVR29.py`
- **Roster key:** `anomaly_pipeline_test`
- **What it checks:** For each anomaly segment observed in the log, verifies the pipeline stages appear in order — `AnomalyPipeline` rule fired, `dispatchFlow` called, `OutputModule` batch sent. Reports FAIL if the pipeline breaks before the output stage.
- **Known limitations:** the OUTPUT_MODULE batch send stage is not firing in the current build after dispatchFlow — the pipeline breaks before JSON output.

### Performance Baseline (SAVR-40)
Look for the service staying within CPU, memory, and I/O budgets during normal operation.

- **File:** `tests/SAVR2SAVR40.py`
- **Roster key:** `SAVR40`
- **What it checks:** Samples the service's resource usage across the run window and verifies average CPU stays below 3%, total I/O reads stay below 100MB, and memory growth slope stays below 500 KB/hr.
- **Known limitations:** memory slope may exceed threshold during startup as the service initializes its data structures. The current build shows ~1727 KB/hr slope which exceeds the 500 KB/hr threshold.

### Device Registration (SAVR-43, Issue 1)
Look for a device completing registration and authentication in the correct order, even when no AI activity has been detected yet.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `registration_test`
- **What it checks:** Confirms six milestones occur in order — fingerprint generated, registration request sent, registration accepted, authentication request sent, authentication accepted, first heartbeat sent — and that every process scan completed before registration reported zero AI processes found.
- **Known limitations:** currently blocked by license limit exceeded on the controller. Registration returns `success=false` which prevents auth and heartbeat from running.

### Status Report Contents (SAVR-43, Issue 2)
Look for each periodic status report containing all required fields.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `heartbeat_payload_test`
- **What it checks:** Verifies the heartbeat payload includes all required fields, a valid stats block, a correctly formatted last-scan timestamp, and a successful server response.
- **Known limitations:** currently blocked by license limit exceeded — heartbeat never fires if registration fails.

### Detection Record Completeness (SAVR-43, Issue 3)
Look for a detection record on an AI program that's also using the network to include both process details and network details together.

- **File:** `tests/SAVR2SAVR43.py`
- **Roster key:** `combined_fields_test`
- **What it checks:** For each detected-agent record in the run window, verifies all 13 required process- and network-level fields are present and non-empty.
- **Known limitations:** all 13 combined fields are absent from every agent entry in the current build — confirmed Issue 3 regression. Additionally, `event_type` field is not persisted to `detected_agents.json`. The test produces many rows due to accumulated entries from repeated runs; this will be addressed by filtering on `first_detected` in a future update.

### Container Detection (SAVR-27/28)
Look for Docker containers running AI workloads being correctly detected, classified, and distinguished from non-AI containers.

- **File:** `tests/SAVR2SAVR27a28.py`
- **Roster key:** `SAVR27a28`
- **What it checks:**
  - `ollama_mount_test` — detected via `ContainerAnalysis`, `service_type=LocalModel`, `confidence>=0.85`, `.gguf` volume mount present in `model_mounts`
  - `nginx_test` — correctly NOT forwarded to the detection engine
  - `langchain_test` — `cmd_match=1` confirmed in log via `[DOCKER]` line with `pattern=langchain`
  - `n8n_test` — `service_type=WorkflowAutomation`, `confidence>=0.60`
  - `pyai_test` — `service_type=PythonAIAgent`, `env_api_keys_mask!=0` confirming `OPENAI_API_KEY` env var was detected
- **Known limitations:**
  - `model_mounts` is never populated even when a `.gguf` file is present and actively loaded — confirmed product gap
  - n8n confidence is 0.50 without active OpenAI API calls, below the 0.60 threshold — tabled pending fixture complexity
  - `cmd_match` and `image_match` flags are logged but not persisted to `detected_agents.json` — known gap

## Roster Configuration

The roster (`roster.json`) controls which processes, domains, and fields each test asserts on. It is the single place to configure expected values for a given environment.

Each test has its own top-level key in the roster. If a key is absent, that test is skipped entirely. An empty object `{}` enables the test with default settings.

The following fields are automatically patched by `setup.py` on every run — do not manually edit them as they will be overwritten:

- `tcp_stats_test.by_pid` — httpbin fixture PID
- `SAVR12.by_pid` — curl/openai fixture PID
- `SAVR17.expected_agents[0].pid` — python+torch fixture PID

Fields that are environment-specific and may need updating between VMs or builds:

- `confidence_test.config_path` — path to `config.json` on the target machine
- `confidence_test.expected_agents` — processes expected to be running and detected; add or remove entries to match what is installed
- `confidence_test.known_container_processes` — list of process name prefixes to exclude from the unexpected entries check (e.g. `["/bin/", "python -c"]`)
- `dns_correlation_test.domains` — domains to verify DNS+TCP correlation for
- `schannel_test.domains` — TLS domains to verify; must be reachable via PowerShell/.NET
- `heartbeat_payload_test` — required fields and stats keys; update if the heartbeat payload schema changes
- `kernel_file_monitor_test` — provider GUID and event ID; update if the ETW provider changes
- `module_enum_test.expected_agents` — processes to check for library enumeration
- `SAVR27a28.expect_container_name` — name of the ollama Docker container to check (default: `ollama_mount_test`)
- `SAVR27a28.expect_model_mount` — expected `.gguf` mount path (default: `/models/tinyllama.gguf`)

## Reading the Results

Each row in the results output gets one of these verdicts:

- **PASS** — worked as expected
- **FAIL** — did not work as expected (a real finding)
- **PARTIAL** — mostly worked, but part of it is missing or incomplete
- **NOT_DETECTED** — the activity we needed to check never happened during this run (usually means rerun with the right setup, not a product problem)
- **INCONCLUSIVE** — not enough information in this run to make a call either way

## Known Product Bugs (Current Build)

The following are confirmed product bugs rather than test or environment issues:

- **M365Copilot.exe not persisted** — detected in log at conf 0.95 but never written to `detected_agents.json`
- **RTT always 0** — `rtt=0ms` on all TCP connect lines regardless of actual latency
- **Event-driven dispatch not implemented** — scanner uses poll-only mode, ignoring ETW process-added events
- **DNS cache inserts absent** — IP-to-domain cache not being populated in this build
- **model_mounts not populated** — container model mount detection not implemented
- **cmd_match/image_match not persisted** — logged in `[DOCKER]` lines but not written to `detected_agents.json`
- **Issue 3 regression** — combined process+flow fields absent from all agent entries
- **OUTPUT_MODULE batch not sent** — anomaly pipeline breaks before JSON output stage
- **kex unresolved** — TLS key exchange algorithm code 255 not mapped to a name
- **alpn not captured** — ALPN field not extracted from TLS handshake
