# SAVR-16 Test Cases — ETW Kernel-File Monitor (AI Library/Model Detection + PID Allowlist)

Automation: `mytests/SAVR16.py` (class `KernelFileMonitorTest`, roster key `kernel_file_monitor_test`).
The runner discovers it automatically — just make sure the roster section exists.

## What the automation checks

From the log window, per run: session `SecureAIKernelFileMonitor` created; provider GUID = EDD08927 and Event ID = 12; the 7-counter statistics block was logged; Events Lost = 0 and RT Buffers Lost = 0; event rate = Events Received ÷ (Started→stats duration) < 1000/sec; `Matched (path+ext)` ≥ configured minimum; `Dropped (PID filter)` ≥ configured minimum; CPU ≤ 5% and Memory Working Set ≤ 50 MB (configurable); monitor Stopped only after service shutdown began.

Note: the service logs the statistics block when the monitor stops, so every run below **ends with a service stop or restart** — that's what flushes the numbers into the log.

---

## Test Case SAVR16-1 — Idle lifecycle (session, provider, clean stop)

**Purpose:** the checklist Viren did manually — session runs, correct GUID, rate under limit — plus clean stop.

1. Note timestamp X, restart SecureAiService.
2. Let it idle ≥ 60 seconds. Do not generate file activity.
3. Stop (or restart) the service to flush stats. Run the harness with `--start X`.

Roster: `expect_matched_min: 0`, `expect_dropped_min: 0`.
Expected: everything PASS with all counters 0 (matches the ticket screenshots). Verified: replaying the ticket's attached log gives 11/11 PASS.

---

## Test Case SAVR16-2 — AI path events fired (positive filter test)

**Purpose:** acceptance criterion "AI path events correctly fired."

1. Note timestamp X, restart the service.
2. Ensure an allowlisted AI process is running (e.g. python.exe with an AI library loaded — check for the `AI process added pid-image` line, which confirms it's in AI_PROCESS_SET).
3. From that process, write files that hit **both** filters — a watched path AND a watched extension. Practical options:
   - `pip install` a wheel containing `.pyd` files → lands in `site-packages`
   - `ollama pull <small model>` → writes `.gguf` under `.ollama/models`
   - a python script that downloads a model via huggingface → `.cache/huggingface`, `.safetensors`/`.bin`
4. Stop/restart the service. Run the harness.

Roster for this run: `expect_matched_min: 1` (or the count you expect).
Expected: `Matched (path+ext) ≥ 1` PASS. FAIL here means the filters or the allowlist wiring are broken.

---

## Test Case SAVR16-3 — PID allowlist first-line drop (negative filter test)

**Purpose:** "FIRST LINE: PID allowlist check → drop if not in AI_PROCESS_SET."

1. Note timestamp X, restart the service.
2. From a process that is **not** an AI process (plain notepad, powershell, explorer copy), write/copy files into the same watched paths with watched extensions (e.g. copy a dummy `.gguf` into `.ollama\models`).
3. Stop/restart the service. Run the harness.

Roster for this run: `expect_dropped_min: 1`, `expect_matched_min: 0`.
Expected: `Dropped (PID filter) ≥ 1` and `Matched = 0` — proving non-AI events are cut at the first line and never reach the path/extension matching.

---

## Test Case SAVR16-4 — Volume + performance under full workload

**Purpose:** acceptance "event rate < 1000/sec under full workload" + the ticket's CPU/memory observation task.

1. Note timestamp X, restart the service.
2. Generate heavy file activity for ≥ 5 minutes: large `pip install`s, model downloads, plus heavy non-AI file churn (big folder copies) to stress the first-line filter.
3. Stop/restart the service. Run the harness.

Expected: event rate < 1000/sec PASS; Events Lost = 0 and RT Buffers Lost = 0 PASS; CPU ≤ 5% and Memory ≤ 50 MB PASS (tune `max_cpu_pct` / `max_memory_kb` in the roster to whatever your team agrees the budget is).

---

## Roster reference

```json
"kernel_file_monitor_test": {
  "expected_provider": "EDD08927",
  "expected_event_id": 12,
  "max_event_rate_per_sec": 1000,
  "require_zero_lost": true,
  "max_cpu_pct": 5.0,
  "max_memory_kb": 51200,
  "expect_matched_min": 0,
  "expect_dropped_min": 0
}
```

Flip `expect_matched_min` / `expect_dropped_min` per scenario (SAVR16-2 and SAVR16-3). Everything else stays constant.

## Result semantics
PASS = requirement met. FAIL = seen but wrong (real finding). NOT_DETECTED = the monitor's lines never appeared in the window — window started too late, service wasn't restarted (stats flush on stop), or the build doesn't have the feature (e.g. the June-25 baseline log).

## Known limitation
The log's stats block is aggregate counters, not per-file lines, so the automation can't verify *which* path/extension matched — only that the expected number of matches/drops occurred. The scenario design (only touch one filter category per run) is what makes the counters meaningful. If the developers add per-event debug lines later, we can tighten this.
