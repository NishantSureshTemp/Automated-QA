# My Test Harness

Personal log-based test harness for the Anomaly Detection Engine.
Same design as the shared overall.py, but self-owned and with automatic
test discovery — the runner never needs editing.

## Folder layout

```
harness/
  runner.py            <- the runner. Never edit for new tickets.
  roster.json          <- settings: which tests run + what they expect
  mytests/
    _common.py         <- shared helpers (JSON extraction, log regexes)
    SAVR-43/           <- one folder per Jira ticket
      SAVR43.py                    (test classes - auto-discovered)
      SAVR43_TestCases.md          (manual procedure)
      roster_savr43.json           (this ticket's roster sections)
      _standalone_run_savr43.py    (optional self-contained runner)
    SAVR-16/
      SAVR16.py
      SAVR16_TestCases.md
```

Discovery is recursive: any .py under mytests/ (at any depth) is
scanned for test classes. Files starting with `_` are skipped - use
that prefix for helpers and standalone scripts.

## Running

```
python runner.py --start "2026-07-13 14:00:00.000"
```

Snapshots the live SecureAiService.log, keeps only entries at/after
--start, feeds them through every enabled test, writes results.csv.

Useful options:

| option | meaning |
|---|---|
| `--log path` | use a specific log file instead of the live one |
| `--no-snapshot` | read the file directly (offline replay of a copy) |
| `--roster path` | use a different settings file |
| `--out path` | name the results CSV |
| `--list` | show discovered tests and whether the roster enables them |

Read the CSV: PASS = expectation met. FAIL = seen but wrong (a real
finding). NOT_DETECTED = the activity never appeared in the window —
usually means the window/scenario was wrong, not the product.

## Adding a new Jira ticket

1. Create a folder `mytests/SAVR-xx/` and put `SAVRxx.py` in it
   (plus the ticket's docs). One class per check. Contract:

```python
class MyNewTest:
    name = "my_new_test"              # roster key
    def __init__(self, cfg): ...      # receives its roster section
    def offer(self, line, i, window): # called for every log line
    def resolve(self): ...            # score after the last line
    def rows(self): ...               # yield (test, subject, expected,
                                      #        actual, result, comment)
```

2. Add a `"my_new_test": { ... }` section to roster.json.
3. `python runner.py --list` to confirm it shows ENABLED. Done.

No section in roster.json = test skipped. That's the on/off switch.

Shared regexes/helpers live in `mytests/_common.py` (scanner confidence
lines, TCP connect lines, DNS query lines, payload-JSON extraction) —
import from there instead of re-writing them per ticket.

## Compatibility with the shared harness

Test classes use the exact same contract as the team's overall.py, so
a file from mytests/ can be dropped into their tests/ folder (adjust
the `from mytests._common import ...` line to local definitions) and
vice versa.

## SAVR-43 specifics

Enabled tests: registration_test (Issue 1), heartbeat_payload_test
(Issue 2), combined_fields_test (Issue 3). For Issue 3, put the paths
of captured agent_detected event JSONs into the roster's
`event_files` list (or a folder into `event_dir`) before running.
When the Swagger renames land, update the heartbeat section of
roster.json (stats_key -> "system_stats", cpu_usage/memory_usage,
last_scan_time_format -> "iso8601") — no code changes.
