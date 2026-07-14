"""
runner.py - your own overall-style test harness.

Same idea as the shared overall.py, with one improvement: it discovers
test classes automatically from the mytests/ folder, so adding a new
Jira ticket means dropping a new file in mytests/ and adding a section
to roster.json. You never edit this runner.

Usage:
    python runner.py --start "2026-07-13 14:00:00.000"
    python runner.py --start "..." --roster roster.json --out results.csv
    python runner.py --log copy.log --no-snapshot --start "..."
    python runner.py --list                    (show discovered tests)

How a test gets picked up:
  1. Its class lives in any .py file inside mytests/ (filename doesn't
     matter; one file per Jira ticket is the convention).
  2. The class has:  name (str), __init__(cfg), offer(line, i, window),
     resolve(), rows()  - the same contract as the shared harness, so
     test files move between the two without changes.
  3. roster.json contains a section whose key equals the class's name.
     No section = test is skipped for that run.
"""

import argparse
import csv
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTS_DIR = HERE / "mytests"
DEFAULT_LOG = Path(r"C:\Windows\System32\config\systemprofile\AppData"
                   r"\Local\Cybersenz\SecureAiService\Logs\SecureAiService.log")

_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})")


# ------------------------------------------------------------------ discovery

def discover_test_classes(tests_dir: Path) -> list:
    """Import every .py in mytests/ (except _*.py) and collect classes
    that implement the test contract."""
    classes, seen_names = [], {}
    if not tests_dir.is_dir():
        raise SystemExit(f"tests folder not found: {tests_dir}")
    # recursive: test files can live in per-ticket subfolders,
    # e.g. mytests/SAVR-16/SAVR16.py
    for py in sorted(tests_dir.rglob("*.py")):
        if py.name.startswith("_") or "__pycache__" in py.parts:
            continue
        spec = importlib.util.spec_from_file_location(f"mytests.{py.stem}", py)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        for obj in vars(mod).values():
            if (isinstance(obj, type)
                    and isinstance(getattr(obj, "name", None), str)
                    and callable(getattr(obj, "offer", None))
                    and callable(getattr(obj, "resolve", None))
                    and callable(getattr(obj, "rows", None))):
                if obj.name in seen_names:
                    # same class re-exported/imported elsewhere: keep first
                    if seen_names[obj.name] is not obj:
                        print(f"WARNING: duplicate test name '{obj.name}' "
                              f"in {py.name}; keeping the first one found")
                    continue
                seen_names[obj.name] = obj
                classes.append(obj)
    return classes


# ------------------------------------------------------------------ log window

def snapshot(log_path: Path) -> Path:
    """Copy the live log first so it can't grow or rotate mid-read."""
    snap = log_path.with_suffix(".snapshot")
    shutil.copy2(log_path, snap)
    return snap


def load_window(src: Path, start: str) -> list:
    """Return log lines at/after `start`. Tolerant of mixed encodings
    and the service's \r\r\n line endings."""
    text = src.read_bytes().decode("utf-8", errors="replace")
    out, started = [], False
    for line in text.replace("\r", "").split("\n"):
        m = _TIMESTAMP_RE.match(line)
        if not started:
            if m and m.group(1) >= start:  # string compare is safe for this format
                started = True
            else:
                continue
        if line.strip():
            out.append(line)
    return out


# ------------------------------------------------------------------ run/report

def build_tests(roster: dict, classes: list) -> list:
    return [cls(roster[cls.name]) for cls in classes if cls.name in roster]


def run(window, tests):
    for i, line in enumerate(window):
        for t in tests:
            t.offer(line, i, window)   # tests may peek window[i+1:]
    for t in tests:
        t.resolve()


def write_report(tests, out: Path):
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["test", "subject", "expected", "actual",
                    "result", "comments"])
        for t in tests:
            for row in t.rows():
                w.writerow(row)


# ------------------------------------------------------------------ cli

def parse_args():
    p = argparse.ArgumentParser(description="Personal log-based test harness")
    p.add_argument("--start",
                   help="Run-start timestamp, e.g. '2026-06-03 16:52:00.000'")
    p.add_argument("--log", type=Path, default=DEFAULT_LOG,
                   help="Path to SecureAiService.log (default: live log)")
    p.add_argument("--roster", type=Path, default=HERE / "roster.json",
                   help="Roster JSON (default: roster.json next to runner)")
    p.add_argument("--out", type=Path, default=Path("results.csv"))
    p.add_argument("--no-snapshot", action="store_true",
                   help="Read the log directly (offline replay of a copy)")
    p.add_argument("--list", action="store_true",
                   help="List discovered tests and whether the roster "
                        "enables them, then exit")
    return p.parse_args()


def main():
    a = parse_args()
    classes = discover_test_classes(TESTS_DIR)

    roster = {}
    if a.roster.exists():
        roster = json.loads(a.roster.read_text(encoding="utf-8"))

    if a.list:
        print(f"discovered {len(classes)} test class(es) in {TESTS_DIR}:")
        for cls in classes:
            state = "ENABLED" if cls.name in roster else "disabled (no roster section)"
            print(f"  {cls.name:28s} [{cls.__name__}]  {state}")
        return

    if not a.start:
        raise SystemExit("--start is required (or use --list)")
    if not roster:
        raise SystemExit(f"roster not found or empty: {a.roster}")
    if not a.log.exists():
        raise SystemExit(f"log file not found: {a.log}")

    tests = build_tests(roster, classes)
    if not tests:
        raise SystemExit("no tests enabled: no roster section matches any "
                         "discovered test name (run with --list to check)")

    src = a.log if a.no_snapshot else snapshot(a.log)
    window = load_window(src, a.start)
    if not window:
        raise SystemExit(
            f"no log entries at/after --start {a.start!r}; check the "
            "timestamp format (YYYY-MM-DD HH:MM:SS.mmm) and the log's range")

    run(window, tests)
    write_report(tests, a.out)

    counts = {}
    for t in tests:
        for row in t.rows():
            counts[row[4]] = counts.get(row[4], 0) + 1
    total = sum(counts.values())
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"{len(tests)} test(s), {total} checks -> {summary}")
    print(f"report written to {a.out}")


if __name__ == "__main__":
    main()
