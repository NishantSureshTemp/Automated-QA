import argparse, shutil, csv, re
from pathlib import Path
import json
from tests.SAVR2SAVR7 import ConfidenceTest #01
from tests.SAVR2SAVR14 import TcpStatsTest #08
from tests.SAVR2SAVR13 import ScanLatencyTest #09
from tests.SAVR2SAVR18 import DnsCorrelationTest #05
from tests.SAVR2SAVR15 import SchannelTest #07
import subprocess

#python overall.py --start "2026-07-02 16:00:00.049" --roster roster.json --out results.csv

TEST_CLASSES = [ConfidenceTest, TcpStatsTest, ScanLatencyTest, DnsCorrelationTest, SchannelTest]

LOG_PATH = Path(r"C:\Windows\System32\config\systemprofile\AppData\Local\Cybersenz\SecureAiService\Logs\SecureAiService.log")


def get_pids_by_name(proc_name):
    result = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {proc_name}", "/FO", "CSV", "/NH"],
        capture_output=True, text=True
    )
    pids = []
    for line in result.stdout.strip().splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 2:
            pids.append(parts[1])
    return pids

def build_tests(roster_path):
    if roster_path is None:
        return []
    cfg = json.loads(roster_path.read_text())

    # auto-resolve tcp_stats_test by_name entries into by_pid using live tasklist
    if "tcp_stats_test" in cfg:
        tcp_cfg = cfg["tcp_stats_test"]
        for proc_name, domain in tcp_cfg.get("by_name", {}).items():
            pids = get_pids_by_name(proc_name)
            for pid in pids:
                tcp_cfg["by_pid"][pid] = {"label": proc_name, "domain": domain}
        tcp_cfg["by_name"] = {}   # clear so Test2 doesn't double-process them

    return [cls(cfg[cls.name]) for cls in TEST_CLASSES if cls.name in cfg]

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--start", required=True,
                   help="Run-start timestamp, e.g. '2026-06-25 08:13:00.000'")
    p.add_argument("--out", default="results.csv", type=Path)
    p.add_argument("--roster", type=Path,
                   help="JSON of expected subjects -> conf range")
    # roster shape:
    # {
    #   "confidence_test": {
    #     "by_name": { "chrome.exe": [0.0, 0.50] },
    #     "by_pid":  { "7140": {"label": "python+openai", "range": [0.80, 1.0]},
    #                  "7141": {"label": "python plain",  "range": [0.0, 0.50]} }
    #   }
    # }
    return p.parse_args()

def snapshot(log_path: Path) -> Path:
    # copy first so the growing file can't change under us
    snap = log_path.with_suffix(".snapshot")
    shutil.copy2(log_path, snap)
    return snap

timestamp_re = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})")

def load_window(snap: Path, start: str) -> list[str]:
    lines = snap.read_text(encoding="utf-8", errors="replace").splitlines()
    out, started = [], False
    for line in lines:
        m = timestamp_re.match(line)
        if not started:
            if m and m.group(1) >= start:   # >= not ==, string compare is safe for this format
                started = True
            else:
                continue
        out.append(line)
    return out   # indexable array; multi-line matchers can peek forward

def run(window, tests):
    for i, line in enumerate(window):
        for t in tests:
            t.offer(line, i, window)   # test decides if it bites; can peek window[i+1:]
    for t in tests:
        t.resolve()                    # the "surmising" step: score no-shows, etc.

def write_report(tests, out: Path):
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["test", "subject", "expected", "actual",
                    "result", "comments"])
        for t in tests:
            for row in t.rows():       # each test emits its own rows
                w.writerow(row)

def main():
    a = parse_args()
    snap = snapshot(LOG_PATH)
    window = load_window(snap, a.start)
    tests = build_tests(a.roster)      # registry of test instances
    run(window, tests)
    write_report(tests, a.out)

if __name__ == "__main__":
    main()