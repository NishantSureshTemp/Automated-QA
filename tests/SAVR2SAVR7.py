import re

CONF_RE = re.compile(
    r"\[SCANNER\]\s+Trusted AI process:\s*(?P<proc>\S+\.exe)\s*"
    r"\(PID\s+(?P<pid>\d+),.*?conf\s+(?P<conf>[0-9.]+)\)",
)

class ConfidenceTest:
    name = "confidence_test"          # roster section key + registry gate

    def __init__(self, cfg):
        self.by_name = cfg.get("by_name", {})     # {"chrome.exe": [lo, hi]}
        self.by_pid  = cfg.get("by_pid", {})      # {"7140": {"label":..., "range":[lo,hi]}}
        self.seen = {}                            # pid -> {"proc", "conf"}; first sighting wins

    # --- per-line matcher (runs during the main loop) ---
    def offer(self, line, i, window):
        m = CONF_RE.search(line)
        if not m:
            return
        pid = m.group("pid")
        if pid in self.seen:          # same PID already counted -> ignore repeat scans
            return
        self.seen[pid] = {"proc": m.group("proc"), "conf": float(m.group("conf"))}

    # --- scoring after EOF (the "surmising" step) ---
    def resolve(self):
        self.results = []             # (subject, expected, actual, result, comment)
        matched_names = set()
        seen_pids = set(self.seen)

        for pid, info in self.seen.items():
            conf, proc = info["conf"], info["proc"]

            if pid in self.by_pid:                        # by-pid wins (more specific)
                entry = self.by_pid[pid]
                lo, hi = entry["range"]
                res = "PASS" if lo <= conf <= hi else "FAIL"
                self.results.append((
                    f'{proc} (PID {pid}, {entry["label"]})',
                    f"{lo}-{hi}", conf, res,
                    "" if res == "PASS" else "confidence outside expected range",
                ))

            elif proc in self.by_name:                    # else fall back to name
                lo, hi = self.by_name[proc]
                res = "PASS" if lo <= conf <= hi else "FAIL"
                matched_names.add(proc)
                self.results.append((
                    f"{proc} (PID {pid})",
                    f"{lo}-{hi}", conf, res,
                    "" if res == "PASS" else "confidence outside expected range",
                ))

        # roster entries that never showed up in the window
        for pid, entry in self.by_pid.items():
            if pid not in seen_pids:
                lo, hi = entry["range"]
                self.results.append((
                    f'PID {pid} ({entry["label"]})',
                    f"{lo}-{hi}", "", "NOT_DETECTED",
                    "no SCANNER confidence line for this PID in the run window",
                ))
        for proc, rng in self.by_name.items():
            if proc not in matched_names:
                lo, hi = rng
                self.results.append((
                    proc, f"{lo}-{hi}", "", "NOT_DETECTED",
                    "no SCANNER confidence line for this name in the run window",
                ))

    # --- emit CSV rows (runner adds nothing, just writes them) ---
    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)