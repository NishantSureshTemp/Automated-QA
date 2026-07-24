import re

# Stage 1: ETW TCP connection callback
TCP_CONN_RE = re.compile(
    r"TcpConnectionDetector::OnClassicConnectionEstablished\s+-\s+"
    r"\[TCP_CONN_DETECTOR\]\s+TCP\[v\d\]\s+PID=(?P<pid>\d+)"
)

# Stage 2a: AnomalyPipeline sees a new segment (optional, informational only)
NEW_SEGMENT_RE = re.compile(
    r"AnomalyPipeline::process_flow\s+-\s+\[AnomalyPipeline\]\s+"
    r"New network segment:\s+(?P<seg>\S+)"
)

# Stage 2b: AnomalyPipeline rule fired on a segment
RULE_FIRED_RE = re.compile(
    r"AnomalyPipeline::process_flow\s+-\s+\[AnomalyPipeline\]\s+"
    r"L1 rule (?P<rule>\S+) fired on seg (?P<seg>\S+)"
)

# Stage 3: dispatchFlow -- anomaly handed off for delivery
DISPATCH_RE = re.compile(
    r"SecureAiService::dispatchFlow\s+-\s+\[Anomaly\]\s+"
    r"(?P<category>\S+)\s+rule=(?P<rule>\S+)\s+layer=(?P<layer>\S+)\s+"
    r"sev=(?P<sev>\S+)\s+score=(?P<score>[\d.]+)\s+seg=(?P<seg>\S+)"
)

# Stage 4: OutputModule sends the anomaly batch (JSON output to controller)
OUTPUT_SENT_RE = re.compile(
    r"OutputModule::SenderLoop\s+-\s+\[OUTPUT_MODULE\]\s+"
    r"Sent anomaly batch of (?P<count>\d+) items"
)

TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})")

# how many lines forward we're willing to look for the next stage in the
# chain before declaring that stage missing
MAX_LOOKAHEAD = 500


class PipelineWiringTest:
    name = "pipeline_wiring_test"

    def __init__(self, cfg, agents=None, sysinfo=None):
        self.max_lookahead = cfg.get("max_lookahead", MAX_LOOKAHEAD)
        # seg -> record of what we've seen for that segment
        self.segments = {}
        # keep first TCP connect line index as a rough anchor for "pipeline start"
        self.first_tcp_index = None

    def offer(self, line, i, window):
        if TCP_CONN_RE.search(line) and self.first_tcp_index is None:
            self.first_tcp_index = i

        m = RULE_FIRED_RE.search(line)
        if m:
            seg = m.group("seg")
            key = seg.lower()
            rec = self.segments.setdefault(key, {"display_seg": seg})
            if "rule_fired_idx" not in rec:
                rec["rule_fired_idx"] = i
                rec["rule"] = m.group("rule")
            return

        m = DISPATCH_RE.search(line)
        if m:
            seg = m.group("seg")
            key = seg.lower()
            rec = self.segments.setdefault(key, {"display_seg": seg})
            if "dispatch_idx" not in rec:
                rec["dispatch_idx"] = i
                rec["dispatch_rule"] = m.group("rule")
                rec["sev"] = m.group("sev")
                rec["score"] = m.group("score")
            return

        m = OUTPUT_SENT_RE.search(line)
        if m:
            # OUTPUT_MODULE lines aren't tagged with a seg, so attribute this
            # batch-sent event to any segment that has dispatched but not yet
            # been matched to an output line
            for seg, rec in self.segments.items():
                if "dispatch_idx" in rec and "output_idx" not in rec:
                    if i >= rec["dispatch_idx"] and (i - rec["dispatch_idx"]) <= self.max_lookahead:
                        rec["output_idx"] = i
                        rec["output_count"] = m.group("count")
            return

    def resolve(self):
        self.results = []

        if not self.segments:
            self.results.append((
                "pipeline",
                "TCP_CONN_DETECTOR -> AnomalyPipeline -> dispatchFlow -> OUTPUT_MODULE",
                "", "NOT_DETECTED",
                "no AnomalyPipeline rule-fired or dispatchFlow lines found in "
                "window -- no anomaly occurred to exercise the pipeline",
            ))
            return

        for key, rec in self.segments.items():
            self._score(rec.get("display_seg", key), rec)

    def _score(self, seg, rec):
        failures = []

        rule_idx = rec.get("rule_fired_idx")
        dispatch_idx = rec.get("dispatch_idx")
        output_idx = rec.get("output_idx")

        if rule_idx is None:
            failures.append(
                "dispatchFlow fired with no preceding AnomalyPipeline "
                "rule-fired line -- wiring broken between rule engine and dispatch"
            )
        if dispatch_idx is None:
            failures.append(
                "AnomalyPipeline rule fired but no dispatchFlow line followed -- "
                "wiring broken between rule engine and dispatch"
            )
        elif rule_idx is not None and dispatch_idx < rule_idx:
            failures.append("dispatchFlow appeared before the rule-fired line (out of order)")

        if dispatch_idx is not None and output_idx is None:
            failures.append(
                "dispatchFlow fired but no OUTPUT_MODULE 'Sent anomaly batch' "
                "line followed -- pipeline broke before JSON output stage"
            )
        elif dispatch_idx is not None and output_idx is not None and output_idx < dispatch_idx:
            failures.append("OUTPUT_MODULE batch-sent line appeared before dispatchFlow (out of order)")

        actual_parts = []
        if rule_idx is not None:
            actual_parts.append(f"rule_fired@line{rule_idx} ({rec.get('rule')})")
        if dispatch_idx is not None:
            actual_parts.append(
                f"dispatch@line{dispatch_idx} (rule={rec.get('dispatch_rule')} "
                f"sev={rec.get('sev')} score={rec.get('score')})"
            )
        if output_idx is not None:
            actual_parts.append(f"output_sent@line{output_idx} (batch={rec.get('output_count')} items)")
        actual = "; ".join(actual_parts) if actual_parts else "no stages matched"

        result = "FAIL" if failures else "PASS"
        comment = "; ".join(failures)

        self.results.append((
            seg,
            "AnomalyPipeline rule fired -> dispatchFlow -> OUTPUT_MODULE batch sent, in order",
            actual,
            result,
            comment,
        ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)
