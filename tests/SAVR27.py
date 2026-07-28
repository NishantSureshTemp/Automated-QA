class SAVR27:
    name = "SAVR27"

    def __init__(self, cfg, agents, sysinfo):
        self.results = []
        self.expect_stype  = cfg.get("expect_service_type", "LocalModel")
        self.expect_method = cfg.get("expect_detection_method", "ContainerAnalysis")

        self.agent = next(
            (a for a in (agents or [])
             if a.get("detection_method") == "ContainerAnalysis"
             and "ollama" in a.get("process_path", "").lower()),
            None
        )

    def offer(self, line, i, window):
        pass

    def resolve(self):
        if self.agent is None:
            self.results.append((
                "ollama container detection",
                f"ContainerAnalysis entry in detected_agents.json",
                "absent",
                "NOT_DETECTED",
                "no ContainerAnalysis entry for ollama found in detected_agents.json"
            ))
            return

        failures = []
        actuals  = []

        actual_method = self.agent.get("detection_method", "")
        if actual_method != self.expect_method:
            failures.append(f"detection_method={actual_method} expected {self.expect_method}")
        actuals.append(f"detection_method={actual_method}")

        actual_stype = self.agent.get("service_type", "")
        if actual_stype != self.expect_stype:
            failures.append(f"service_type={actual_stype} expected {self.expect_stype}")
        actuals.append(f"service_type={actual_stype}")

        container = self.agent.get("container")
        if not isinstance(container, dict):
            failures.append("container block absent")
        else:
            actuals.append(f"container_id={container.get('container_id', '?')}")

        self.results.append((
            "ollama container detection",
            f"ContainerAnalysis, service_type={self.expect_stype}",
            ", ".join(actuals),
            "PASS" if not failures else "FAIL",
            "; ".join(failures),
        ))

    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)