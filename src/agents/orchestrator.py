from src.agents.planner import PlannerAgent
from src.agents.analyst import AnalystAgent

class GhostWatchAgent:

    def __init__(self, scanner):
        self.scanner = scanner
        self.planner = PlannerAgent()
        self.analyst = AnalystAgent()

    def run(self, target_url: str, target_info: dict):

        plan = self.planner.create_plan(target_info)

        all_findings = []

        for phase, probes in plan.items():
            for probe in probes:

                # THIS assumes your scanner already has this function
                findings = self.scanner.run_probe(target_url, probe)

                all_findings.extend(findings)

        analysis = self.analyst.analyze(all_findings)

        return {
            "plan": plan,
            "findings": all_findings,
            "analysis": analysis
        }
