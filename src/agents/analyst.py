class AnalystAgent:

    def analyze(self, findings: list):

        risk_score = 0
        attack_chain = []

        for f in findings:

            if "prompt_injection" in f.get("type", ""):
                risk_score += 30
                attack_chain.append("prompt_injection")

            if "role_hijack" in f.get("type", ""):
                risk_score += 40
                attack_chain.append("role_hijacking")

            if "data_leak" in f.get("type", ""):
                risk_score += 50
                attack_chain.append("data_leakage")

        next_actions = []

        if "prompt_injection" in attack_chain:
            next_actions.append("attempt_role_escalation")

        return {
            "risk_score": risk_score,
            "attack_chain": attack_chain,
            "next_actions": next_actions
        }
