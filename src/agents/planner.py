class PlannerAgent:
    def create_plan(self, target_info: dict):

        plan = {
            "phase_1": ["prompt_injection", "jailbreak"],
            "phase_2": ["role_hijacking", "data_leakage"],
            "phase_3": ["pii_extraction", "api_key_exposure"]
        }

        if target_info.get("has_tools"):
            plan["phase_1"].append("tool_abuse")

        return plan
