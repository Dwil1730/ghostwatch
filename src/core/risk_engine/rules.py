# src/core/risk_engine/rules.py

SEVERITY_OVERRIDE = {
    "pii_leak": "HIGH",
    "system_prompt_leak": "HIGH",
    "jailbreak_success": "HIGH",
    "data_leak": "HIGH"
}