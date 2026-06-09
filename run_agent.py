from src.scanner_wrapper import ScannerWrapper
from src.analyzers.response_analyzer import analyze_response
import json

TARGET_URL = "http://127.0.0.1:8000/chat"
PROBE_TYPES = [
    "prompt_injection", "jailbreak", "data_leakage",
    "role_hijacking", "pii_extraction", "system_prompt_leakage",
    "tool_abuse", "api_key_exposure"
]

scanner = ScannerWrapper()
all_findings = []
total_probes = 0

print(f"\n{'='*60}")
print(f"  GHOSTWATCH AI SECURITY SCANNER")
print(f"  Target: {TARGET_URL}")
print(f"{'='*60}\n")

for probe_type in PROBE_TYPES:
    results = scanner.run_probe(TARGET_URL, probe_type)
    for r in results:
        total_probes += 1
        response_text = r.get("response", r.get("error", ""))
        analysis = analyze_response(
            probe_type=probe_type,
            payload=r.get("payload", ""),
            response_text=response_text
        )
        if analysis["is_vulnerable"]:
            severity = analysis["severity"]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
            print(f"{icon} [{severity}] {probe_type.upper()}")
            print(f"   Payload  : {analysis['payload'][:80]}")
            print(f"   Triggers : {analysis['triggered_indicators']}")
            print(f"   Partial  : {analysis.get('partial_leak', False)}")
            print(f"   Score    : {analysis['risk_score']}/10")
            print(f"   Response : {analysis['response_preview'][:120]}\n")
            all_findings.append(analysis)

critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
high     = sum(1 for f in all_findings if f["severity"] == "HIGH")
medium   = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

print(f"{'='*60}")
print(f"  SCAN COMPLETE")
print(f"  Probes fired : {total_probes}")
print(f"  Vulnerabilities: {len(all_findings)}")
print(f"  Critical: {critical} | High: {high} | Medium: {medium}")
print(f"{'='*60}\n")

with open("ghostwatch_report.json", "w") as f:
    json.dump(all_findings, f, indent=2)
print("Report saved → ghostwatch_report.json")
