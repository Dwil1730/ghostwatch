"""
GhostWatch — AI Red Team Security Platform
==========================================
Autonomous LLM vulnerability scanner powered by Azure AI Foundry.

Submission: Microsoft Agents League Hackathon 2026 — Reasoning Agents Track
GitHub:     https://github.com/Dwil1730/ghostwatch
Framework:  MITRE ATLAS + OWASP LLM Top 10
"""

import sys
import os
import argparse
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

__version__ = "1.0.0"
__author__  = "Chris Williams (zEN)"
__track__   = "Microsoft Agents League — Reasoning Agents"

BANNER = r"""
╔══════════════════════════════════════════╗
║         GHOSTWATCH AI SECURITY AGENT     ║
║     LLM Vulnerability Scanner v1.0       ║
╚══════════════════════════════════════════╝
Powered by Azure AI Foundry · MITRE ATLAS · OWASP LLM Top 10
"""

def check_environment():
    missing = []
    if not os.environ.get("AZURE_OPENAI_API_KEY"):
        missing.append("AZURE_OPENAI_API_KEY")
    if not os.environ.get("AZURE_OPENAI_ENDPOINT"):
        missing.append("AZURE_OPENAI_ENDPOINT")
    return missing

def run_full_scan(target_url, use_ai=True, verbose=False):
    print(BANNER)
    if use_ai:
        missing = check_environment()
        if missing:
            print(f"[ERROR] Missing environment variables: {', '.join(missing)}")
            print("        Copy .env.example to .env and fill in your Azure credentials.")
            print("        To run scan without AI analysis: use --no-ai flag")
            sys.exit(1)
    print(f"► Target:   {target_url}")
    print(f"► AI Layer: {'Azure AI Foundry (GPT-4o)' if use_ai else 'Disabled'}")
    print(f"► Started:  {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print()
    print("► Step 1: Starting target AI endpoint...")
    print()
    print("► Step 2: GhostWatch Agent discovering & scanning...")
    print()
    try:
        from src.core.pipeline import run_scan
    except ImportError as e:
        print(f"[ERROR] Could not import scan pipeline: {e}")
        sys.exit(1)
    scan_result = run_scan(url=target_url, filter_type=None)
    if scan_result["status"] != "ok":
        print(f"[ERROR] Scan failed: {scan_result.get('errors', 'unknown error')}")
        sys.exit(1)
    data = scan_result["data"]
    findings = [r for r in data["results"] if r["detection_status"] == "vulnerable"]
    _print_findings_table(data, findings, verbose)
    if use_ai and findings:
        print("► Step 3: AI Reasoning Engine analyzing findings...")
        print()
        try:
            from run_agent import run_ghostwatch_agent
            run_ghostwatch_agent(target_url)
        except Exception as e:
            print(f"[WARNING] AI analysis failed: {e}")
    elif not use_ai:
        print("► Step 3: AI analysis skipped (--no-ai flag set)")
    print()
    print("✅ GhostWatch scan complete.")

def _print_findings_table(data, findings, verbose=False):
    print("GHOSTWATCH SECURITY SCAN")
    print()
    print(f"[discovery] Found 1 live endpoint(s)")
    print(f"[scanning]  {data.get('url', 'target')}")
    print(f"  Timestamp:   {data.get('timestamp', 'N/A')}")
    print(f"  Probes run:  {data['total_executed']}")
    print(f"  Vulnerable:  {data['total_vulnerable']} ({len(set(f['probe_type'] for f in findings))} unique attack types)")
    print(f"  Safe:        {data['total_safe']}")
    print()
    if not findings:
        print("No vulnerabilities detected.")
        return
    seen = {}
    for f in findings:
        pt = f["probe_type"]
        if pt not in seen or f["risk_score"] > seen[pt]["risk_score"]:
            seen[pt] = f
    print(f"FINDINGS ({len(seen)} unique / {len(findings)} total hits)")
    print()
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(findings, key=lambda x: (sev_order.get(x["severity"], 9), -x["risk_score"]))
    printed = set()
    for f in sorted_findings:
        pt = f["probe_type"]
        if pt in printed and not verbose:
            continue
        printed.add(pt)
        print(f"  [{f['severity']}] {pt} — score {f['risk_score']} — {f.get('mitre_id','')}")
    print()

def main():
    parser = argparse.ArgumentParser(description="GhostWatch — Autonomous LLM Security Scanner")
    parser.add_argument("--url", "-u", default="http://127.0.0.1:8000/chat", help="Target LLM endpoint URL")
    parser.add_argument("--no-ai", action="store_true", help="Skip Azure AI Foundry reasoning layer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all findings including duplicates")
    parser.add_argument("--version", action="version", version=f"GhostWatch v{__version__}")
    args = parser.parse_args()
    run_full_scan(target_url=args.url, use_ai=not args.no_ai, verbose=args.verbose)

if __name__ == "__main__":
    main()
