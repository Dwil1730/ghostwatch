import os
import sys
import anthropic
from dotenv import load_dotenv
load_dotenv()
from src.core.pipeline import run_scan

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

def run_ghostwatch_agent(target_url: str):
    print(f"\n🔍 GhostWatch Agent scanning: {target_url}\n")

    scan_result = run_scan(url=target_url, filter_type=None)

    if scan_result["status"] != "ok":
        print(f"Scan failed: {scan_result['errors']}")
        return

    data = scan_result["data"]
    findings = [r for r in data["results"] if r["detection_status"] == "vulnerable"]

    print(f"\n✅ Scan complete:")
    print(f"   Probes run:  {data['total_executed']}")
    print(f"   Vulnerable:  {data['total_vulnerable']}")
    print(f"   Safe:        {data['total_safe']}")

    if findings:
        print(f"\n🚨 Top Findings:")
        for f in findings[:5]:
            print(f"   [{f['severity']}] {f['probe_type']} — score {f['risk_score']}")

    summary = f"""
GhostWatch scanned {target_url} and found {data['total_vulnerable']} vulnerabilities out of {data['total_executed']} probes.

Top findings:
{chr(10).join([f"- {f['probe_type']} ({f['severity']}) score={f['risk_score']} indicators={f['indicators']}" for f in findings[:10]])}

Provide:
1) Executive summary of the security posture
2) Overall risk level (Critical/High/Medium/Low)
3) Top 3 specific remediation recommendations
Be concise and actionable.
"""

    print("\n🤖 GhostWatch AI Analysis:")
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": summary}
        ]
    )
    print(message.content[0].text)

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/chat"
    run_ghostwatch_agent(url)
