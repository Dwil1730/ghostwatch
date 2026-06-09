import os
import sys
import anthropic
from dotenv import load_dotenv
from src.core.pipeline import run_scan

load_dotenv()
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))


def run_ghostwatch_agent(target_url: str):
    print(f"\n🔍 GhostWatch Agent scanning: {target_url}\n")

    scan_result = run_scan(url=target_url, filter_type=None)

    if scan_result["status"] != "ok":
        print(f"Scan failed: {scan_result['errors']}")
        return

    data = scan_result["data"]
    findings = data["unique_vulnerable"]

    print(f"\n✅ Scan complete:")
    print(f"   Probes run:   {data['total_executed']}")
    print(f"   Vulnerable:   {data['total_vulnerable']} hits ({data['total_unique_vulnerable']} unique types)")
    print(f"   Safe:         {data['total_safe']}")

    if findings:
        print(f"\n🚨 Unique Vulnerability Types Found:")
        for f in findings:
            print(f"   [{f['severity']}] {f['probe_type']} — score {f['risk_score']} — {f['mitre_id']}")

    summary = f"""
GhostWatch AI Security Scan Results:
Target: {target_url}
Probes run: {data['total_executed']}
Total vulnerability hits: {data['total_vulnerable']}
Unique attack types successful: {data['total_unique_vulnerable']}

Confirmed vulnerability types:
{chr(10).join([f"- {f['probe_type']} ({f['severity']}) score={f['risk_score']} mitre={f['mitre_id']} owasp={f['owasp_category']}" for f in findings])}

Provide:
1) Executive summary (2-3 sentences)
2) Overall risk level
3) Top 3 specific remediations with tool recommendations
"""

    print("\n🤖 GhostWatch AI Analysis:")
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": summary}]
    )
    print(message.content[0].text)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/chat"
    run_ghostwatch_agent(url)
