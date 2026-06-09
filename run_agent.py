import os
import sys
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential
from src.core.pipeline import run_scan

endpoint = "https://eastus.api.azureml.ms"

client = AIProjectClient(
    endpoint=endpoint,
    subscription_id="22448a38-0d46-4d08-865e-fbad322c28f9",
    resource_group_name="ghostwatch-rg",
    project_name="ghostwatch",
    credential=DefaultAzureCredential(),
)

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

    # Use Foundry inference for AI analysis
    summary = f"""
GhostWatch scanned {target_url} and found {data['total_vulnerable']} vulnerabilities out of {data['total_executed']} probes.

Top findings:
{chr(10).join([f"- {f['probe_type']} ({f['severity']}) score={f['risk_score']}" for f in findings[:10]])}

Provide: 1) Executive summary 2) Risk level 3) Top 3 remediations.
"""

    try:
        openai_client = client.get_openai_client()
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are GhostWatch, an expert AI security analyst."},
                {"role": "user", "content": summary}
            ]
        )
        print("\n🤖 GhostWatch AI Analysis:")
        print(response.choices[0].message.content)
    except Exception as e:
        print(f"\n⚠️  AI analysis unavailable: {e}")
        print("Scanner results above are still valid.")

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/chat"
    run_ghostwatch_agent(url)
