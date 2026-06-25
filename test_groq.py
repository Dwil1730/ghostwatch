import os
import sys
import json
from dotenv import load_dotenv
from groq import Groq

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from probes.probe_library import get_all_probes
from analyzers.response_analyzer import analyze_response

load_dotenv()
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

MODEL = "llama-3.3-70b-versatile"

TARGET_CATEGORIES = ["prompt_injection", "indirect_injection"]

probes = get_all_probes()
target_probes = [p for p in probes if p["attack_type"] in TARGET_CATEGORIES]

print(f"Testing {len(target_probes)} probes against {MODEL} via Groq\n")
print("=" * 70)

results = []

for i, probe in enumerate(target_probes, 1):
    payload = probe["payload"]
    print(f"\n[{i}/{len(target_probes)}] {probe['attack_type']}")
    print(f"PROMPT: {payload[:80]}")

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": payload}],
            max_tokens=300,
        )
        response_text = response.choices[0].message.content

    except Exception as e:
        response_text = f"ERROR: {e}"

    print(f"RESPONSE: {response_text[:150]}")

    analyzed = analyze_response(
        probe_type=probe["attack_type"],
        payload=payload,
        response_text=response_text
    )

    print(f"VULNERABLE: {analyzed['is_vulnerable']} | Score: {analyzed['risk_score']} | Severity: {analyzed['severity']}")
    print("-" * 70)

    results.append({
        "probe_type": probe["attack_type"],
        "mitre_id": probe["mitre_id"],
        "owasp_category": probe["owasp_category"],
        "prompt": payload,
        "response": response_text,
        "is_vulnerable": analyzed["is_vulnerable"],
        "risk_score": analyzed["risk_score"],
        "severity": analyzed["severity"],
        "triggered_indicators": analyzed["triggered_indicators"],
    })

with open("groq_test_results.json", "w") as f:
    json.dump(results, f, indent=2)

vulnerable = [r for r in results if r["is_vulnerable"]]
print("\n" + "=" * 70)
print(f"SUMMARY: {len(vulnerable)}/{len(results)} probes flagged as vulnerable")
print("=" * 70)

if vulnerable:
    print("\nVULNERABLE FINDINGS:")
    for v in vulnerable:
        print(f"\n  [{v['severity']}] {v['probe_type']} (score {v['risk_score']})")
        print(f"  PROMPT: {v['prompt']}")
        print(f"  RESPONSE: {v['response'][:200]}")
else:
    print("\nNo vulnerabilities flagged - this is EXPECTED for a hardened model.")
    print("This itself is useful data for your white paper.")

print(f"\nFull results saved to groq_test_results.json")
