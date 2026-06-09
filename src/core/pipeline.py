import os
from datetime import datetime

from src.core.probe_engine import execute_probes
from src.targets.anthropic_client import execute_anthropic_probe
from src.targets.local_target_client import execute_local_probe, execute_probes_concurrent
from src.analyzers.response_analyzer import analyze_response


def run_scan(filter_type=None, url=None, method="POST"):
    try:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        probes = execute_probes(filter_type=filter_type)

        if url:
            print(f"[discovery] Found 1 live endpoint(s)")
            print(f"[scanning] {url}")
            raw_results = execute_probes_concurrent(probes, url, max_workers=10)
        else:
            if not api_key:
                return {
                    "status": "fail",
                    "data": {},
                    "errors": ["ANTHROPIC_API_KEY not set."],
                }
            print(f"[discovery] Scanning Anthropic API ({len(probes)} probes)")
            print(f"[scanning] https://api.anthropic.com/v1/messages")
            raw_results = []
            for i, probe in enumerate(probes, 1):
                print(f"  [{i}/{len(probes)}] {probe.get('attack_type', 'unknown')}", end="\r")
                raw_results.append(execute_anthropic_probe(probe, api_key))
            print()

        results = []
        for result in raw_results:
            if result is None:
                continue
            result = analyze_response(result)
            results.append({
                "probe_type": result.probe_type,
                "severity": getattr(result.severity, "name", str(result.severity)),
                "risk_score": getattr(result, "risk_score", 0),
                "indicators": getattr(result, "indicators", []),
                "mitre_id": result.mitre_id,
                "owasp_category": result.owasp_category,
                "status_code": result.status_code,
                "response_preview": getattr(result, "response_preview", ""),
                "detection_status": getattr(result, "detection_status", "unknown"),
            })

        vulnerable = [r for r in results if r["detection_status"] == "vulnerable"]
        errors     = [r for r in results if r["detection_status"] == "error"]
        safe       = [r for r in results if r["detection_status"] == "safe"]

        return {
            "status": "ok",
            "data": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "total_executed": len(results),
                "total_vulnerable": len(vulnerable),
                "total_safe": len(safe),
                "total_errors": len(errors),
                "results": results,
            },
            "errors": [],
        }

    except Exception as e:
        return {
            "status": "fail",
            "data": {},
            "errors": [str(e)],
        }
