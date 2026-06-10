import os
from datetime import datetime
from src.core.probe_engine import execute_probes
from src.targets.local_target_client import execute_probes_concurrent
from src.analyzers.response_analyzer import analyze_response


def run_scan(filter_type=None, url=None, method="POST"):
    try:
        probes = execute_probes(filter_type=filter_type)

        if not url:
            return {
                "status": "fail",
                "data": {},
                "errors": ["No target URL provided. Use --url to specify a target."],
            }

        print(f"[discovery] Found 1 live endpoint(s)")
        print(f"[scanning] {url}")
        raw_results = execute_probes_concurrent(probes, url, max_workers=10)

        results = []
        for result in raw_results:
            if result is None:
                continue
            analyzed = analyze_response(
                probe_type=result.probe_type,
                payload=result.payload,
                response_text=result.raw_response or ""
            )
            results.append({
                "probe_type": analyzed["probe_type"],
                "severity": analyzed["severity"],
                "risk_score": analyzed["risk_score"],
                "indicators": analyzed["triggered_indicators"],
                "mitre_id": result.mitre_id,
                "owasp_category": result.owasp_category,
                "status_code": result.status_code,
                "payload": result.payload,
                "response_preview": analyzed["response_preview"],
                "detection_status": "vulnerable" if analyzed["is_vulnerable"] else "safe",
            })

        vulnerable = [r for r in results if r["detection_status"] == "vulnerable"]
        errors = [r for r in results if r["detection_status"] == "error"]
        safe = [r for r in results if r["detection_status"] == "safe"]

        # Deduplicate by probe_type + severity for summary
        seen = set()
        unique_vulnerable = []
        for r in vulnerable:
            key = (r["probe_type"], r["severity"])
            if key not in seen:
                seen.add(key)
                unique_vulnerable.append(r)

        return {
            "status": "ok",
            "data": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "total_executed": len(results),
                "total_vulnerable": len(vulnerable),
                "total_unique_vulnerable": len(unique_vulnerable),
                "total_safe": len(safe),
                "total_errors": len(errors),
                "results": results,
                "unique_vulnerable": unique_vulnerable,
            },
            "errors": [],
        }

    except Exception as e:
        return {
            "status": "fail",
            "data": {},
            "errors": [str(e)],
        }
