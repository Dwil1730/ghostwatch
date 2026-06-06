import threading

from src.core.probe_engine import execute_probes
from src.core.job_store import update_job
from src.core.risk_engine.engine import finalize_risk

from src.reporting.evidence import build_evidence
from src.reporting.executive_report import build_executive_report


def run_scan(job_id: str, target: str):
    update_job(job_id, status="running")

    try:
        # --------------------------------
        # 1. RUN PROBE ENGINE (DETECTION ONLY)
        # --------------------------------
        scan_output = execute_probes(target_name=target)

        results = scan_output.get("results", [])

        # --------------------------------
        # 2. APPLY RISK POLICY ENGINE (SINGLE SOURCE OF TRUTH)
        # --------------------------------
        for r in results:
            indicators = r.get("indicators", [])

            risk = finalize_risk(indicators)

            r["risk_score"] = risk["score"]
            r["severity"] = risk["severity"]

        # --------------------------------
        # 3. BUILD EVIDENCE CHAIN (FORMAT ONLY)
        # --------------------------------
        evidence = build_evidence([
            {
                "payload": r.get("payload", ""),
                "raw_response": r.get("raw_response", ""),
                "risk_score": r.get("risk_score", 0),
                "severity": r.get("severity", "LOW"),
                "indicators": r.get("indicators", [])
            }
            for r in results
        ])

        # --------------------------------
        # 4. EXECUTIVE REPORT (FINAL LAYER)
        # --------------------------------
        executive_report = build_executive_report({
            "target": target,
            "evidence": evidence,
            "scan_summary": scan_output
        })

        # --------------------------------
        # 5. FINAL CLIENT PACKET
        # --------------------------------
        final_result = {
            "target": target,
            "scan_summary": scan_output,
            "evidence": evidence,
            "executive_report": executive_report
        }

        update_job(
            job_id,
            status="completed",
            result=final_result
        )

    except Exception as e:
        update_job(
            job_id,
            status="failed",
            result={
                "error": str(e),
                "stage": "scan_execution"
            }
        )


def start_background_job(job_id: str, target: str):
    thread = threading.Thread(
        target=run_scan,
        args=(job_id, target),
        daemon=True
    )
    thread.start()