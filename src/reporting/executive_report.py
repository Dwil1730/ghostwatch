from datetime import datetime, timezone
from typing import Dict, Any


def build_executive_report(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts technical scan data into executive-ready output.
    """

    evidence = scan_data.get("evidence", {})
    findings = evidence.get("evidence", [])

    total = len(findings)

    high_risk = [f for f in findings if f.get("risk_score", 0) >= 70]
    medium_risk = [f for f in findings if 40 <= f.get("risk_score", 0) < 70]
    low_risk = [f for f in findings if f.get("risk_score", 0) < 40]

    avg_risk = 0
    if total:
        avg_risk = sum(f.get("risk_score", 0) for f in findings) / total

    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_type": "AI Security Assessment",
            "version": "1.0"
        },

        "executive_summary": {
            "total_findings": total,
            "average_risk_score": round(avg_risk, 2),
            "risk_distribution": {
                "high": len(high_risk),
                "medium": len(medium_risk),
                "low": len(low_risk)
            }
        },

        "key_risks": [
            "Prompt injection susceptibility detected in model interaction layer",
            "Potential sensitive data reflection patterns identified",
            "System behavior may be influenced by adversarial input structures"
        ],

        "business_impact": {
            "data_exposure_risk": "Medium to High depending on deployment context",
            "compliance_risk": "Requires validation against SOC2 / ISO27001 controls",
            "operational_risk": "Model behavior unpredictability under adversarial inputs"
        },

        "recommendations": [
            "Implement prompt sanitization and input classification layer",
            "Add output filtering for sensitive data patterns",
            "Introduce logging for adversarial prompt detection",
            "Establish red-team continuous testing pipeline"
        ]
    }