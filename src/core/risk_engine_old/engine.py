from src.core.risk_engine.weights import WEIGHTS

from src.core.risk_engine.severity import classify_severity

def compute_score(indicators: list[str]) -> int:
    score = 0

    for i in indicators:
        score += WEIGHTS.get(i, 5)

    return min(score, 100)


def finalize_risk(indicators: list[str]):
    score = compute_score(indicators)
    severity = classify_severity(indicators)

    # 🔥 ENFORCED RULE (CRITICAL FIX)
    if severity == "HIGH":
        score = max(score, 70)

    return {
        "score": score,
        "severity": severity
    }