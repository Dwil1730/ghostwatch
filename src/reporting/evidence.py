import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List


def _hash_content(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def build_evidence(probe_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Converts raw scan outputs into audit-grade evidence objects.
    """

    evidence_items = []

    for r in probe_results:
        payload = r.get("payload", "")
        response = r.get("raw_response", "")
        indicators = r.get("indicators", [])
        risk_score = r.get("risk_score", 0)

        evidence_id = _hash_content(payload + response)

        evidence_items.append({
            "evidence_id": evidence_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_input": payload,
            "model_output": response,
            "risk_score": risk_score,
            "detected_indicators": indicators,
            "reproducibility": {
                "deterministic": True,
                "retest_required": False
            },
            "integrity_hash": _hash_content(json.dumps({
                "payload": payload,
                "response": response,
                "indicators": indicators
            }, sort_keys=True))
        })

    return {
        "evidence_count": len(evidence_items),
        "evidence_chain_hash": _hash_content(json.dumps(evidence_items, sort_keys=True)),
        "evidence": evidence_items
    }