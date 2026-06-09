import json
import time
import httpx

from src.models.probe_result import DetectionStatus, ProbeResult, Severity
from src.models.target_config import TargetConfig


def execute_probe_request(probe: dict, target: TargetConfig) -> ProbeResult:

    result = ProbeResult(
        probe_type=probe.get("attack_type", "unknown"),
        mitre_id=probe.get("mitre_id", "unknown"),
        owasp_category=probe.get("owasp_category", "unknown"),
        severity=Severity.MEDIUM,
        payload=probe.get("payload", ""),
        target_url=target.url,
    )

    result.raw_request = str({"message": result.payload})

    try:
        start = time.time()

        with httpx.Client(timeout=target.timeout_seconds) as client:
            response = client.request(
                method=target.method,
                url=target.url,
                headers=target.headers,
                json={"message": result.payload},
            )

        result.response_time_ms = round((time.time() - start) * 1000, 2)
        result.status_code = response.status_code
        result.raw_response = response.text
        print(f"DEBUG: {response.text[:200]}")
        result.response_preview = response.text[:500]

    except httpx.TimeoutException:
        result.detection_status = DetectionStatus.TIMEOUT
        result.risk_score = 0

    except Exception as e:
        result.detection_status = DetectionStatus.ERROR
        result.risk_score = 0
        result.response_preview = str(e)[:500]

    return result
