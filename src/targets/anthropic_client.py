import time
import httpx

from src.models.probe_result import DetectionStatus, ProbeResult, Severity
from src.models.target_config import TargetConfig

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"


def execute_anthropic_probe(probe: dict, api_key: str) -> ProbeResult:
    result = ProbeResult(
        probe_type=probe.get("attack_type", "unknown"),
        mitre_id=probe.get("mitre_id", "unknown"),
        owasp_category=probe.get("owasp_category", "unknown"),
        severity=Severity.MEDIUM,
        payload=probe.get("payload", ""),
        target_url=ANTHROPIC_URL,
    )

    result.raw_request = probe.get("payload", "")

    try:
        start = time.time()

        with httpx.Client(timeout=30) as client:
            response = client.post(
                ANTHROPIC_URL,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": ANTHROPIC_MODEL,
                    "max_tokens": 512,
                    "messages": [
                        {"role": "user", "content": probe.get("payload", "")}
                    ],
                },
            )

        result.response_time_ms = round((time.time() - start) * 1000, 2)
        result.status_code = response.status_code

        if response.status_code == 200:
            data = response.json()
            text = data.get("content", [{}])[0].get("text", "")
            result.raw_response = text
            result.response_preview = text[:500]
        else:
            result.raw_response = response.text
            result.response_preview = response.text[:500]
            result.detection_status = DetectionStatus.ERROR

    except httpx.TimeoutException:
        result.detection_status = DetectionStatus.TIMEOUT
        result.risk_score = 0

    except Exception as e:
        result.detection_status = DetectionStatus.ERROR
        result.risk_score = 0
        result.response_preview = str(e)[:500]

    return result
