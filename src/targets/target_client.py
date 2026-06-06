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

    try:
        body = target.body_template % result.payload
    except Exception:
        body = {"prompt": result.payload}

    result.raw_request = str(body)

    try:
        start = time.time()

        with httpx.Client(timeout=target.timeout_seconds) as client:
            response = client.request(
                method=target.method,
                url=target.url,
                headers=target.headers,
                json={"prompt": result.payload},
            )

        result.response_time_ms = round((time.time() - start) * 1000, 2)
        result.status_code = response.status_code
        result.raw_response = response.text
        result.response_preview = response.text[:500]

    except httpx.TimeoutException:
        result.detection_status = DetectionStatus.TIMEOUT
        result.risk_score = 0

    except Exception as e:
        result.detection_status = DetectionStatus.ERROR
        result.risk_score = 0
        result.response_preview = str(e)[:500]

    return result


def _extract_response(response: httpx.Response, target: TargetConfig) -> str:
    content_type = response.headers.get("content-type", "")
    if target.response_json_path and "application/json" in content_type:
        try:
            data = response.json()
            return _extract_json_path(data, target.response_json_path)
        except Exception:
            return response.text
    return response.text


def _extract_json_path(data, path: str) -> str:
    current = data
    parts = path.replace("[", ".").replace("]", "").split(".")
    for part in parts:
        if not part:
            continue
        try:
            if isinstance(current, dict):
                current = current.get(part, current)
            elif isinstance(current, list):
                idx = int(part)
                current = current[idx] if idx < len(current) else current
            else:
                break
        except Exception:
            break
    return current if isinstance(current, str) else json.dumps(current)
