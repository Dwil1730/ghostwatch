import time
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.models.probe_result import DetectionStatus, ProbeResult, Severity


def execute_local_probe(probe: dict, url: str) -> ProbeResult:
    result = ProbeResult(
        probe_type=probe.get("attack_type", "unknown"),
        mitre_id=probe.get("mitre_id", "unknown"),
        owasp_category=probe.get("owasp_category", "unknown"),
        severity=Severity.MEDIUM,
        payload=probe.get("payload", ""),
        target_url=url,
    )

    try:
        start = time.time()
        with httpx.Client(timeout=15) as client:
            response = client.post(
                url,
                headers={"Content-Type": "application/json"},
                json={"message": probe.get("payload", "")},
            )

        result.response_time_ms = round((time.time() - start) * 1000, 2)
        result.status_code = response.status_code

        if response.status_code == 200:
            data = response.json()
            text = data.get("response", data.get("message", str(data)))
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


def execute_probes_concurrent(probes: list, url: str, max_workers: int = 10) -> list:
    results = [None] * len(probes)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(execute_local_probe, probe, url): i
                   for i, probe in enumerate(probes)}
        completed = 0
        for future in as_completed(futures):
            i = futures[future]
            results[i] = future.result()
            completed += 1
            print(f"  [{completed}/{len(probes)}] {probes[i].get('attack_type', 'unknown'):30}", end="\r")
    print()
    return results
