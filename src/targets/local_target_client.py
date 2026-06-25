import time
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.models.probe_result import DetectionStatus, ProbeResult, Severity
from src.analyzers.response_analyzer import analyze_response


def execute_local_probe(probe: dict, url: str) -> ProbeResult:

    payload_field = probe.get("payload", "")
    if isinstance(payload_field, list):
        payload = payload_field[0] if payload_field else ""
    else:
        payload = payload_field

    try:
        start = time.time()

        with httpx.Client(timeout=15) as client:
            response = client.post(
                url.rstrip("/") + "/chat",
                headers={"Content-Type": "application/json"},
                json={"message": payload},
            )

        latency = round((time.time() - start) * 1000, 2)

        text = ""
        if response.status_code == 200:
            try:
                data = response.json()
                text = data.get("response", data.get("message", str(data)))
            except Exception:
                text = response.text
        else:
            text = response.text

        analysis = analyze_response(
            probe.get("attack_type", "unknown"),
            payload,
            text
        )

        if analysis["is_vulnerable"]:
            det_status = DetectionStatus.VULNERABLE
        elif response.status_code != 200:
            det_status = DetectionStatus.ERROR
        else:
            det_status = DetectionStatus.SAFE

        return ProbeResult(
            target_url=url,
            probe_type=probe.get("attack_type", "unknown"),
            mitre_id=probe.get("mitre_id", "unknown"),
            owasp_category=probe.get("owasp_category", "unknown"),
            severity=Severity[analysis.get("severity", "MEDIUM")] if analysis.get("severity", "MEDIUM") in ["LOW","MEDIUM","HIGH","CRITICAL"] else Severity.MEDIUM,

            payload=payload,

            raw_response=text,
            response_preview=text[:500],

            response_time_ms=latency,
            status_code=response.status_code,

            detection_status=det_status,
        )

    except httpx.TimeoutException:
        return ProbeResult(
            target_url=url,
            probe_type=probe.get("attack_type", "unknown"),
            mitre_id=probe.get("mitre_id", "unknown"),
            owasp_category=probe.get("owasp_category", "unknown"),
            severity=Severity.MEDIUM,
            payload=payload,
            raw_response="",
            response_preview="TIMEOUT",
            response_time_ms=0,
            status_code=0,
            detection_status=DetectionStatus.TIMEOUT,
        )

    except Exception as e:
        return ProbeResult(
            target_url=url,
            probe_type=probe.get("attack_type", "unknown"),
            mitre_id=probe.get("mitre_id", "unknown"),
            owasp_category=probe.get("owasp_category", "unknown"),
            severity=Severity.MEDIUM,
            payload=payload,
            raw_response="",
            response_preview=str(e)[:500],
            response_time_ms=0,
            status_code=0,
            detection_status=DetectionStatus.ERROR,
        )


def execute_probes_concurrent(probes: list, url: str, max_workers: int = 10) -> list:
    results = [None] * len(probes)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(execute_local_probe, probe, url): i
            for i, probe in enumerate(probes)
        }

        completed = 0

        for future in as_completed(futures):
            i = futures[future]
            results[i] = future.result()
            completed += 1

            print(
                f"  [{completed}/{len(probes)}] {probes[i].get('attack_type', 'unknown'):30}",
                end="\r"
            )

    print()
    return results
