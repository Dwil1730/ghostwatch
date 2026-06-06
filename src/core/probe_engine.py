from datetime import datetime, timezone

from src.probes.probe_library import get_all_probes
from src.targets.target_client import execute_probe_request
from src.analyzers.response_analyzer import analyze_response
from src.models.target_config import TargetConfig
from src.core.report_writer import save_scan_report


DEFAULT_TARGET = TargetConfig(
    name="local-test",
    url="http://localhost:8000/chat",
)


def execute_probes(target_name="local_mock", filter_type=None):

    probes = get_all_probes()

    if filter_type:
        probes = [p for p in probes if p["attack_type"] == filter_type]

    results = []

    for probe in probes:
        result = execute_probe_request(probe, DEFAULT_TARGET)
        result = analyze_response(result)
        results.append(result.model_dump(mode="json"))

    output = build_output(results)

    save_scan_report(output)

    return output


def build_output(results):

    vulnerable = sum(1 for r in results if r["detection_status"] == "vulnerable")
    safe = sum(1 for r in results if r["detection_status"] == "safe")
    errors = sum(1 for r in results if r["detection_status"] in ["error", "timeout"])

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_executed": len(results),
        "total_vulnerable": vulnerable,
        "total_safe": safe,
        "total_errors": errors,
        "results": results,
    }


if __name__ == "__main__":
    output = execute_probes()

    print("\n=== SUMMARY ===")
    print(f"Total:      {output['total_executed']}")
    print(f"Vulnerable: {output['total_vulnerable']}")
    print(f"Safe:       {output['total_safe']}")
    print(f"Errors:     {output['total_errors']}")