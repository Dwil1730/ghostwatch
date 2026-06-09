from datetime import datetime, timezone

from src.probes.probe_library import get_all_probes
from src.probes.api_probes import get_api_probes
from src.probes.auth_probes import get_auth_probes
from src.probes.output_probes import get_output_probes
from src.targets.target_client import execute_probe_request
from src.analyzers.response_analyzer import analyze_response
from src.models.target_config import TargetConfig
from src.core.report_writer import save_scan_report


def execute_probes(target_name="local_mock", filter_type=None):
    probes = get_all_probes() + get_api_probes() + get_auth_probes() + get_output_probes()

    if filter_type:
        probes = [p for p in probes if p["attack_type"] == filter_type]

    return probes


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
    print(output)
    print("\n=== SUMMARY ===")
    print(f"Total:      {output['total_executed']}")
    print(f"Vulnerable: {output['total_vulnerable']}")
    print(f"Safe:       {output['total_safe']}")
    print(f"Errors:     {output['total_errors']}")
