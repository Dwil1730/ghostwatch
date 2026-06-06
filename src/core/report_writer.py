import json
import os
from datetime import datetime, timezone

REPORT_DIR = "reports"


def save_scan_report(scan_data: dict) -> str:

    os.makedirs(REPORT_DIR, exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat().replace(":", "-")

    file_path = os.path.join(REPORT_DIR, f"scan_{timestamp}.json")

    with open(file_path, "w") as f:
        json.dump(scan_data, f, indent=2)

    return file_path
