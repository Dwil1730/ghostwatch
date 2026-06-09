import sys
import re

file_path = sys.argv[1]

with open(file_path, "r") as f:
    log = f.read()

probes = re.findall(r"Probes run:\s*(\d+)", log)
errors = re.findall(r"Errors:\s*(\d+)", log)
safe = re.findall(r"Safe:\s*(\d+)", log)
vuln = re.findall(r"Vulnerable:\s*(\d+)", log)

summary = {
    "probes_run": probes[-1] if probes else "N/A",
    "errors": errors[-1] if errors else "N/A",
    "safe": safe[-1] if safe else "N/A",
    "vulnerable": vuln[-1] if vuln else "N/A"
}

print("\n=== GHOSTWATCH EXECUTION SUMMARY ===\n")

for k, v in summary.items():
    print(f"{k}: {v}")
