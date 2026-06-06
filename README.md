# GhostWatch

Adversarial LLM security assessment framework — tests prompt injection, jailbreaks, and system prompt leakage with MITRE ATT&CK mapping and executive PDF reporting.

## What it tests
- Prompt Injection (MITRE AML.T0051 / OWASP LLM01)
- Jailbreaks (MITRE AML.T0054 / OWASP LLM01)
- System Prompt Leakage (MITRE AML.T0056 / OWASP LLM07)
- Payload Reflection

## Output
- Executive PDF report with findings table, business impact, and recommendations
- JSON findings with MITRE ATT&CK and OWASP LLM Top 10 mappings
- Risk scoring per probe

## Run a scan
```bash
python cli.py run
```

## Generate PDF report
```bash
python cli.py report
```

## Stack
- Python 3.12
- FastAPI
- ReportLab
- HTTPx
