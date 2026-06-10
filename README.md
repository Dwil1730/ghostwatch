# GhostWatch 

**AI-powered LLM security scanner** — automatically probes AI APIs for vulnerabilities and generates risk-scored reports.

## What It Does
GhostWatch runs 30+ security probes against any LLM-powered endpoint and detects:
- Prompt Injection
- Jailbreaks
- System Prompt Leakage
- PII Extraction
- Role Hijacking
- API Key Exposure
- Data Leakage

Each finding is mapped to **MITRE ATLAS** and **OWASP LLM Top 10** frameworks.

## Quick Start
```bash
pip install -r requirements.txt
python3 cli.py run --url http://your-llm-endpoint/chat
```

## Built With
- Python + FastAPI
- Azure AI Foundry (Reasoning Agent)
- MITRE ATLAS + OWASP LLM Top 10

## Hackathon
Built for Microsoft Agents League Hackathon 2026 — Reasoning Agents track.
