from fastapi import FastAPI
from src.probes.probe_library import get_all_probes

app = FastAPI()

@app.get("/")
def health():
    return {"status": "GhostWatch API running"}

@app.get("/probes")
def probes():
    return get_all_probes()
