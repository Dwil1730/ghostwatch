from fastapi import FastAPI

from src.core.job_store import create_job, get_job
from src.core.worker import start_background_job

app = FastAPI(title="Ghostwatch Security Scanner")


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/scan")
def run_scan(target: str = "local_mock"):
    job_id = create_job(target)
    start_background_job(job_id, target)

    return {
        "job_id": job_id,
        "status": "queued",
        "target": target
    }


@app.get("/scan/{job_id}")
def scan_status(job_id: str):
    job = get_job(job_id)

    if not job:
        return {"error": "job not found"}

    return job