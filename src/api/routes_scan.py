from fastapi import APIRouter
from src.jobs.job_store import create_job, get_job
from src.core.worker import start_background_job

router = APIRouter()

@router.post("/scan")
def run_scan():
    job_id = create_job()
    start_background_job(job_id)

    return {
        "job_id": job_id,
        "status": "queued"
    }


@router.get("/scan/{job_id}")
def get_scan(job_id: str):
    job = get_job(job_id)

    if not job:
        return {"error": "not found"}

    return job
