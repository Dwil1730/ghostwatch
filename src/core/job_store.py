import json
import uuid
import redis
from datetime import datetime

r = redis.Redis(host="localhost", port=6379, decode_responses=True)


def create_job(target: str):
    job_id = str(uuid.uuid4())

    job = {
        "job_id": job_id,
        "status": "queued",
        "target": target,
        "created_at": datetime.utcnow().isoformat(),
        "result": None
    }

    r.set(f"job:{job_id}", json.dumps(job))
    return job_id


def get_job(job_id: str):
    data = r.get(f"job:{job_id}")

    if not data:
        return None

    return json.loads(data)


def update_job(job_id: str, **updates):
    data = r.get(f"job:{job_id}")

    if not data:
        return None

    job = json.loads(data)

    job.update(updates)
    job["updated_at"] = datetime.utcnow().isoformat()

    r.set(f"job:{job_id}", json.dumps(job))
    return job
