import os
import json
from fastapi import APIRouter

router = APIRouter()

REPORT_DIR = "reports"


@router.get("/reports")
def list_reports():
    if not os.path.exists(REPORT_DIR):
        return {"reports": []}

    return {"reports": os.listdir(REPORT_DIR)}


@router.get("/reports/{file_name}")
def get_report(file_name: str):
    path = os.path.join(REPORT_DIR, file_name)

    if not os.path.exists(path):
        return {"error": "not found"}

    with open(path, "r") as f:
        return json.load(f)
