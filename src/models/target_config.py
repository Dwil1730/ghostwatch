from pydantic import BaseModel
from typing import Dict, Optional


class TargetConfig(BaseModel):
    name: str = "default-target"
    url: str
    method: str = "POST"
    headers: Dict[str, str] = {}
    body_template: str = '{"prompt": "%s"}'
    timeout_seconds: int = 10
