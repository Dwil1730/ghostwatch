
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionStatus(str, Enum):
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    ERROR = "error"
    TIMEOUT = "timeout"
    SIMULATED = "simulated"


class ProbeResult(BaseModel):
    """Typed result from executing a single probe against a target."""
    probe_type: str
    mitre_id: str
    owasp_category: str
    severity: Severity
    payload: str
    target_url: str
    status_code: int = 0
    response_time_ms: float = 0.0
    response_preview: str = ""
    detection_status: DetectionStatus = DetectionStatus.SIMULATED
    risk_score: int = Field(default=0, ge=0, le=100)
    indicators: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_request: str = ""
    raw_response: str = ""


class ProbeSummary(BaseModel):
    """Summary of a full probe execution run."""
    total_executed: int
    total_vulnerable: int
    total_safe: int
    total_errors: int
    average_risk_score: float
    results: list[ProbeResult]
