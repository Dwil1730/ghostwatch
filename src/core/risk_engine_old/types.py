from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    probe_type: str
    indicators: List[str]
    raw_score: int
    severity: str
    final_score: int