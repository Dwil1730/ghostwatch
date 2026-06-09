from src.core.risk_engine.rules import SEVERITY_OVERRIDE


def classify_severity(indicators: list[str]) -> str:
    """
    Deterministic severity classification.
    NO external dependencies.
    NO placeholders.
    """

    for i in indicators:
        if i in SEVERITY_OVERRIDE:
            return SEVERITY_OVERRIDE[i]

    return "LOW"