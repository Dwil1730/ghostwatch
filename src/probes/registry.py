from typing import Dict, Any, List

PROBE_REGISTRY: Dict[str, Any] = {}

def register_probe(name: str):
    """
    Decorator to register a probe class into global registry.
    """
    def wrapper(cls):
        PROBE_REGISTRY[name] = cls()
        return cls
    return wrapper


def get_all_probes() -> List[dict]:
    """
    Returns all instantiated probes in standardized format.
    """
    probes = []

    for name, probe_obj in PROBE_REGISTRY.items():
        probes.append({
            "name": name,
            "attack_type": getattr(probe_obj, "attack_type", name),
            "mitre_id": getattr(probe_obj, "mitre_id", "UNKNOWN"),
            "owasp_category": getattr(probe_obj, "owasp_category", "UNKNOWN"),
            "submittable": getattr(probe_obj, "submittable", True),
            "description": getattr(probe_obj, "description", ""),
            "payload": probe_obj.payloads()
        })

    return probes
