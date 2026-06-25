from src.probes.probe_library import get_all_probes


def execute_probes(target_name="local_mock", filter_type=None):
    probes = get_all_probes()

    if filter_type:
        probes = [p for p in probes if p.get("attack_type") == filter_type]

    return probes
