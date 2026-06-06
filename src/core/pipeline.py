from src.core.probe_engine import execute_probes


def run_scan(filter_type=None):
    try:
        output = execute_probes(filter_type=filter_type)

        return {
            "status": "ok",
            "data": output if output else {},
            "errors": []
        }

    except Exception as e:
        return {
            "status": "fail",
            "data": {},
            "errors": [str(e)]
        }
