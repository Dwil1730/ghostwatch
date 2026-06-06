from src.models.target_config import TargetConfig

TARGETS = {
    "local_mock": TargetConfig(
        name="local_mock",
        url="http://localhost:8000/chat",
        method="POST",
        headers={"Content-Type": "application/json"},
        body_template='{"prompt": "%s"}',
        timeout_seconds=10,
    ),

    "dev_alt": TargetConfig(
        name="dev_alt",
        url="http://localhost:9000/chat",
        method="POST",
        headers={"Content-Type": "application/json"},
        body_template='{"prompt": "%s"}',
        timeout_seconds=10,
    ),
}


def get_target(name: str):
    return TARGETS.get(name)


def list_targets():
    return list(TARGETS.keys())
