import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def docker_daemon():
    """Skip tests that need Docker when there is no daemon (or HARDLAB_SKIP_DOCKER=1)."""
    import os

    from hardlab import docker

    if os.environ.get("HARDLAB_SKIP_DOCKER") == "1" or not docker.available():
        pytest.skip("no Docker daemon available")
    return True
