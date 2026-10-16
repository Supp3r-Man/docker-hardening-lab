"""Tests that build and run a real container. Skipped when there is no Docker daemon."""
import json
import tempfile

import pytest

from hardlab import docker, measure

pytestmark = pytest.mark.usefixtures("docker_daemon")

STAGE = "04-runtime-locked"


@pytest.fixture(scope="module")
def built_stage():
    measure.ensure_bases([STAGE])
    with tempfile.TemporaryDirectory(prefix="hardlab-test-") as tmp:
        ctx = measure.make_context(tmp)
        docker.timed_build(ctx, "docker/%s.Dockerfile" % STAGE, measure.tag_for(STAGE))
    yield STAGE
    docker.cleanup_labelled()


def test_locked_container_is_non_root_read_only_and_capless(built_stage):
    d = measure.run_diag(built_stage, measure.mode_flags("locked"))
    assert d["uid"] == 65532 and not d["root"]
    assert d["caps_effective"] == [] and d["caps_bounding"] == []
    assert d["no_new_privs"] is True
    assert d["write_root"] is False and d["write_app"] is False and d["write_tmp"] is True
    assert d["has_shell"] is False and d["has_pip"] is False
    assert d["memory_limit_bytes"] == 128 * 1024 * 1024 and d["pids_limit"] == 64 and d["cpu_limit"] == 0.5


def test_same_image_with_default_flags_keeps_docker_default_bounding_set(built_stage):
    d = measure.run_diag(built_stage, [])
    assert not d["root"] and d["caps_effective"] == []  # non-root user: nothing effective
    assert len(d["caps_bounding"]) > 0 and d["no_new_privs"] is False
    assert d["write_app"] is False  # /app is owned by root even though the process is not


def test_service_answers_and_stops_cleanly_under_the_lock(built_stage):
    result = measure.run_service(built_stage, measure.mode_flags("locked"))
    assert result["http_ok"] and result["sign_ok"]
    assert result["health"] == "healthy"
    assert result["exit_code"] == 0 and result["stop_seconds"] < 5


def test_image_inspect_reports_user_and_healthcheck(built_stage):
    from hardlab.parse import parse_inspect

    info = parse_inspect(docker.image_inspect(measure.tag_for(built_stage)))
    assert info["user"] == "65532:65532" and info["healthcheck"] is True
    json.dumps(info)  # serialisable
