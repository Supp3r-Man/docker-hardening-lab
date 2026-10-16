import json
import re
from pathlib import Path

import pytest

from hardlab import lint

ROOT = Path(__file__).resolve().parent.parent
STAGES = list(lint.REQUIRED)


def read(stage):
    return (ROOT / "docker" / (stage + ".Dockerfile")).read_text(encoding="utf-8")


def rules_hit(text):
    return {f.rule for f in lint.lint_dockerfile(text)}


# ---- the parser ----------------------------------------------------------------------------

def test_parse_joins_continuations_and_skips_comments():
    ins = lint.parse_dockerfile("# top\nFROM a:1\nRUN one \\\n  # inner comment\n  two\n\nCMD [\"x\"]\n")
    assert [(i.name, i.args) for i in ins] == [("FROM", "a:1"), ("RUN", "one two"), ("CMD", '["x"]')]
    assert ins[1].line == 3


def test_split_stages_and_aliases():
    stages = lint.split_stages(lint.parse_dockerfile("FROM a:1 AS build\nRUN x\nFROM b:2\nCOPY --from=build /a /b\n"))
    assert [(s.image, s.alias) for s in stages] == [("a:1", "build"), ("b:2", "")]
    assert [i.name for i in stages[1].instructions] == ["COPY"]


@pytest.mark.parametrize("ref,expected", [
    ("python", ("python", None, None)),
    ("python:3.11", ("python", "3.11", None)),
    ("python:3.11@sha256:ab", ("python", "3.11", "sha256:ab")),
    ("localhost:5000/team/app:v1", ("localhost:5000/team/app", "v1", None)),
    ("gcr.io/distroless/python3:nonroot@sha256:cd", ("gcr.io/distroless/python3", "nonroot", "sha256:cd")),
])
def test_parse_image_ref(ref, expected):
    assert lint.parse_image_ref(ref) == expected


# ---- individual rules on small snippets ----------------------------------------------------

def test_floating_tags_and_digest_pins():
    assert {"no-floating-tag", "pin-digest"} <= rules_hit("FROM python\n")
    assert "no-floating-tag" in rules_hit("FROM python:latest\n")
    hit = rules_hit("FROM python:3.11@sha256:" + "a" * 64 + "\n")
    assert "no-floating-tag" not in hit and "pin-digest" not in hit


def test_stage_alias_references_are_not_external_images():
    text = "FROM python:3.11@sha256:aa AS build\nFROM build\nUSER 1\n"
    assert "pin-digest" not in rules_hit(text) and "no-floating-tag" not in rules_hit(text)


def test_final_user_must_be_non_root():
    assert "final-nonroot" in rules_hit("FROM a:1\n")
    assert "final-nonroot" in rules_hit("FROM a:1\nUSER root\n")
    assert "final-nonroot" in rules_hit("FROM a:1\nUSER 0:0\n")
    assert "final-nonroot" not in rules_hit("FROM a:1\nUSER 65532:65532\n")
    # a non-root user in an earlier stage does not count
    assert "final-nonroot" in rules_hit("FROM a:1 AS x\nUSER 1000\nFROM b:1\n")


def test_healthcheck_rule():
    assert "healthcheck" in rules_hit("FROM a:1\n")
    assert "healthcheck" in rules_hit("FROM a:1\nHEALTHCHECK NONE\n")
    assert "healthcheck" not in rules_hit('FROM a:1\nHEALTHCHECK --interval=5s CMD ["x"]\n')


def test_pip_no_cache_accepts_flag_or_env():
    assert "pip-no-cache" in rules_hit("FROM a:1\nRUN pip install x\n")
    assert "pip-no-cache" not in rules_hit("FROM a:1\nRUN pip install --no-cache-dir x\n")
    assert "pip-no-cache" not in rules_hit("FROM a:1\nENV PIP_NO_CACHE_DIR=1\nRUN pip install x\n")
    assert "pip-no-cache" in rules_hit("FROM a:1\nRUN python -m pip3 install x\n")


def test_deps_before_source():
    bad = "FROM a:1\nCOPY . .\nRUN pip install -r requirements.txt\n"
    good = "FROM a:1\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\nCOPY . .\n"
    assert "deps-before-source" in rules_hit(bad)
    assert "deps-before-source" not in rules_hit(good)
    # copying a build stage's output before the install is fine
    assert "deps-before-source" not in rules_hit("FROM a:1\nCOPY --from=x /y /y\nRUN pip install -r r.txt\n")


def test_remote_exec():
    assert "no-remote-exec" in rules_hit("FROM a:1\nADD https://x.example/a.tgz /a\n")
    assert "no-remote-exec" in rules_hit("FROM a:1\nRUN curl -sSL https://x.example/i.sh | sh\n")
    assert "no-remote-exec" in rules_hit("FROM a:1\nRUN wget -qO- https://x.example/i.sh | sudo bash\n")
    assert "no-remote-exec" not in rules_hit("FROM a:1\nRUN curl -o a.tgz https://x.example/a.tgz\n")


def test_baked_secrets():
    assert "no-baked-secrets" in rules_hit("FROM a:1\nENV API_TOKEN=abc123\n")
    assert "no-baked-secrets" in rules_hit("FROM a:1\nARG DB_PASSWORD=hunter2\n")
    assert "no-baked-secrets" not in rules_hit("FROM a:1\nARG DB_PASSWORD\n")
    assert "no-baked-secrets" not in rules_hit("FROM a:1\nENV PORT=8080\n")


def test_exec_form():
    assert "exec-form" in rules_hit("FROM a:1\nCMD python server.py\n")
    assert "exec-form" in rules_hit("FROM a:1\nHEALTHCHECK CMD curl -f http://x/\n")
    assert "exec-form" not in rules_hit('FROM a:1\nCMD ["python", "server.py"]\n')
    assert "exec-form" not in rules_hit('FROM a:1\nHEALTHCHECK --interval=5s CMD ["x"]\n')


def test_multi_stage():
    assert "multi-stage" in rules_hit("FROM a:1\n")
    assert "multi-stage" not in rules_hit("FROM a:1 AS b\nFROM c:1\n")


def test_no_from_is_an_error():
    with pytest.raises(ValueError):
        lint.lint_dockerfile("RUN echo hi\n")


# ---- the four real stages ------------------------------------------------------------------

def test_every_stage_meets_what_it_is_required_to():
    for stage in STAGES:
        _, failed = lint.verdict(stage, read(stage))
        assert failed == [], "%s breaks required rules %s" % (stage, failed)


def test_naive_baseline_trips_the_headline_rules():
    """If the baseline passes a rule, the rule proves nothing about the later stages."""
    hit = rules_hit(read("01-naive"))
    assert {"no-floating-tag", "pin-digest", "final-nonroot", "healthcheck", "pip-no-cache",
            "deps-before-source", "multi-stage"} <= hit


def test_stage_three_and_four_have_user_healthcheck_and_no_latest():
    for stage in ("03-nonroot-hardened", "04-runtime-locked"):
        text = read(stage)
        assert ":latest" not in text
        stages = lint.split_stages(lint.parse_dockerfile(text))
        names = [i.name for i in stages[-1].instructions]
        assert "USER" in names and "HEALTHCHECK" in names
        assert rules_hit(text) == set()


def test_stages_improve_monotonically():
    """Each stage breaks no more rules than the one before it."""
    counts = [len(rules_hit(read(s))) for s in STAGES]
    assert counts == sorted(counts, reverse=True) and counts[-1] == 0


def test_digests_in_dockerfiles_match_the_recorded_file():
    recorded = json.loads((ROOT / "docker" / "base-images.json").read_text(encoding="utf-8"))["images"]
    by_ref = {ref: meta["digest"] for ref, meta in recorded.items()}
    seen = 0
    for stage in STAGES:
        for st in lint.split_stages(lint.parse_dockerfile(read(stage))):
            name, tag, digest = lint.parse_image_ref(st.image)
            if digest:
                assert by_ref[name + ":" + tag] == digest, "%s: digest differs from base-images.json" % stage
                seen += 1
    assert seen >= 4
    for meta in recorded.values():
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", meta["digest"])


def test_base_images_file_lists_every_stage_exactly_where_it_is_used():
    recorded = json.loads((ROOT / "docker" / "base-images.json").read_text(encoding="utf-8"))["images"]
    for ref, meta in recorded.items():
        for stage in meta["used_by"]:
            assert ref in read(stage), "%s should reference %s" % (stage, ref)
        assert meta["pinned"] == (any("@" + meta["digest"] in read(s) for s in meta["used_by"]))


# ---- compose -------------------------------------------------------------------------------

def compose_text():
    return (ROOT / "docker-compose.yml").read_text(encoding="utf-8")


def test_real_compose_passes_every_check():
    assert lint.lint_compose(compose_text()) == []


@pytest.mark.parametrize("old,new,rule", [
    ("    read_only: true\n", "", "read-only-rootfs"),
    ("    tmpfs:\n      - /tmp\n", "", "tmpfs-for-writes"),
    ("    cap_drop:\n      - ALL\n", "", "drop-all-caps"),
    ("    security_opt:\n      - no-new-privileges:true\n", "", "no-new-privileges"),
    ("    mem_limit: 128m\n", "", "memory-limit"),
    ("    cpus: 0.5\n", "", "cpu-limit"),
    ("    pids_limit: 64\n", "", "pids-limit"),
    ('"127.0.0.1:8080:8080"', '"8080:8080"', "localhost-port"),
    ("    restart: unless-stopped\n", "    restart: unless-stopped\n    privileged: true\n", "not-privileged"),
    ("    restart: unless-stopped\n", "    restart: unless-stopped\n    cap_add:\n      - SYS_ADMIN\n", "no-cap-add"),
])
def test_each_compose_rule_catches_its_own_violation(old, new, rule):
    text = compose_text()
    assert old in text
    assert rule in {f.rule for f in lint.lint_compose(text.replace(old, new))}


def test_compose_rule_ids_are_all_exercised():
    assert len(lint.COMPOSE_RULES) == 10


def test_flags_from_compose_match_the_file():
    flags = lint.flags_from_compose(compose_text())
    assert flags == ["--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt",
                     "no-new-privileges:true", "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64"]


def test_flags_follow_the_compose_file_when_it_changes():
    changed = compose_text().replace("mem_limit: 128m", "mem_limit: 256m").replace("pids_limit: 64", "pids_limit: 32")
    flags = lint.flags_from_compose(changed)
    assert flags[flags.index("--memory") + 1] == "256m" and flags[flags.index("--pids-limit") + 1] == "32"


def test_unknown_service_is_reported():
    assert lint.lint_compose(compose_text(), service="nope")[0].rule == "service"
