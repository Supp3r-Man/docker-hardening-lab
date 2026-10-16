"""Lint Dockerfiles and the compose file by parsing them. No Docker daemon needed.

Each rule has a short id, so a stage can be required to pass some rules and be expected to
fail others. The naive Dockerfile must trip every rule below; otherwise the rules prove nothing.
"""
import re
from dataclasses import dataclass, field

from .miniyaml import parse_yaml


@dataclass
class Instruction:
    name: str
    args: str
    line: int


@dataclass
class Stage:
    image: str
    alias: str
    line: int
    instructions: list = field(default_factory=list)


@dataclass
class Finding:
    rule: str
    message: str
    line: int = 0


def parse_dockerfile(text):
    """Dockerfile text -> list of Instruction. Joins `\\` continuations, drops comments."""
    out, buf, start = [], "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if buf and stripped.startswith("#"):
            continue
        if not buf:
            start = number
        if stripped.endswith("\\"):
            buf += stripped[:-1].rstrip() + " "
            continue
        buf += stripped
        name, _, args = buf.partition(" ")
        out.append(Instruction(name.upper(), args.strip(), start))
        buf = ""
    if buf:
        name, _, args = buf.partition(" ")
        out.append(Instruction(name.upper(), args.strip(), start))
    return out


def split_stages(instructions):
    stages = []
    for ins in instructions:
        if ins.name == "FROM":
            parts = ins.args.split()
            parts = [p for p in parts if not p.startswith("--")]
            alias = parts[2] if len(parts) >= 3 and parts[1].upper() == "AS" else ""
            stages.append(Stage(parts[0], alias, ins.line))
        elif stages:
            stages[-1].instructions.append(ins)
    return stages


def parse_image_ref(ref):
    """'repo/name:tag@sha256:abc' -> (name, tag or None, digest or None)."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    last = ref.rsplit("/", 1)[-1]
    tag = None
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    return ref, tag, digest


def _external_stages(stages):
    aliases = set()
    for st in stages:
        if st.image != "scratch" and st.image not in aliases:
            yield st
        if st.alias:
            aliases.add(st.alias)


def rule_no_floating_tag(stages, _ins):
    for st in _external_stages(stages):
        _, tag, _ = parse_image_ref(st.image)
        if tag is None or tag == "latest":
            yield Finding("no-floating-tag", "%s has no version tag (or uses :latest)" % st.image, st.line)


def rule_pin_digest(stages, _ins):
    for st in _external_stages(stages):
        if not parse_image_ref(st.image)[2]:
            yield Finding("pin-digest", "%s is not pinned by digest" % st.image, st.line)


def rule_multi_stage(stages, _ins):
    if len(stages) < 2:
        yield Finding("multi-stage", "single stage: build tools and caches ship in the final image", 0)


def rule_final_nonroot(stages, _ins):
    final = stages[-1]
    users = [i for i in final.instructions if i.name == "USER"]
    if not users:
        yield Finding("final-nonroot", "final stage never sets USER, so it runs as root", final.line)
        return
    user = users[-1].args.split(":")[0].strip()
    if user in ("root", "0"):
        yield Finding("final-nonroot", "final USER is root", users[-1].line)


def rule_healthcheck(stages, _ins):
    final = stages[-1]
    checks = [i for i in final.instructions if i.name == "HEALTHCHECK"]
    if not checks or checks[-1].args.strip().upper() == "NONE":
        yield Finding("healthcheck", "final stage has no HEALTHCHECK", final.line)


def rule_pip_no_cache(stages, _ins):
    for st in stages:
        env = " ".join(i.args for i in st.instructions if i.name == "ENV")
        for i in st.instructions:
            if i.name == "RUN" and re.search(r"\bpip3?\s+install\b", i.args):
                if "--no-cache-dir" not in i.args and "PIP_NO_CACHE_DIR" not in env:
                    yield Finding("pip-no-cache", "pip install keeps its download cache in the layer", i.line)


def rule_deps_before_source(stages, _ins):
    """A dependency install must come before the source is copied, or every code edit reinstalls."""
    for st in stages:
        pip_at = next((n for n, i in enumerate(st.instructions)
                       if i.name == "RUN" and re.search(r"\bpip3?\s+install\b", i.args)), None)
        if pip_at is None:
            continue
        for i in st.instructions[:pip_at]:
            if i.name in ("COPY", "ADD") and "--from=" not in i.args:
                sources = [a for a in i.args.split()[:-1] if not a.startswith("--")]
                if any("requirements" not in s for s in sources):
                    yield Finding("deps-before-source",
                                  "source is copied before the dependency install, so code edits bust its cache", i.line)
                    return


def rule_no_remote_exec(stages, _ins):
    for st in stages:
        for i in st.instructions:
            if i.name == "ADD" and re.search(r"https?://", i.args):
                yield Finding("no-remote-exec", "ADD fetches a remote URL with no checksum", i.line)
            if i.name == "RUN" and re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b", i.args):
                yield Finding("no-remote-exec", "RUN pipes a download into a shell", i.line)


def rule_no_baked_secrets(stages, _ins):
    for st in stages:
        for i in st.instructions:
            if i.name in ("ENV", "ARG"):
                for m in re.finditer(r"([A-Z_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY)[A-Z_]*)=(\S+)", i.args, re.I):
                    if m.group(2).strip("\"'"):
                        yield Finding("no-baked-secrets", "%s has a value baked into the image" % m.group(1), i.line)


def rule_exec_form(stages, _ins):
    final = stages[-1]
    for i in final.instructions:
        body = i.args
        if i.name == "HEALTHCHECK":
            body = re.sub(r"^(--\S+\s+)*CMD\s+", "", body)
        elif i.name not in ("CMD", "ENTRYPOINT"):
            continue
        if body.strip() and not body.strip().startswith("[") and body.strip().upper() != "NONE":
            yield Finding("exec-form", "%s uses shell form, so signals do not reach the process" % i.name, i.line)


RULES = {
    "no-floating-tag": rule_no_floating_tag,
    "pin-digest": rule_pin_digest,
    "multi-stage": rule_multi_stage,
    "final-nonroot": rule_final_nonroot,
    "healthcheck": rule_healthcheck,
    "pip-no-cache": rule_pip_no_cache,
    "deps-before-source": rule_deps_before_source,
    "no-remote-exec": rule_no_remote_exec,
    "no-baked-secrets": rule_no_baked_secrets,
    "exec-form": rule_exec_form,
}

# What each stage is REQUIRED to satisfy. Stage 1 requires nothing: it is the baseline.
REQUIRED = {
    "01-naive": [],
    "02-slim-multistage": ["multi-stage", "pip-no-cache", "deps-before-source", "no-remote-exec",
                           "no-baked-secrets", "exec-form"],
    "03-nonroot-hardened": list(RULES),
    "04-runtime-locked": list(RULES),
}


def lint_dockerfile(text):
    instructions = parse_dockerfile(text)
    stages = split_stages(instructions)
    if not stages:
        raise ValueError("no FROM instruction found")
    findings = []
    for rule in RULES.values():
        findings.extend(rule(stages, instructions))
    return findings


def verdict(stage_name, text):
    """-> (findings, failed_required_rule_ids)"""
    findings = lint_dockerfile(text)
    hit = {f.rule for f in findings}
    return findings, sorted(hit & set(REQUIRED[stage_name]))


# ---- compose -------------------------------------------------------------------------------

COMPOSE_RULES = [
    "read-only-rootfs", "tmpfs-for-writes", "drop-all-caps", "no-new-privileges",
    "memory-limit", "cpu-limit", "pids-limit", "localhost-port", "not-privileged", "no-cap-add",
]


def lint_compose(text, service="web"):
    """-> list of Finding for the service in docker-compose.yml."""
    doc = parse_yaml(text)
    svc = (doc.get("services") or {}).get(service)
    if svc is None:
        return [Finding("service", "service %r not found" % service)]
    out = []
    if svc.get("read_only") is not True:
        out.append(Finding("read-only-rootfs", "read_only is not true"))
    if not svc.get("tmpfs"):
        out.append(Finding("tmpfs-for-writes", "no tmpfs: a read-only service has nowhere to write scratch files"))
    if "ALL" not in [str(c).upper() for c in (svc.get("cap_drop") or [])]:
        out.append(Finding("drop-all-caps", "cap_drop does not include ALL"))
    if "no-new-privileges:true" not in [str(s) for s in (svc.get("security_opt") or [])]:
        out.append(Finding("no-new-privileges", "security_opt lacks no-new-privileges:true"))
    if not svc.get("mem_limit"):
        out.append(Finding("memory-limit", "no mem_limit"))
    if not svc.get("cpus"):
        out.append(Finding("cpu-limit", "no cpus limit"))
    if not svc.get("pids_limit"):
        out.append(Finding("pids-limit", "no pids_limit"))
    for port in svc.get("ports") or []:
        if not str(port).startswith("127.0.0.1:"):
            out.append(Finding("localhost-port", "port %s is published on all interfaces" % port))
    if svc.get("privileged"):
        out.append(Finding("not-privileged", "privileged: true"))
    if svc.get("cap_add"):
        out.append(Finding("no-cap-add", "cap_add re-grants capabilities"))
    return out


def flags_from_compose(text, service="web"):
    """The `docker run` flags that mean the same as the compose service's runtime settings.

    Ports are left out: the measurement tool publishes its own free port.
    """
    svc = parse_yaml(text)["services"][service]
    flags = []
    if svc.get("read_only"):
        flags.append("--read-only")
    for path in svc.get("tmpfs") or []:
        flags += ["--tmpfs", str(path)]
    for cap in svc.get("cap_drop") or []:
        flags += ["--cap-drop", str(cap)]
    for opt in svc.get("security_opt") or []:
        flags += ["--security-opt", str(opt)]
    if svc.get("mem_limit"):
        flags += ["--memory", str(svc["mem_limit"])]
    if svc.get("cpus"):
        flags += ["--cpus", str(svc["cpus"])]
    if svc.get("pids_limit"):
        flags += ["--pids-limit", str(svc["pids_limit"])]
    return flags
