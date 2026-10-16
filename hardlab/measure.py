"""Build each stage, time it, look inside the running container, and scan it.

Everything here talks to a real Docker daemon. The numbers are written to
results/summary.json; hardlab/parse.py turns raw Docker output into those numbers.
"""
import datetime
import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from . import docker, lint
from .parse import (interpret_diag, parse_build_log, parse_diag, parse_inspect, parse_trivy,
                    summarize)

ROOT = Path(__file__).resolve().parent.parent
TRIVY_IMAGE = "aquasec/trivy:latest"
TRIVY_CACHE_VOLUME = "hardlab-trivy-cache"

# python is where the image keeps it; diag_path is where app/diag.py ends up in that image.
STAGES = {
    "01-naive": {"python": "python", "diag_path": "/app/app/diag.py", "mode": "default"},
    "02-slim-multistage": {"python": "python", "diag_path": "/app/diag.py", "mode": "default"},
    "03-nonroot-hardened": {"python": "/usr/bin/python3.11", "diag_path": "/app/diag.py", "mode": "default"},
    "04-runtime-locked": {"python": "/usr/bin/python3.11", "diag_path": "/app/diag.py", "mode": "locked"},
}


def tag_for(stage):
    return "hardlab/%s:measure" % stage


def locked_flags():
    return lint.flags_from_compose((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def mode_flags(mode):
    return locked_flags() if mode == "locked" else []


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_context(dest):
    """A throwaway copy of the build context, so timing edits never touch the repo."""
    dest = Path(dest)
    shutil.copytree(ROOT / "app", dest / "app")
    shutil.copytree(ROOT / "docker", dest / "docker")
    return dest


def measure_build(stage, repeats):
    """Cold builds (--no-cache) and warm builds (cache on, one code line changed)."""
    meta = STAGES[stage]
    dockerfile = "docker/%s.Dockerfile" % stage
    tag = tag_for(stage)
    cold = []
    with tempfile.TemporaryDirectory(prefix="hardlab-ctx-") as tmp:
        ctx = make_context(tmp)
        for _ in range(repeats):
            seconds, _log = docker.timed_build(ctx, dockerfile, tag, no_cache=True)
            cold.append(seconds)
        warm, cached, steps = [], [], 0
        server = ctx / "app" / "server.py"
        for i in range(repeats):
            server.write_text(server.read_text(encoding="utf-8") + "\n# edit %d\n" % i, encoding="utf-8")
            seconds, log = docker.timed_build(ctx, dockerfile, tag)
            counts = parse_build_log(log)
            warm.append(seconds)
            cached.append(counts["cached"])
            steps = counts["steps"]
    return {
        "cold_s": summarize(cold),
        "warm_s": summarize(warm),
        "cold_runs_s": [round(x, 2) for x in cold],
        "warm_runs_s": [round(x, 2) for x in warm],
        "warm_steps_total": steps,
        "warm_steps_cached": summarize(cached)["median"],
        "warm_steps_cached_runs": cached,
        "dockerfile": dockerfile,
        "python": meta["python"],
    }


def run_diag(stage, flags):
    meta = STAGES[stage]
    proc = docker.run(["run", "--rm", "--label", docker.LABEL] + flags +
                      ["--entrypoint", meta["python"], tag_for(stage), meta["diag_path"]], timeout=120)
    return interpret_diag(parse_diag(proc.stdout))


def run_service(stage, flags, wait_s=45):
    """Start the real service, poke it, and stop it with SIGTERM like an orchestrator would."""
    port = free_port()
    name = "hardlab-%s-%d" % (stage, port)
    docker.run(["run", "-d", "--name", name, "--label", docker.LABEL, "-p", "127.0.0.1:%d:8080" % port]
               + flags + [tag_for(stage)])
    result = {"http_ok": False, "sign_ok": False, "health": "none", "stop_seconds": None, "exit_code": None}
    try:
        deadline = time.time() + 15
        while time.time() < deadline and not result["http_ok"]:
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/healthz" % port, timeout=2) as r:
                    result["http_ok"] = r.status == 200
            except OSError:
                time.sleep(0.3)
        if result["http_ok"]:
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/sign?msg=hello" % port, timeout=2) as r:
                    result["sign_ok"] = json.loads(r.read()).get("msg") == "hello"
            except (OSError, ValueError):
                pass
        has_check = parse_inspect(docker.image_inspect(tag_for(stage)))["healthcheck"]
        if has_check:
            deadline = time.time() + wait_s
            while time.time() < deadline:
                status = docker.run(["inspect", "--format", "{{.State.Health.Status}}", name]).stdout.strip()
                result["health"] = status
                if status in ("healthy", "unhealthy"):
                    break
                time.sleep(1)
        start = time.perf_counter()
        docker.run(["stop", name], timeout=60)
        result["stop_seconds"] = round(time.perf_counter() - start, 2)
        result["exit_code"] = int(docker.run(["inspect", "--format", "{{.State.ExitCode}}", name]).stdout.strip())
    finally:
        docker.run(["rm", "-f", name], check=False)
    return result


def scan_images(stages, workdir):
    """Vulnerability counts per image with Trivy, run as a container. Returns (per_stage, meta)."""
    meta = {"tool": "trivy", "skipped": None}
    pulled_trivy = not docker.image_exists(TRIVY_IMAGE)
    per_stage = {}
    try:
        for stage in stages:
            tar = Path(workdir) / (stage + ".tar")
            docker.run(["save", "-o", str(tar), tag_for(stage)], timeout=300)
            proc = docker.run(["run", "--rm", "--label", docker.LABEL, "-v", "%s:/in:ro" % workdir,
                               "-v", "%s:/root/.cache" % TRIVY_CACHE_VOLUME, TRIVY_IMAGE, "image",
                               "--input", "/in/%s.tar" % stage, "--format", "json", "--quiet",
                               "--scanners", "vuln"], timeout=900, check=False)
            if proc.returncode != 0:
                meta["skipped"] = "trivy failed: " + (proc.stderr or proc.stdout).strip()[-300:]
                return {}, meta
            per_stage[stage] = parse_trivy(proc.stdout)
            tar.unlink()
        ver = docker.run(["run", "--rm", "-v", "%s:/root/.cache" % TRIVY_CACHE_VOLUME, TRIVY_IMAGE,
                          "version", "--format", "json"], check=False)
        try:
            info = json.loads(ver.stdout)
            meta["version"] = info.get("Version")
            meta["db_updated_at"] = (info.get("VulnerabilityDB") or {}).get("UpdatedAt")
        except ValueError:
            pass
        return per_stage, meta
    except (docker.DockerError, subprocess.TimeoutExpired) as exc:
        meta["skipped"] = "trivy could not run: %s" % str(exc)[-300:]
        return {}, meta
    finally:
        docker.run(["volume", "rm", "-f", TRIVY_CACHE_VOLUME], check=False)
        if pulled_trivy:
            docker.run(["image", "rm", "-f", TRIVY_IMAGE], check=False)


def ensure_bases(stages, log=print):
    """Pull any base image a stage needs that is not already local, so builds never time a pull."""
    bases = json.loads((ROOT / "docker" / "base-images.json").read_text(encoding="utf-8"))["images"]
    for ref, meta in bases.items():
        if set(meta["used_by"]) & set(stages) and not docker.image_exists(ref):
            log("   pulling base image %s (not timed)" % ref)
            docker.run(["pull", "-q", ref], timeout=900)


def measure(stages=None, repeats=3, scan=True, keep=False, log=print):
    stages = stages or list(STAGES)
    if not docker.available():
        raise SystemExit("Docker daemon not reachable; start Docker and try again.")
    info = docker.server_info()
    ensure_bases(stages, log)
    results = {}
    try:
        for stage in stages:
            log("== %s: building (%d cold + %d warm)" % (stage, repeats, repeats))
            entry = {"build": measure_build(stage, repeats)}
            entry["image"] = parse_inspect(docker.image_inspect(tag_for(stage)))
            meta = STAGES[stage]
            log("   running diagnostics (default and locked)")
            matrix = {mode: run_diag(stage, mode_flags(mode)) for mode in ("default", "locked")}
            log("   running the service under mode=%s" % meta["mode"])
            service = run_service(stage, mode_flags(meta["mode"]))
            findings, failed = lint.verdict(stage, (ROOT / entry["build"]["dockerfile"]).read_text(encoding="utf-8"))
            entry.update({"mode": meta["mode"], "matrix": matrix, "service": service,
                          "lint": {"findings": sorted({f.rule for f in findings}), "required_failed": failed}})
            results[stage] = entry
        scan_meta = {"tool": "trivy", "skipped": "scan disabled with --no-scan"}
        if scan:
            log("== scanning with Trivy")
            with tempfile.TemporaryDirectory(prefix="hardlab-scan-") as work:
                scans, scan_meta = scan_images(stages, work)
            for stage, value in scans.items():
                results[stage]["scan"] = value
            if scan_meta.get("skipped"):
                log("   scan skipped: %s" % scan_meta["skipped"])
    finally:
        if not keep:
            docker.cleanup_labelled()
    summary = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "docker": info,
        "repeats": repeats,
        "notes": ["Base images were pulled before timing, so builds measure the build, not the network pull.",
                  "Cold = docker build --no-cache. Warm = cache on after changing one line of app/server.py."],
        "scan": scan_meta,
        "stages": results,
    }
    out = ROOT / "results" / "summary.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    log("wrote %s" % out)
    return summary
