"""A thin wrapper around the docker CLI. Everything that touches the daemon goes through here."""
import os
import shutil
import subprocess
import time

LABEL = "hardlab=measure"


class DockerError(RuntimeError):
    pass


def run(args, timeout=600, check=True, input_text=None):
    """Run `docker <args>`; return CompletedProcess with text stdout/stderr."""
    env = dict(os.environ, MSYS_NO_PATHCONV="1")  # Git Bash on Windows rewrites /tmp-style args
    proc = subprocess.run(["docker"] + [str(a) for a in args], capture_output=True, text=True,
                          timeout=timeout, env=env, input=input_text, encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise DockerError("docker %s failed (%d): %s" % (" ".join(str(a) for a in args[:3]), proc.returncode,
                                                           (proc.stderr or proc.stdout).strip()[-600:]))
    return proc


def available():
    """True if the docker CLI exists and the daemon answers."""
    if shutil.which("docker") is None:
        return False
    try:
        return run(["info", "--format", "{{.ServerVersion}}"], timeout=20, check=False).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def server_info():
    out = run(["info", "--format", "{{.ServerVersion}}|{{.OperatingSystem}}|{{.Architecture}}|{{.CgroupVersion}}|{{.Driver}}"]).stdout
    version, os_name, arch, cgroup, driver = out.strip().split("|")
    return {"server_version": version, "os": os_name, "arch": arch, "cgroup_version": cgroup, "storage_driver": driver}


def timed_build(context, dockerfile, tag, no_cache=False):
    """Build and time it. Returns (seconds, plain build log)."""
    cmd = ["build", "--progress=plain", "-f", str(dockerfile), "-t", tag, "--label", LABEL]
    if no_cache:
        cmd.append("--no-cache")
    cmd.append(str(context))
    start = time.perf_counter()
    proc = run(cmd, timeout=900)
    return time.perf_counter() - start, proc.stderr + proc.stdout


def image_inspect(tag):
    return run(["image", "inspect", tag]).stdout


def image_exists(ref):
    return run(["image", "inspect", ref], check=False).returncode == 0


def cleanup_labelled():
    """Remove only what this tool created: containers, then images, carrying the lab label."""
    containers = run(["ps", "-aq", "--filter", "label=" + LABEL], check=False).stdout.split()
    if containers:
        run(["rm", "-f"] + containers, check=False)
    images = run(["image", "ls", "-q", "--filter", "label=" + LABEL], check=False).stdout.split()
    if images:
        run(["image", "rm", "-f"] + sorted(set(images)), check=False)
