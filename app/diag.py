"""Print what the container looks like from the inside, as one JSON line.

Run with the image's own python (`docker run --entrypoint <python> <image> /app/diag.py`) so
it works even in images that have no shell. The measurement tool reads this output.
"""
import json
import os


def status_field(name):
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith(name + ":"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None


def can_write(directory):
    path = os.path.join(directory, ".hardlab_probe")
    try:
        with open(path, "w") as f:
            f.write("x")
        os.remove(path)
        return True
    except OSError:
        return False


def cgroup(name):
    try:
        with open("/sys/fs/cgroup/" + name) as f:
            return f.read().strip()
    except OSError:
        return None


print(json.dumps({
    "uid": os.getuid(),
    "gid": os.getgid(),
    "cap_eff": status_field("CapEff"),
    "cap_bnd": status_field("CapBnd"),
    "no_new_privs": status_field("NoNewPrivs"),
    "write_root": can_write("/"),
    "write_app": can_write("/app"),
    "write_tmp": can_write("/tmp"),
    "has_shell": os.path.exists("/bin/sh"),
    "has_pip": any(os.path.exists(p) for p in ("/usr/local/bin/pip", "/usr/bin/pip", "/usr/bin/pip3")),
    "memory_max": cgroup("memory.max"),
    "pids_max": cgroup("pids.max"),
    "cpu_max": cgroup("cpu.max"),
}))
