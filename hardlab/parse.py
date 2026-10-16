"""Pure parsing and arithmetic for the measurements. No Docker needed, so it is unit tested.

Everything the measurement tool learns from Docker arrives as text (JSON from `docker image
inspect`, a build log, a Trivy report, the diagnostics script's output). It is turned into
numbers here and nowhere else.
"""
import json
import re
import statistics

# Linux capability names by bit number (linux/capability.h, through CAP_CHECKPOINT_RESTORE = 40).
CAP_NAMES = [
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID",
    "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
    "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
    "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD",
    "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG",
    "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE",
]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def decode_caps(hex_mask):
    """'00000000a80425fb' -> sorted list of capability names. None or '' -> []."""
    if not hex_mask:
        return []
    mask = int(hex_mask, 16)
    names = []
    for bit in range(mask.bit_length()):
        if mask >> bit & 1:
            names.append(CAP_NAMES[bit] if bit < len(CAP_NAMES) else "CAP_%d" % bit)
    return names


def parse_inspect(text):
    """`docker image inspect <id>` JSON -> the few fields the lab reports."""
    data = json.loads(text)
    if isinstance(data, list):
        data = data[0]
    config = data.get("Config") or {}
    layers = (data.get("RootFS") or {}).get("Layers") or []
    return {
        "size_bytes": int(data["Size"]),
        "layers": len(layers),
        "user": config.get("User") or "",
        "entrypoint": config.get("Entrypoint") or [],
        "cmd": config.get("Cmd") or [],
        "healthcheck": bool(config.get("Healthcheck")) and config["Healthcheck"].get("Test") != ["NONE"],
        "id": data.get("Id", ""),
    }


def parse_diag(stdout):
    """The diagnostics script prints one JSON object; take the last line that parses as one."""
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    raise ValueError("no JSON object in diagnostics output: %r" % stdout[:200])


def interpret_diag(diag):
    """Turn raw /proc and cgroup strings into the facts the README tables show."""
    return {
        "uid": diag["uid"],
        "root": diag["uid"] == 0,
        "caps_effective": decode_caps(diag.get("cap_eff")),
        "caps_bounding": decode_caps(diag.get("cap_bnd")),
        "no_new_privs": diag.get("no_new_privs") == "1",
        "write_root": bool(diag["write_root"]),
        "write_app": bool(diag["write_app"]),
        "write_tmp": bool(diag["write_tmp"]),
        "has_shell": bool(diag["has_shell"]),
        "has_pip": bool(diag["has_pip"]),
        "memory_limit_bytes": _limit(diag.get("memory_max")),
        "pids_limit": _limit(diag.get("pids_max")),
        "cpu_limit": _cpu_limit(diag.get("cpu_max")),
    }


def _limit(value):
    if value is None or value == "max":
        return None
    return int(value)


def _cpu_limit(value):
    """cgroup v2 cpu.max is '<quota> <period>' or 'max <period>'; return CPUs, or None."""
    if not value:
        return None
    quota, period = value.split()
    if quota == "max":
        return None
    return round(int(quota) / int(period), 3)


def parse_build_log(text):
    """Count build steps and cache hits in a `docker build --progress=plain` log.

    A step is a numbered BuildKit vertex that has a bracketed name ('[2/6] COPY ...' or
    '[build 3/4] RUN ...'). A cache hit is a '#N CACHED' line for one of those.
    """
    steps = set()
    cached = set()
    for line in text.splitlines():
        m = re.match(r"#(\d+) \[(?:[\w.\-]+ )?\d+/\d+\]", line)
        if m:
            steps.add(m.group(1))
            continue
        m = re.match(r"#(\d+) CACHED", line)
        if m:
            cached.add(m.group(1))
    return {"steps": len(steps), "cached": len(cached & steps)}


def parse_trivy(text):
    """A `trivy image --format json` report -> vulnerability counts by severity."""
    report = json.loads(text)
    counts = {s: 0 for s in SEVERITIES}
    fixable = 0
    seen = set()
    packages = {}
    os_name = (report.get("Metadata") or {}).get("OS") or {}
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            key = (result.get("Target"), vuln.get("VulnerabilityID"), vuln.get("PkgName"), vuln.get("InstalledVersion"))
            if key in seen:
                continue
            seen.add(key)
            sev = vuln.get("Severity", "UNKNOWN").upper()
            counts[sev if sev in counts else "UNKNOWN"] += 1
            if vuln.get("FixedVersion"):
                fixable += 1
            packages[vuln.get("PkgName")] = packages.get(vuln.get("PkgName"), 0) + 1
    top = sorted(packages.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    return {"counts": counts, "total": sum(counts.values()), "fixable": fixable,
            "top_packages": [[name, n] for name, n in top],
            "os": ("%s %s" % (os_name.get("Family", ""), os_name.get("Name", ""))).strip()}


def summarize(values):
    """min / median / max / n of a list of numbers, rounded for display."""
    if not values:
        return {"n": 0, "min": None, "median": None, "max": None}
    return {
        "n": len(values),
        "min": round(min(values), 2),
        "median": round(statistics.median(values), 2),
        "max": round(max(values), 2),
    }


def human_bytes(n):
    """Decimal megabytes, the unit `docker images` uses."""
    if n is None:
        return "-"
    if n >= 1e9:
        return "%.2f GB" % (n / 1e9)
    return "%.1f MB" % (n / 1e6)
