"""Turn results/summary.json into README tables and a chart. Nothing here is typed in by hand."""
import json
from pathlib import Path

from .parse import SEVERITIES, human_bytes

ROOT = Path(__file__).resolve().parent.parent
MARK_START, MARK_END = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"

# Reference palette, light mode (blue = slot 1, orange = slot 2, plus the neutral inks).
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e1"
BLUE, ORANGE = "#2a78d6", "#eb6834"
SEQ = {"CRITICAL": "#0d3b78", "HIGH": "#2a78d6", "MEDIUM": "#7fb0ec", "LOW": "#c4dbf6", "UNKNOWN": "#d8d7d2"}

LABELS = {"01-naive": "1 naive", "02-slim-multistage": "2 slim\nmultistage",
          "03-nonroot-hardened": "3 non-root\nhardened", "04-runtime-locked": "4 runtime\nlocked"}


def load(path=None):
    path = Path(path or ROOT / "results" / "summary.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _cached(build):
    """'6 of 8', with the range when the runs disagreed (the build cache is shared and not always stable)."""
    runs = build.get("warm_steps_cached_runs") or []
    text = "%d of %d" % (build["warm_steps_cached"], build["warm_steps_total"])
    if runs and min(runs) != max(runs):
        text += " (range %d to %d)" % (min(runs), max(runs))
    return text


def _yn(value):
    return "yes" if value else "no"


def tables(summary):
    stages = summary["stages"]
    names = list(stages)
    scan_ok = bool(summary.get("scan") and not summary["scan"].get("skipped"))
    out = []

    head = "| Stage | Image size | Layers | Cold build | Warm rebuild (code edit) | Cached steps on rebuild | Runs as | Shell in image |"
    out += ["### What the image looks like", "", head, "|---|---|---|---|---|---|---|---|"]
    for n in names:
        s = stages[n]
        diag = s["matrix"][s["mode"]]
        b = s["build"]
        out.append("| %s | %s | %d | %.1f s | %.1f s | %s | %s | %s |" % (
            n, human_bytes(s["image"]["size_bytes"]), s["image"]["layers"], b["cold_s"]["median"],
            b["warm_s"]["median"], _cached(b),
            "root" if diag["root"] else "uid %d" % diag["uid"], _yn(diag["has_shell"])))
    out += ["", "Build times are the median of %d runs on this machine (min to max in `results/summary.json`). "
                "Layers are the image's filesystem layers." % summary["repeats"], ""]

    out += ["### What the container can do at runtime", "",
            "Each image run twice: with Docker's default flags, and with the stage 4 lock "
            "(flags derived from `docker-compose.yml`). Capabilities are the kernel's effective set inside the container.", "",
            "| Stage | Run as | Default: capabilities | Default: write `/` | Locked: capabilities | Locked: write `/` | Locked: write `/tmp` | Memory limit (locked) |",
            "|---|---|---|---|---|---|---|---|"]
    for n in names:
        d, k = stages[n]["matrix"]["default"], stages[n]["matrix"]["locked"]
        mem = k["memory_limit_bytes"]
        out.append("| %s | %s | %d | %s | %d | %s | %s | %s |" % (
            n, "root" if d["root"] else "uid %d" % d["uid"], len(d["caps_effective"]), _yn(d["write_root"]),
            len(k["caps_effective"]), _yn(k["write_root"]), _yn(k["write_tmp"]),
            human_bytes(mem) if mem else "none"))
    out.append("")

    out += ["### Does the service still work, and does it stop cleanly?", "",
            "| Stage | Run mode | `/healthz` and `/sign` answer | Docker health status | `docker stop` | Exit code |",
            "|---|---|---|---|---|---|"]
    for n in names:
        s, v = stages[n], stages[n]["service"]
        out.append("| %s | %s | %s | %s | %s s | %s |" % (
            n, s["mode"], _yn(v["http_ok"] and v["sign_ok"]),
            v["health"] if v["health"] != "none" else "no HEALTHCHECK", v["stop_seconds"], v["exit_code"]))
    out.append("")

    sc = summary.get("scan") or {}
    if scan_ok:
        out += ["### Known vulnerabilities (Trivy %s, database updated %s)" % (sc.get("version", "?"), sc.get("db_updated_at", "?")), "",
                "| Stage | Image OS | Critical | High | Medium | Low | Unknown | Total | With a fix available | Most-flagged packages |",
                "|---|---|---|---|---|---|---|---|---|---|"]
        for n in names:
            v = stages[n].get("scan")
            if v:
                c = v["counts"]
                top = ", ".join("%s (%d)" % (name, k) for name, k in v.get("top_packages", [])[:3])
                out.append("| %s | %s | %d | %d | %d | %d | %d | %d | %d | %s |" % (
                    n, v.get("os") or "-", c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["UNKNOWN"],
                    v["total"], v["fixable"], top or "-"))
        out += ["", "A count depends on the database date, so a rerun later gives different numbers. Compare stages within one run."]
    else:
        out += ["### Known vulnerabilities", "", "Not measured: %s." % (sc.get("skipped") or "no scan data")]
    out.append("")

    out += ["### Dockerfile lint", "", "Rules are checked by parsing the files (`python -m hardlab lint`). "
            "Stage 1 is the baseline and must fail; stages 3 and 4 must pass everything.", "",
            "| Stage | Rules it breaks |", "|---|---|"]
    for n in names:
        broken = stages[n]["lint"]["findings"]
        out.append("| %s | %s |" % (n, ", ".join("`%s`" % r for r in broken) or "none"))
    return "\n".join(out) + "\n"


def chart(summary, path=None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    stages = summary["stages"]
    names = list(stages)
    labels = [LABELS.get(n, n) for n in names]
    scan_ok = bool(summary.get("scan") and not summary["scan"].get("skipped")) and all("scan" in stages[n] for n in names)
    panels = 3 if scan_ok else 2

    plt.rcParams.update({"font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
                         "xtick.color": INK2, "ytick.color": INK2, "text.color": INK})
    fig, axes = plt.subplots(1, panels, figsize=(4.6 * panels, 4.2), facecolor=SURFACE)
    xs = list(range(len(names)))

    def style(ax, title, ylabel):
        ax.set_facecolor(SURFACE)
        ax.set_title(title, loc="left", fontsize=11, color=INK, pad=12)
        ax.set_ylabel(ylabel)
        ax.set_xticks(xs)
        ax.set_xticklabels(labels, fontsize=8)
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.tick_params(length=0)

    # 1. image size
    sizes = [stages[n]["image"]["size_bytes"] / 1e6 for n in names]
    ax = axes[0]
    ax.bar(xs, sizes, width=0.5, color=BLUE, edgecolor=SURFACE, linewidth=2)
    for x, v in zip(xs, sizes):
        ax.text(x, v, "%.0f MB" % v, ha="center", va="bottom", fontsize=9, color=INK)
    style(ax, "Image size", "MB (as reported by Docker)")
    ax.set_ylim(0, max(sizes) * 1.15)

    # 2. build time, cold vs warm
    ax = axes[1]
    cold = [stages[n]["build"]["cold_s"]["median"] for n in names]
    warm = [stages[n]["build"]["warm_s"]["median"] for n in names]
    w = 0.34
    ax.bar([x - w / 2 for x in xs], cold, width=w, color=BLUE, edgecolor=SURFACE, linewidth=2, label="cold (no cache)")
    ax.bar([x + w / 2 for x in xs], warm, width=w, color=ORANGE, edgecolor=SURFACE, linewidth=2, label="warm (one code line changed)")
    for x, v in zip(xs, cold):
        ax.text(x - w / 2, v, "%.1f" % v, ha="center", va="bottom", fontsize=8, color=INK)
    for x, v in zip(xs, warm):
        ax.text(x + w / 2, v, "%.1f" % v, ha="center", va="bottom", fontsize=8, color=INK)
    style(ax, "Build time", "seconds (median)")
    ax.set_ylim(0, max(cold + warm) * 1.2)
    ax.legend(frameon=False, fontsize=8, loc="upper right")

    # 3. vulnerabilities, stacked by severity
    if scan_ok:
        ax = axes[2]
        bottoms = [0] * len(names)
        for sev in SEVERITIES:
            vals = [stages[n]["scan"]["counts"][sev] for n in names]
            if not any(vals):
                continue
            ax.bar(xs, vals, width=0.5, bottom=bottoms, color=SEQ[sev], edgecolor=SURFACE, linewidth=2, label=sev.title())
            bottoms = [b + v for b, v in zip(bottoms, vals)]
        for x, total in zip(xs, bottoms):
            ax.text(x, total, str(total), ha="center", va="bottom", fontsize=9, color=INK)
        style(ax, "Known vulnerabilities", "count (Trivy)")
        ax.set_ylim(0, max(bottoms + [1]) * 1.15)
        ax.legend(frameon=False, fontsize=8, loc="upper right")

    fig.tight_layout()
    path = Path(path or ROOT / "results" / "hardening.png")
    fig.savefig(path, dpi=140, facecolor=SURFACE)
    plt.close(fig)
    return path


def write_readme(summary, readme=None):
    readme = Path(readme or ROOT / "README.md")
    text = readme.read_text(encoding="utf-8")
    if MARK_START not in text or MARK_END not in text:
        raise SystemExit("README.md has no %s ... %s block" % (MARK_START, MARK_END))
    head, rest = text.split(MARK_START, 1)
    _, tail = rest.split(MARK_END, 1)
    sc = summary["docker"]
    setup = ("Measured on %s, Docker Engine %s (%s, %s, cgroup v%s), %d runs per timing, %s.\n\n"
             "![Image size, build time and vulnerabilities for each stage](results/hardening.png)\n\n" % (
                 sc["os"], sc["server_version"], sc["arch"], sc["storage_driver"], sc["cgroup_version"],
                 summary["repeats"], summary["generated_at"]))
    readme.write_text(head + MARK_START + "\n\n" + setup + tables(summary) + "\n" + MARK_END + tail, encoding="utf-8")
    return readme
