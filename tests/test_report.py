import copy

import pytest

from hardlab import report


def diag(root, caps, write_root, write_tmp=True, mem=None):
    return {"uid": 0 if root else 65532, "root": root, "caps_effective": ["CHOWN"] * caps, "caps_bounding": [],
            "no_new_privs": not root, "write_root": write_root, "write_app": root, "write_tmp": write_tmp,
            "has_shell": root, "has_pip": root, "memory_limit_bytes": mem, "pids_limit": None, "cpu_limit": None}


def stage(size, cold, warm, root, scan=None, mode="default"):
    entry = {
        "image": {"size_bytes": size, "layers": 5},
        "build": {"cold_s": {"median": cold}, "warm_s": {"median": warm}, "warm_steps_total": 8, "warm_steps_cached": 5,
                  "dockerfile": "x"},
        "mode": mode,
        "matrix": {"default": diag(root, 14 if root else 0, root), "locked": diag(False, 0, False, mem=134217728)},
        "service": {"http_ok": True, "sign_ok": True, "health": "healthy" if not root else "none",
                    "stop_seconds": 0.6, "exit_code": 0},
        "lint": {"findings": ["healthcheck", "pin-digest"] if root else [], "required_failed": []},
    }
    if scan:
        entry["scan"] = scan
    return entry


def summary(with_scan):
    scan_a = {"counts": {"CRITICAL": 1, "HIGH": 20, "MEDIUM": 40, "LOW": 60, "UNKNOWN": 0}, "total": 121, "fixable": 9}
    scan_b = {"counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 5, "UNKNOWN": 0}, "total": 7, "fixable": 0}
    return {
        "generated_at": "2026-10-16T12:00:00Z", "repeats": 3,
        "docker": {"os": "Docker Desktop", "server_version": "29.8.2", "arch": "x86_64",
                   "storage_driver": "overlayfs", "cgroup_version": "2"},
        "scan": ({"tool": "trivy", "skipped": None, "version": "0.99", "db_updated_at": "2026-10-16"} if with_scan
                 else {"tool": "trivy", "skipped": "scan disabled with --no-scan"}),
        "stages": {
            "01-naive": stage(1_640_000_000, 12.5, 9.1, True, scan_a if with_scan else None),
            "04-runtime-locked": stage(80_500_000, 8.4, 1.4, False, scan_b if with_scan else None, mode="locked"),
        },
    }


def test_tables_show_measured_values_not_placeholders():
    text = report.tables(summary(True))
    assert "| 01-naive | 1.64 GB | 5 | 12.5 s | 9.1 s | 5 of 8 | root | yes |" in text
    assert "| 04-runtime-locked | 80.5 MB | 5 | 8.4 s | 1.4 s | 5 of 8 | uid 65532 | no |" in text
    assert "Trivy 0.99" in text and "| 01-naive | - | 1 | 20 | 40 | 60 | 0 | 121 | 9 | - |" in text
    assert "`healthcheck`, `pin-digest`" in text and "| 04-runtime-locked | none |" in text
    assert "no HEALTHCHECK" in text and "healthy" in text
    assert "128.0 MB" not in text and "134.2 MB" in text  # the locked memory limit is reported in decimal MB


def test_cached_steps_show_a_range_only_when_runs_disagree():
    b = {"warm_steps_cached": 6, "warm_steps_total": 8, "warm_steps_cached_runs": [6, 6, 4]}
    assert report._cached(b) == "6 of 8 (range 4 to 6)"
    assert report._cached(dict(b, warm_steps_cached_runs=[6, 6, 6])) == "6 of 8"
    assert report._cached({"warm_steps_cached": 5, "warm_steps_total": 8}) == "5 of 8"


def test_scan_table_names_the_most_flagged_packages():
    s = summary(True)
    s["stages"]["04-runtime-locked"]["scan"]["top_packages"] = [["libpython3.11", 44], ["libc6", 29]]
    s["stages"]["04-runtime-locked"]["scan"]["os"] = "debian 12.13"
    assert "debian 12.13 | 0 | 0 | 2 | 5 | 0 | 7 | 0 | libpython3.11 (44), libc6 (29) |" in report.tables(s)


def test_tables_say_when_the_scan_was_skipped():
    text = report.tables(summary(False))
    assert "Not measured: scan disabled with --no-scan" in text
    assert "| Critical |" not in text


def test_chart_has_two_panels_without_scan_and_three_with(tmp_path):
    pytest.importorskip("matplotlib")
    a = report.chart(summary(False), tmp_path / "a.png")
    b = report.chart(summary(True), tmp_path / "b.png")
    assert a.stat().st_size > 5_000 and b.stat().st_size > a.stat().st_size * 0.9
    assert a.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_write_readme_replaces_only_the_marked_block(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("intro\n%s\nold numbers\n%s\noutro\n" % (report.MARK_START, report.MARK_END), encoding="utf-8")
    report.write_readme(summary(True), readme)
    text = readme.read_text(encoding="utf-8")
    assert text.startswith("intro\n") and text.endswith("\noutro\n")
    assert "old numbers" not in text and "29.8.2" in text and "results/hardening.png" in text
    again = copy.copy(text)
    report.write_readme(summary(True), readme)
    assert readme.read_text(encoding="utf-8") == again  # idempotent


def test_write_readme_requires_markers(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("no markers here\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        report.write_readme(summary(True), readme)
