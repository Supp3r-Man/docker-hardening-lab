import json

import pytest

from hardlab import parse

INSPECT = json.dumps([{
    "Id": "sha256:abc", "Size": 80538423,
    "Config": {"User": "65532:65532", "Entrypoint": ["/usr/bin/python3.11"], "Cmd": ["/app/server.py"],
               "Healthcheck": {"Test": ["CMD", "/usr/bin/python3.11", "/app/healthcheck.py"]}},
    "RootFS": {"Type": "layers", "Layers": ["a", "b", "c"]},
}])

BUILD_LOG = """\
#1 [internal] load build definition from 03.Dockerfile
#1 DONE 0.0s
#5 [build 2/4] WORKDIR /build
#5 CACHED
#6 [build 3/4] COPY app/requirements.txt .
#6 CACHED
#7 [build 4/4] RUN pip install --no-cache-dir --target /deps -r requirements.txt
#7 CACHED
#8 [stage-1 1/4] COPY --from=build --chown=0:0 /deps /deps
#8 CACHED
#9 [stage-1 2/4] COPY --chown=0:0 app/ /app/
#9 DONE 0.1s
#10 [stage-1 3/4] WORKDIR /app
#10 DONE 0.0s
#11 exporting to image
#11 CACHED
"""

TRIVY = json.dumps({"Results": [
    {"Target": "os", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "libc", "InstalledVersion": "1", "Severity": "HIGH", "FixedVersion": "2"},
        {"VulnerabilityID": "CVE-1", "PkgName": "libc", "InstalledVersion": "1", "Severity": "HIGH", "FixedVersion": "2"},
        {"VulnerabilityID": "CVE-2", "PkgName": "zlib", "InstalledVersion": "1", "Severity": "LOW"},
        {"VulnerabilityID": "CVE-3", "PkgName": "ssl", "InstalledVersion": "3", "Severity": "weird"},
    ]},
    {"Target": "python-pkg"},
]})


def test_decode_caps_known_masks():
    assert parse.decode_caps("0000000000000000") == []
    assert parse.decode_caps(None) == []
    default = parse.decode_caps("00000000a80425fb")
    assert len(default) == 14
    assert {"CHOWN", "NET_BIND_SERVICE", "SETUID", "NET_RAW"} <= set(default)
    assert "SYS_ADMIN" not in default
    assert parse.decode_caps("0000000000000001") == ["CHOWN"]
    assert parse.decode_caps("000001ffffffffff") == parse.CAP_NAMES  # all 41 known bits


def test_decode_caps_unknown_high_bit():
    assert parse.decode_caps("0000020000000000") == ["CAP_41"]


def test_parse_inspect():
    info = parse.parse_inspect(INSPECT)
    assert info["size_bytes"] == 80538423
    assert info["layers"] == 3
    assert info["user"] == "65532:65532"
    assert info["healthcheck"] is True
    assert info["entrypoint"] == ["/usr/bin/python3.11"]


def test_parse_inspect_healthcheck_none_and_missing():
    none = json.dumps([{"Size": 1, "Config": {"Healthcheck": {"Test": ["NONE"]}}}])
    assert parse.parse_inspect(none)["healthcheck"] is False
    missing = json.dumps({"Size": 1, "Config": {}})
    info = parse.parse_inspect(missing)
    assert info["healthcheck"] is False and info["layers"] == 0 and info["user"] == ""


def test_parse_diag_takes_last_json_line():
    out = 'warning: something\n{"uid": 1}\n{"uid": 65532, "write_root": false}\n'
    assert parse.parse_diag(out)["uid"] == 65532


def test_parse_diag_rejects_garbage():
    with pytest.raises(ValueError):
        parse.parse_diag("no json here\n")
    with pytest.raises(ValueError):
        parse.parse_diag("{not json}\n")


def test_interpret_diag():
    raw = {"uid": 0, "gid": 0, "cap_eff": "00000000a80425fb", "cap_bnd": "00000000a80425fb", "no_new_privs": "0",
           "write_root": True, "write_app": True, "write_tmp": True, "has_shell": True, "has_pip": True,
           "memory_max": "max", "pids_max": "max", "cpu_max": "max 100000"}
    d = parse.interpret_diag(raw)
    assert d["root"] and len(d["caps_effective"]) == 14 and not d["no_new_privs"]
    assert d["memory_limit_bytes"] is None and d["pids_limit"] is None and d["cpu_limit"] is None
    locked = dict(raw, uid=65532, cap_eff="0000000000000000", cap_bnd="0000000000000000", no_new_privs="1",
                  write_root=False, memory_max="134217728", pids_max="64", cpu_max="50000 100000")
    d = parse.interpret_diag(locked)
    assert not d["root"] and d["caps_effective"] == [] and d["no_new_privs"]
    assert d["memory_limit_bytes"] == 134217728 and d["pids_limit"] == 64 and d["cpu_limit"] == 0.5


def test_interpret_diag_missing_cgroup_files():
    raw = {"uid": 1, "gid": 1, "cap_eff": None, "cap_bnd": None, "no_new_privs": None, "write_root": False,
           "write_app": False, "write_tmp": False, "has_shell": False, "has_pip": False,
           "memory_max": None, "pids_max": None, "cpu_max": None}
    d = parse.interpret_diag(raw)
    assert d["memory_limit_bytes"] is None and d["cpu_limit"] is None and d["caps_effective"] == []


def test_parse_build_log_counts_only_real_steps():
    counts = parse.parse_build_log(BUILD_LOG)
    # the internal vertex (#1) and the export (#11) have no [n/m] marker, so they are not steps
    assert counts == {"steps": 6, "cached": 4}


def test_parse_trivy_dedupes_and_counts():
    v = parse.parse_trivy(TRIVY)
    assert v["counts"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "UNKNOWN": 1}
    assert v["total"] == 3 and v["fixable"] == 1
    assert v["top_packages"][0] == ["libc", 1] and len(v["top_packages"]) == 3  # ties break by name
    assert v["os"] == ""


def test_parse_trivy_reports_os_and_ranks_packages():
    report = {"Metadata": {"OS": {"Family": "debian", "Name": "12.13"}}, "Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-%d" % i, "PkgName": "libpython3.11", "InstalledVersion": "1", "Severity": "LOW"}
        for i in range(3)] + [{"VulnerabilityID": "CVE-9", "PkgName": "zlib", "InstalledVersion": "1", "Severity": "LOW"}]}]}
    v = parse.parse_trivy(json.dumps(report))
    assert v["os"] == "debian 12.13" and v["top_packages"] == [["libpython3.11", 3], ["zlib", 1]]


def test_parse_trivy_empty_report():
    assert parse.parse_trivy("{}")["total"] == 0


def test_summarize():
    assert parse.summarize([3.0, 1.0, 2.0]) == {"n": 3, "min": 1.0, "median": 2.0, "max": 3.0}
    assert parse.summarize([]) == {"n": 0, "min": None, "median": None, "max": None}
    assert parse.summarize([1.234, 2.345])["median"] == 1.79


def test_human_bytes():
    assert parse.human_bytes(80_538_423) == "80.5 MB"
    assert parse.human_bytes(1_640_000_000) == "1.64 GB"
    assert parse.human_bytes(None) == "-"
