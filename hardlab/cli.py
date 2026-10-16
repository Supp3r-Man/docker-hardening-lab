"""python -m hardlab demo|lint|flags|measure|report|digests"""
import argparse
import json
import sys
from pathlib import Path

from . import docker, lint, measure as measure_mod, report

ROOT = Path(__file__).resolve().parent.parent


def cmd_lint(args):
    bad = 0
    for stage, required in lint.REQUIRED.items():
        text = (ROOT / "docker" / (stage + ".Dockerfile")).read_text(encoding="utf-8")
        findings, failed = lint.verdict(stage, text)
        status = "FAIL" if failed else "ok"
        bad += bool(failed)
        print("%-22s %-4s required: %-2d  rules broken: %s" % (
            stage, status, len(required), ", ".join(sorted({f.rule for f in findings})) or "none"))
        if args.verbose:
            for f in findings:
                print("    line %-3d %-20s %s" % (f.line, f.rule, f.message))
    compose = lint.lint_compose((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    print("%-22s %-4s checks: %d  broken: %s" % ("docker-compose.yml", "FAIL" if compose else "ok",
                                                  len(lint.COMPOSE_RULES), ", ".join(f.rule for f in compose) or "none"))
    return 1 if bad or compose else 0


def cmd_flags(_args):
    flags = lint.flags_from_compose((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    print("docker run -d -p 127.0.0.1:8080:8080 " + " ".join(flags) + " hardlab/04-runtime-locked:latest")
    return 0


def cmd_demo(_args):
    print("Offline demo: lint every stage and show the runtime flags. No Docker needed.\n")
    cmd_lint(argparse.Namespace(verbose=False))
    print("\nStage 4 runtime flags, derived from docker-compose.yml:")
    cmd_flags(None)
    print("\nNext: `python -m hardlab measure` builds and measures every stage (needs Docker, a few minutes).")
    return 0


def cmd_measure(args):
    summary = measure_mod.measure(stages=args.stages or None, repeats=args.repeats, scan=not args.no_scan, keep=args.keep)
    if not args.no_report and set(summary["stages"]) == set(measure_mod.STAGES):
        report.chart(summary)
        if (ROOT / "README.md").exists() and report.MARK_START in (ROOT / "README.md").read_text(encoding="utf-8"):
            report.write_readme(summary)
        print("wrote results/hardening.png and refreshed the README results block")
    return 0


def cmd_report(_args):
    summary = report.load()
    print("chart:", report.chart(summary))
    print("readme:", report.write_readme(summary))
    return 0


def cmd_digests(args):
    path = ROOT / "docker" / "base-images.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    drift = 0
    for ref, meta in data["images"].items():
        docker.run(["pull", "-q", ref], timeout=900)
        digests = json.loads(docker.run(["image", "inspect", ref, "--format", "{{json .RepoDigests}}"]).stdout)
        current = digests[0].split("@", 1)[1] if digests else None
        same = current == meta["digest"]
        drift += not same
        print("%-45s %s" % (ref, "unchanged" if same else "NEW %s (recorded %s)" % (current, meta["digest"])))
        if args.update and current:
            meta["digest"] = current
    if args.update:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print("updated %s; remember to update the FROM lines in the pinned Dockerfiles to match" % path)
    return 1 if drift and not args.update else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="hardlab", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="offline: lint the stages and show the runtime flags").set_defaults(fn=cmd_demo)
    s = sub.add_parser("lint", help="check the Dockerfiles and compose file by parsing them")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_lint)
    sub.add_parser("flags", help="print the docker run flags equivalent to docker-compose.yml").set_defaults(fn=cmd_flags)
    s = sub.add_parser("measure", help="build, run and scan every stage (needs Docker)")
    s.add_argument("--repeats", type=int, default=3, help="builds per timing (default 3)")
    s.add_argument("--stages", nargs="*", choices=list(measure_mod.STAGES))
    s.add_argument("--no-scan", action="store_true", help="skip the Trivy vulnerability scan")
    s.add_argument("--no-report", action="store_true", help="do not regenerate the chart and README block")
    s.add_argument("--keep", action="store_true", help="leave the built images in Docker")
    s.set_defaults(fn=cmd_measure)
    sub.add_parser("report", help="regenerate the chart and README block from results/summary.json").set_defaults(fn=cmd_report)
    s = sub.add_parser("digests", help="check (or --update) the recorded base image digests")
    s.add_argument("--update", action="store_true")
    s.set_defaults(fn=cmd_digests)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
