"""ASVP CLI (FR-DX-3).

Commands:
  asvp serve                 — run the control-plane API
  asvp repro <finding-id>    — emit the sanitized reproduction sequence
  asvp templates             — list the loaded check template library
  asvp demo                  — run the end-to-end demo against a local target
"""

from __future__ import annotations

import argparse
import json
import sys

from asvp.checks.template import TemplateLibrary


def _cmd_templates(_args) -> int:
    lib = TemplateLibrary.load()
    rows = sorted(lib.all(), key=lambda t: (t.domain, t.id))
    for t in rows:
        print(f"{t.id:<18} {t.domain:<13} {t.default_severity:<8} "
              f"{t.destructiveness:<9} {t.name}")
    print(f"\n{len(rows)} templates across "
          f"{len({t.domain for t in rows})} domains.")
    return 0


def _cmd_repro(args) -> int:
    """Emit the sanitized request sequence for a finding (placeholders only)."""
    from asvp.platform import Platform

    platform = Platform(db_path=args.db)
    finding = platform.findings.get(args.finding_id)
    if finding is None:
        print(f"finding '{args.finding_id}' not found in {args.db}", file=sys.stderr)
        return 1
    print(f"# Reproduction for {finding.finding_id} — {finding.title}")
    print(f"# Endpoint: {finding.endpoint_id}  Severity: {finding.severity}")
    print(f"# Set TEST_IDENTITY_TOKEN from your secrets-manager handle before running.\n")
    if finding.reproduction:
        print(json.dumps(finding.reproduction, indent=2))
    else:
        print("# No HTTP reproduction template stored for this finding type.")
    print(f"\n# Remediation:\n# {finding.remediation.strip()}")
    return 0


def _cmd_serve(args) -> int:
    import uvicorn

    from asvp.api.app import create_app
    from asvp.platform import Platform

    app = create_app(Platform(db_path=args.db))
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _cmd_demo(args) -> int:
    from asvp.demo import run_demo

    run_demo()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="asvp", description="API Security Validation Platform")
    parser.add_argument("--db", default="asvp.db", help="SQLite store path")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("templates", help="list the check template library")

    p_repro = sub.add_parser("repro", help="emit a sanitized reproduction for a finding")
    p_repro.add_argument("finding_id")

    p_serve = sub.add_parser("serve", help="run the control-plane API")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)

    sub.add_parser("demo", help="run the end-to-end demo")

    args = parser.parse_args(argv)
    return {
        "templates": _cmd_templates,
        "repro": _cmd_repro,
        "serve": _cmd_serve,
        "demo": _cmd_demo,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
