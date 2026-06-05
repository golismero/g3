#!/usr/bin/env python3
"""Quickstart for the g3client library.

Demonstrates both high-level tiers against a live g3api server:

  * Tier 2 (Scanner) — an orchestrated scan that returns a report.
  * Tier 3 (Manager) — a managed scan that runs a single tool.

Configuration is read from the environment (or pass --base-url / --token):

    export G3_API_BASEURL=https://g3.internal/api
    export G3_API_TOKEN=...

Usage:

    python quickstart.py scanner scanme.example.com
    python quickstart.py manager scanme.example.com --tool nmap

This script talks to a real server; it is an example, not a test.
"""

from __future__ import annotations

import argparse
import sys

from g3client import (
    ClientError,
    Manager,
    Scanner,
)


def run_scanner(args: argparse.Namespace) -> int:
    """Tier 2: launch an orchestrated scan and print the report."""
    scanner = Scanner.from_credentials(args.base_url, args.token)

    def on_progress(p) -> None:
        print(f"  [scan] {p.status} {p.progress or 0}% {p.message}".rstrip())

    def on_log(lines) -> None:
        print(f"  [logs] +{len(lines)} line(s)")

    report = scanner.scan(
        targets=[args.target],
        pipeline=args.pipeline,
        mode=args.mode,
        report=args.report,
        on_progress=on_progress,
        on_log=on_log,
        timeout=args.timeout,
    )

    print(f"\nscan {report.scanid} finished: {report.status}")
    if report.report_bytes is not None:
        print("\n--- report ---")
        print(report.report_bytes.decode("utf-8", "replace"))
    elif report.report_path is not None:
        print(f"report saved under: {report.report_path}")
    return 0


def run_manager(args: argparse.Namespace) -> int:
    """Tier 3: own a managed scan and run a single tool to completion."""
    mgr = Manager.from_credentials(args.base_url, args.token)
    try:
        objs = mgr.add_targets([args.target])
        if not objs:
            print("no target was added", file=sys.stderr)
            return 1
        dataid = objs[0]["_id"]

        def on_status(s) -> None:
            print(f"  [scan] {s.scan_status}  ({len(s.tasks)} task(s))")

        outcome = mgr.run(
            args.tool,
            dataid,
            preset=args.preset,
            on_status=on_status,
            timeout=args.timeout,
        )

        print(f"\nrun finished: {outcome.state}")
        print(f"produced {len(outcome.data)} G3Data object(s)")
        print(f"artifacts: {outcome.artifacts_dir}")
        if outcome.error_msg:
            print(f"errors: {outcome.error_msg}")
        return 0
    finally:
        mgr.dispose()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url", default=None, help="g3api base URL (or G3_API_BASEURL)"
    )
    parser.add_argument("--token", default=None, help="bearer token (or G3_API_TOKEN)")
    parser.add_argument(
        "--timeout", type=float, default=1800, help="overall poll deadline (s)"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scanner", help="orchestrated scan (Tier 2)")
    s.add_argument("target", help="target host or URL")
    s.add_argument(
        "--pipeline", nargs="+", default=["testssl"], help="tools or piped chains"
    )
    s.add_argument("--mode", default="parallel", choices=("parallel", "sequential"))
    s.add_argument(
        "--report", default=None, help='reporter spec, e.g. "magenta" or "magenta:json"'
    )
    s.set_defaults(func=run_scanner)

    m = sub.add_parser("manager", help="managed scan (Tier 3)")
    m.add_argument("target", help="target host or URL")
    m.add_argument("--tool", default="testssl", help="tool to run")
    m.add_argument("--preset", default=None, help="optional tool preset")
    m.set_defaults(func=run_manager)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
