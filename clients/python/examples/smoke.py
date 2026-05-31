#!/usr/bin/env python3
"""Smoke test for the g3client Python library.

Exercises the managed-scan happy path against a live g3api:
  - lists tool contracts and shared env
  - creates a managed scan
  - adds a target, runs testssl on it, fetches results + artifacts
  - deletes the scan

Usage:

    export G3_API_BASEURL=https://g3.internal
    export G3_API_TOKEN=...

    # Default target is https://www.example.net (IANA-reserved for documentation):
    python smoke.py

    # Point at another HTTPS target you control:
    python smoke.py --target https://your.test.host/

    # Inspect the scan afterwards (don't delete):
    python smoke.py --keep

ONLY scan targets you own or have explicit permission to scan.

Not covered here (alternative entry points; same managed scan can host them):
  - g3.insert_data(scan_id, [{"_type": "url", "_fp": ["g3 target ..."],
                              "url": "...", "scheme": "...", "host": "..."}])
  - g3.import_file(scan_id, tool="nmap", path="/path/to/nmap.xml")
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import textwrap

from g3client import G3Client, G3DATA_PRIMER


_MAX_RESULTS_SHOWN = 3


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        default="https://www.example.net/",
        help="HTTPS URL to scan with testssl "
             "(default: https://www.example.net/).",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Do not delete the managed scan at the end "
             "(useful for manual inspection).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=900.0,
        help="wait_for_task() ceiling, seconds (default: 900).",
    )
    args = parser.parse_args()

    base_url = os.environ.get("G3_API_BASEURL")
    token = os.environ.get("G3_API_TOKEN")
    if not base_url or not token:
        print("ERROR: set G3_API_BASEURL and G3_API_TOKEN", file=sys.stderr)
        return 2

    g3 = G3Client(base_url, token)

    # --- 1. Tool contract discovery -----------------------------------------
    print("=== /plugin/describe ===")
    tools = g3.list_tools()
    for t in tools:
        accepts = list(t.accepts) or "-"
        produces = t.produces or "-"
        print(
            f"  {t.name:20s}  accepts={str(accepts):12s}  "
            f"produces={produces:6s}  ops={len(t.operations)}"
        )
    print(f"  ({len(tools)} plugin(s) registered)")

    # --- 2. Shared env -------------------------------------------------------
    print("\n=== /config/env ===")
    env = g3.get_env()
    if env:
        for name, value in sorted(env.items()):
            print(f"  {name} = {value}")
    else:
        print("  (no G3_ENV_* variables set on the deployment)")

    # --- 3. Create a managed scan -------------------------------------------
    print("\n=== /scan/create ===")
    scan_id = g3.create_managed_scan()
    print(f"  scan_id = {scan_id}")

    try:
        # --- 4. Add the target ----------------------------------------------
        print(f"\n=== /scan/target/add  (target: {args.target}) ===")
        dataids = g3.add_targets(scan_id, [args.target])
        print(f"  dataids = {dataids}")

        # --- 5. Describe testssl. /plugin/describe only returns plugins whose
        #       .g3p declares an `llm:` block, so describe_tool() KeyErrors on
        #       plugins that aren't reachable to LLMs.
        testssl = g3.describe_tool("testssl")
        print("\n=== describe_tool('testssl') ===")
        print(f"  summary  : {testssl.summary}")
        print(f"  accepts  : {list(testssl.accepts)}")
        print(f"  produces : {testssl.produces}")
        for op in testssl.operations:
            desc = op.description or "(no description)"
            print(f"  op[{op.index}] : {desc}  -> {op.produces}")

        # testssl.g3p has three commands:
        #   [0] IPv4 host with discovered services  (needs an nmap-style host)
        #   [1] IPv6 host with discovered services  (ditto + G3_ENV_IPV6_SUPPORTED)
        #   [2] HTTPS URL                            (matches our target shape)
        # We have a URL target, so op[2] is the only sensible variant.
        # /scan/task/dispatch does NOT re-evaluate the plugin's condition, so
        # the caller is responsible for picking an index whose condition the
        # data would satisfy. Pass an HTTP URL here and op[2] still fires —
        # testssl will try to TLS-handshake against port 443 and likely fail.
        index = 2

        # --- 6. Dispatch a single task --------------------------------------
        print(f"\n=== /scan/task/dispatch  (testssl operation {index}) ===")
        task_id = g3.run_tool(
            scan_id, tool="testssl", dataid=dataids[0], index=index,
        )
        print(f"  task_id = {task_id}")

        # --- 7. Wait for terminal state (polling /scan/tasks/status) --------
        print(f"\n=== wait_for_task  (timeout={args.timeout}s) ===")
        status = g3.wait_for_task(scan_id, task_id, timeout=args.timeout)
        print(f"  state    = {status.state}")
        print(f"  worker   = {status.worker}")
        print(f"  started  = {status.started_at}")
        print(f"  finished = {status.completed_at}")
        if status.error_msg:
            print(f"  error    = {status.error_msg}")

        # --- 8. Fetch G3Data results by task id -----------------------------
        # Dump the full objects rather than summarizing — for a smoke test we
        # want to see exactly what came back, not guess at field names.
        print("\n=== /scan/data?taskid ===")
        results = g3.task_results(scan_id, task_id)
        print(f"  {len(results)} object(s) produced")
        for i, obj in enumerate(results[:_MAX_RESULTS_SHOWN]):
            print(f"  --- object {i + 1} ---")
            dump = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
            print(textwrap.indent(dump, "  "))
        if len(results) > _MAX_RESULTS_SHOWN:
            print(
                f"  ... ({len(results) - _MAX_RESULTS_SHOWN} more object(s) omitted)"
            )

        # --- 9. Download artifacts ------------------------------------------
        print("\n=== /scan/task/artifacts ===")
        with tempfile.TemporaryDirectory(prefix="g3client-smoke-") as tmp:
            artifacts_dir = g3.task_artifacts(scan_id, task_id, dest_dir=tmp)
            files = sorted(
                p.relative_to(artifacts_dir)
                for p in artifacts_dir.rglob("*")
                if p.is_file()
            )
            print(f"  extracted to {artifacts_dir}")
            for f in files:
                print(f"    {f}")

        # --- 10. G3DATA_PRIMER sanity check ---------------------------------
        print(
            f"\n=== G3DATA_PRIMER  "
            f"(first 5 lines, {len(G3DATA_PRIMER)} chars total) ==="
        )
        for line in G3DATA_PRIMER.splitlines()[:5]:
            print(f"  {line}")
        print("  ...")

    finally:
        if args.keep:
            print(f"\nKeeping scan {scan_id} (--keep)")
        else:
            print("\n=== /scan/delete ===")
            g3.delete_scan(scan_id)
            print(f"  deleted {scan_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
