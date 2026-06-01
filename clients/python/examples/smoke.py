#!/usr/bin/env python3
"""Smoke test for the g3client.llm Python library.

Exercises the data-flow API against a live g3api:
  - configures via env vars (G3_API_BASEURL, G3_API_TOKEN, G3_ARTIFACTS_ROOT)
  - constructs a Client (eagerly creates a managed scan)
  - lists tool contracts
  - adds a target, runs testssl on it, inspects the RunResult
  - exercises the persistence API (bind/unbind)
  - disposes the client (deletes the scan)

Usage:

    export G3_API_BASEURL=http://localhost/api
    export G3_API_TOKEN=...
    # optional:
    export G3_ARTIFACTS_ROOT=/tmp/g3client-smoke

    python smoke.py                              # uses default target
    python smoke.py --target https://example.net/
    python smoke.py --keep                       # don't dispose at the end

ONLY scan targets you own or have explicit permission to scan.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import uuid

import os

if "G3_API_TOKEN" not in os.environ:
    os.environ["G3_API_TOKEN"] = "changeme"
if "G3_API_BASEURL" not in os.environ:
    os.environ["G3_API_BASEURL"] = "http://localhost/api"
if "G3_API_WSURL" not in os.environ:
    os.environ["G3_API_WSURL"] = "ws://localhost/api/ws"

from g3client.llm import DATA_PRIMER, Client, TaskCancelled


_MAX_RESULTS_SHOWN = 3
_KEY = f"smoke-{uuid.uuid4()}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        default="https://www.example.net/",
        help="HTTPS URL to scan with testssl (default: https://www.example.net/).",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Do not dispose of the managed scan at the end.",
    )
    args = parser.parse_args()

    # --- 1. Construct the engagement-scoped Client (creates the managed scan)
    print(f"=== Client(key={_KEY!r})  (eager scan creation) ===")
    client = Client(_KEY)
    print(f"  scan_id        = {client.scan_id}")
    print(f"  artifacts_root = {client.artifacts_root}")
    print(f"  Client.keys()  = {Client.keys()}")

    try:
        # --- 2. Multiton check: same key returns same instance --------------
        same = Client(_KEY)
        print("\n=== Multiton ===")
        print(f"  Client(key) is Client(key)  =  {client is same}")

        # --- 3. Tool contract discovery -------------------------------------
        print("\n=== client.list_tools() ===")
        tools = client.list_tools()
        for t in tools:
            accepts = list(t.accepts)
            produces = list(t.produces)
            print(
                f"  {t.name:14s}  accepts={str(accepts):18s}  "
                f"produces={produces}"
            )
        print(f"  ({len(tools)} LLM-reachable plugin(s))")

        # --- 4. Shared env --------------------------------------------------
        print("\n=== client.get_env() ===")
        env = client.get_env()
        if env:
            for name, value in sorted(env.items()):
                print(f"  {name} = {value}")
        else:
            print("  (no G3_ENV_* variables set on the deployment)")

        # --- 5. Data-flow: add_target -> run -------------------------------
        print(f"\n=== client.add_target({args.target!r}) ===")
        url_obj = client.add_target(args.target)
        dump = json.dumps(url_obj, indent=2, sort_keys=True, ensure_ascii=False)
        print(textwrap.indent(dump, "  "))

        print("\n=== client.describe_tool('testssl') ===")
        testssl = client.describe_tool("testssl")
        print(f"  summary  : {testssl.summary}")
        print(f"  accepts  : {list(testssl.accepts)}")
        print(f"  produces : {list(testssl.produces)}")

        print("\n=== client.run(url_obj, 'testssl') ===")
        print("  (server auto-evaluates conditions; library polls, fetches results")
        print("   and artifacts, aggregates state — all transparent to the caller)")
        try:
            result = client.run(url_obj, "testssl")
        except TaskCancelled as exc:
            print(f"  ! TASK CANCELLED — task_ids={list(exc.task_ids)}")
            print(f"    partial data: {len(exc.partial_data)} object(s)")
            return 1

        print(f"  state         = {result.state}")
        print(f"  task_ids      = {list(result.task_ids)}")
        print(f"  artifacts_dir = {result.artifacts_dir}")
        if result.error_msg:
            print(f"  error_msg     = {result.error_msg}")

        # --- 6. The data the LLM receives -----------------------------------
        print(f"\n=== RunResult.data  ({len(result.data)} object(s)) ===")
        for i, obj in enumerate(result.data[:_MAX_RESULTS_SHOWN]):
            print(f"  --- object {i + 1} ---")
            dump = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
            print(textwrap.indent(dump, "  "))
        if len(result.data) > _MAX_RESULTS_SHOWN:
            omitted = len(result.data) - _MAX_RESULTS_SHOWN
            print(f"  ... ({omitted} more object(s) omitted)")

        # --- 7. Artifacts tree ---------------------------------------------
        print(f"\n=== artifacts tree under {result.artifacts_dir} ===")
        for path in sorted(result.artifacts_dir.rglob("*")):
            if path.is_file():
                rel = path.relative_to(result.artifacts_dir)
                print(f"  {rel}")

        # --- 8. Persistence API: unbind, rebind, verify identity preserved --
        print("\n=== Persistence: unbind/bind (knife-restart simulation) ===")
        saved_scan_id = client.scan_id
        Client.unbind(_KEY)
        print(f"  after unbind: Client.keys() = {Client.keys()}")
        Client.bind(_KEY, saved_scan_id)
        client = Client(_KEY)
        print(f"  after bind:   Client.keys() = {Client.keys()}")
        print(f"  scan_id round-tripped       =  {client.scan_id == saved_scan_id}")

        # --- 9. DATA_PRIMER sanity ----------------------------------------
        print(
            f"\n=== DATA_PRIMER  (first 5 lines, {len(DATA_PRIMER)} chars total) ==="
        )
        for line in DATA_PRIMER.splitlines()[:5]:
            print(f"  {line}")
        print("  ...")

    finally:
        if args.keep:
            print(f"\nKeeping scan {client.scan_id} (--keep).")
            print("To clean up later:")
            print(
                f"  python -c 'from g3client.llm import Client; "
                f"Client.bind({_KEY!r}, {client.scan_id!r}); "
                f"Client({_KEY!r}).dispose()'"
            )
        else:
            print("\n=== client.dispose() ===")
            scan_id = client.scan_id
            client.dispose()
            print(f"  deleted scan {scan_id}")
            print(f"  Client.keys()  = {Client.keys()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
