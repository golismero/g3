# g3client

Python wrapper for the managed half of `g3api` — the part of golismero3 that
hosts on-demand task dispatch for external clients (knife agents and others).

## Install

From the repo:

    pip install ./clients/python

## Usage

    from g3client import G3Client, G3DATA_PRIMER

    g3 = G3Client("https://g3.internal", token="…")

    scan_id = g3.create_managed_scan()
    [dataid] = g3.add_targets(scan_id, ["https://example.com"])

    task_id = g3.run_tool(scan_id, tool="nikto", dataid=dataid)
    g3.wait_for_task(scan_id, task_id)

    issues = g3.task_results(scan_id, task_id)
    artifacts_dir = g3.task_artifacts(scan_id, task_id, dest_dir="/work")

    g3.delete_scan(scan_id)

The library is scan-scoped and data-only: the caller supplies scan IDs and
data IDs. Engagement ↔ scan mapping and `@mcp.tool` registration are the
consumer's concern.

`G3DATA_PRIMER` is a string constant describing the shared G3Data envelope
and common types, intended to be fed to an LLM ahead of the per-tool
contracts returned by `list_tools()`.
