# g3client

Python client library for `g3api` (Golismero3). Golismero-only; no LLM concerns.

## Tiers

- `g3client.api` — thin, resource-grouped wrappers over every g3api endpoint.
- `g3client.scanner` — high-level helper for orchestrated scans (`scan()`).
- `g3client.manager` — high-level helper for managed scans (`Manager.run()`).

## Configuration

Pass `base_url`/`token` explicitly, or set `G3_API_BASEURL` / `G3_API_TOKEN`
(and optionally `G3_ARTIFACTS_ROOT`).

```python
from g3client import ApiClient, Scanner, Manager

api = ApiClient("https://g3.internal/api", "TOKEN")
```

See `docs/design/g3client-architecture.md` for the language-agnostic design.
