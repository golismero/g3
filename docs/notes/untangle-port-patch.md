# Untangle — future upstream port patch

**Status:** Open. Blocks widening the untangle plugin's url condition.

## The limitation

[Untangle](https://github.com/cemtopcuoglu/untangle) hardcodes the target port to **443**.
In `untangle.py`:

- `fingerprint(target_host, 443)` is called with a literal `443` from `main()`.
- `initial_redirect_check()` calls `ssock.connect((server_n, 443))` with a literal `443`.
- `send_request()` receives a `port` argument but the call chain only ever passes 443.

There is no `-p` / `--port` flag, and the CLI only accepts `-t <hostname>` (a bare
hostname — not a URL, scheme, or port).

## Effect on the g3 plugin

The `untangle.g3p` url command is gated to **default-port HTTPS only**:

```
condition: "{{if and .url (eq .scheme \"https\") (not (contains .host \":\"))}} true {{else}} false {{end}}"
```

So an HTTPS URL on a non-standard port (e.g. `https://example.com:8443/`) will **not**
trigger untangle, because the tool would be handed a `host:port` string (or would silently
hit 443 anyway) and misbehave. We skip it rather than produce wrong results.

## The fix

Send a PR to upstream untangle:

1. Add a port option to the arg parser (e.g. `-p/--port`, default 443).
2. Thread the port through `main()` → `fingerprint()` → `initial_redirect_check()` and
   `send_request()` (the latter already takes a `port` parameter — just stop hardcoding the
   callers).

If upstream accepts it (and we bump the pinned commit in the Dockerfile), come back and
relax the url condition to allow non-default ports, passing the port through `g3p.sh`.

See the plugin design: `docs/superpowers/specs/2026-06-18-untangle-plugin-design.md`.
