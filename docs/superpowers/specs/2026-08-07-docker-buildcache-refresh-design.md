# Docker buildcache refresh — design

**Date:** 2026-08-07
**Status:** approved, pending implementation
**Touches:** `.github/workflows/docker.yml`

## Problem

Every image built by `docker.yml` writes a registry build cache to
`ghcr.io/<owner>/<image>:buildcache` (`cache-to`, `mode=max`) and reads it back on the
next build (`cache-from`). When that cache goes stale, the only way to force a genuinely
cold rebuild is to browse to each of the 15 GHCR packages in the web UI and delete its
`:buildcache` version by hand. There is no way to refresh the whole set in one go.

## Considered and rejected

**A standalone "purge cache" workflow.** The original ask. A new manually-triggered
workflow that deletes the `:buildcache` version from every package, then stops.

Rejected because it solves half the problem: purging leaves the next build cold but does
not produce refreshed images, so the actual "refresh everything" goal still takes two
dispatches. It also needs an explicit list of the 15 package names, which either
duplicates the `build-and-push` matrix (a second list to keep in sync) or requires
`expand-packages: true` on `dataaxiom/ghcr-cleanup-action`, whose wildcard matching needs
a PAT — `GITHUB_TOKEN` cannot enumerate packages.

**Purge, then chain a rebuild.** Same workflow, calling `docker.yml` afterwards. Rejected
as strictly more expensive than rebuilding cold directly, for the same outcome.

## Design

No new workflow file. One `workflow_dispatch` input on `docker.yml`, consumed by one line
in the existing build step.

### 1. Declare the input

`docker.yml` currently has a bare `workflow_dispatch:`. It gains an `inputs:` block with a
single typed boolean:

```yaml
workflow_dispatch:
  inputs:
    no_cache:
      description: 'Rebuild all images without using the registry build cache'
      type: boolean
      default: false
```

`workflow_call:` stays bare. CI.yml invokes `docker.yml` on main pushes, where cache reuse
is exactly the desired behaviour; plumbing the flag through is speculative.

### 2. Consume it

Add to the `docker/build-push-action@v6` step:

```yaml
no-cache: ${{ inputs.no_cache || false }}
```

`cache-from` and `cache-to` are left untouched. `--no-cache` instructs BuildKit to ignore
imported cache regardless of `cache-from`, so no conditional expression is needed.

Two details this depends on:

- The `inputs` context is populated only for `workflow_dispatch` and `workflow_call`. On a
  `vX.Y.Z` tag push `inputs.no_cache` is null and renders as an empty string, which is not
  a valid boolean for the action. `|| false` guarantees a literal `true` or `false`.
- The `x && '' || y` idiom must be avoided here. GitHub's `&&`/`||` return values rather
  than booleans, so `true && ''` evaluates to `''`, which is falsy, and `||` falls through
  to `y` — the expression can never yield the empty branch. `docker.yml:135` already
  respects this by placing the non-empty `format(...)` in the `&&` branch. Using
  `build-push-action`'s native `no-cache` input sidesteps the trap entirely.

### 3. Nothing else changes

`cache-to` still runs on a no-cache build, so the freshly built layers **overwrite**
`:buildcache` with clean content — that is the refresh. The previous cache manifest is left
untagged, and the existing `dataaxiom/ghcr-cleanup-action` step (`delete-untagged: true`,
`docker.yml:145`) reclaims it on the same run. This removes the manual browse-and-delete
chore without adding any deletion logic.

## Operation

Dispatch `docker.yml` from `main` with the box checked: all 15 images rebuild cold and
repopulate their caches, and `:latest` is republished. The `guard` job is unaffected, so
dispatching from a `vX.Y.Z` tag also works when a release's cache needs refreshing.
`fail-fast: false` on the matrix means one image failing to build cold does not strand the
other 14.

Cold rebuilds are materially more expensive than cached ones — `g3` re-fetches Go modules,
`nikto` re-runs `osvdb2cve`, `nmap` re-runs `iana-descriptions` — so this is a deliberate,
manually-triggered operation, not a default.

## Accepted limitation

This refreshes the cache by overwriting it, not by deleting it. If a package's
`:buildcache` is corrupt in a way that makes the `cache-to` export itself fail, this
workflow will not recover it; that package's cache still has to be deleted by hand in the
GHCR UI. Accepted as the right trade for the common case — restoring the deletion path can
be revisited if that failure is ever actually observed.

## Verification

Static only: the change is two YAML fragments. Confirm `docker.yml` still parses and that
the `no_cache` checkbox appears on the workflow's Actions page. Running the workflow and
observing a cold build is the user's call, not part of implementation.
