#!/usr/bin/env bash
#
# git-version.sh — print the build version derived from git state:
#   1. exact vX.Y.Z tag on HEAD   -> that tag        (e.g. v1.2.3)
#   2. branch == main             -> "latest"        (matches the docker tag)
#   3. any other branch           -> sanitized branch name
#   4. no git / detached non-tag  -> "dev"
#
# Used by both misc/build-dist.sh (release zips) and the `docker` make target
# (image build-arg), so the version rule lives in exactly one place. Safe to
# run from any cwd: it relocates to the repo root first.

set -euo pipefail
cd "$(dirname "$0")/.."

ver=dev
if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  # --exact-match exits non-zero when HEAD carries no matching tag; `|| true`
  # keeps `set -e` happy and leaves tag empty in that case.
  tag="$(git describe --exact-match --tags --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)"
  if [ -n "$tag" ]; then
    ver="$tag"
  else
    branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    if [ "$branch" = "main" ]; then
      ver=latest
    elif [ -n "$branch" ] && [ "$branch" != "HEAD" ]; then
      # Sanitize: anything outside [A-Za-z0-9._-] becomes '-'. printf (no
      # trailing newline) so tr doesn't turn a newline into a stray '-'.
      ver="$(printf '%s' "$branch" | tr -c 'A-Za-z0-9._-' '-')"
    fi
  fi
fi
printf '%s\n' "$ver"
