#!/usr/bin/env bash
#
# build-dist.sh — cross-compile the release binaries locally into ./dist/,
# reproducing what .github/workflows/release.yml produces in CI.
#
# Two zip families per platform (mirroring release.yml):
#   g3-<version>-<target>.zip        : g3cli + g3tui  (6 targets)
#   g3-local-<version>-<target>.zip  : g3 + config/   (4 targets, no windows)
# plus a <zip>.sha256 alongside each. Only the zips and checksums are left in
# dist/; per-target staging dirs are removed once their zip is built.
#
# g3 is omitted from windows for the same reason release.yml omits it: it
# shells out to `docker run` with Unix-style paths that don't translate under
# Docker Desktop for Windows. The daemons (g3api/g3scanner/g3worker/g3config)
# are never cross-compiled — they only ever run inside containers.
#
# VERSION resolution (git, when available):
#   1. exact vX.Y.Z tag on HEAD   -> that tag
#   2. branch == main             -> "latest"   (matches the docker image tag)
#   3. any other branch           -> sanitized branch name
#   4. no git / detached non-tag  -> "dev"
#
# Invoked by `make dist`. Safe to run from any cwd: it relocates to the repo
# root (the script's parent dir) first.

set -euo pipefail

# Relocate to repo root so every path below is repo-relative regardless of
# where make (or the user) invoked us from.
cd "$(dirname "$0")/.."

# --- tool checks -----------------------------------------------------------
command -v go  >/dev/null 2>&1 || { echo "error: go not found in PATH" >&2; exit 1; }
command -v zip >/dev/null 2>&1 || { echo "error: zip not found in PATH (needed to package artifacts)" >&2; exit 1; }

# sha256sum (Linux) vs shasum -a 256 (macOS). Pick whichever exists so the
# target works on a dev's machine, not just the ubuntu CI runner.
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" > "$1.sha256"; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" > "$1.sha256"; }
else
  echo "error: neither sha256sum nor shasum found in PATH" >&2
  exit 1
fi

# --- version resolution ----------------------------------------------------
# Shared with the `docker` make target so the tag/branch/dev rule lives in one
# place. We're already at the repo root, so call it by relative path.
VERSION="$(./misc/git-version.sh)"
echo "==> version: $VERSION"

# --- target matrices -------------------------------------------------------
# Each entry: <label>:<goos>:<goarch>. Client zips cover all six platforms;
# the local (g3 + config/) zip skips windows, exactly like release.yml.
CLIENT_TARGETS=(
  linux-x86_64:linux:amd64
  linux-arm64:linux:arm64
  windows-x86_64:windows:amd64
  windows-arm64:windows:arm64
  macos-x86_64:darwin:amd64
  macos-arm64:darwin:arm64
)
LOCAL_TARGETS=(
  linux-x86_64:linux:amd64
  linux-arm64:linux:arm64
  macos-x86_64:darwin:amd64
  macos-arm64:darwin:arm64
)

# Same strip + path-trim + version injection release.yml uses. CGO_ENABLED=0
# is set per build invocation below so every target is a static binary.
LDFLAGS="-s -w -X github.com/golismero/g3/src/g3lib.Version=$VERSION"

# --- fresh dist/ -----------------------------------------------------------
# Wipe prior artifacts but preserve the tracked dist/.gitignore (the same
# self-ignoring `*` + `!.gitignore` pattern as bin/), so the directory stays
# version-controlled across builds.
mkdir -p dist
find dist -mindepth 1 -maxdepth 1 ! -name .gitignore -exec rm -rf {} +

# --- plugin registry (native build) ---------------------------------------
# g3config runs on the host only; build it natively (no GOOS/GOARCH) and let
# it emit config/*.json, which we stage into every local zip below.
echo "==> generating plugin registry (config/)"
( cd src/g3config && go build -trimpath -o ../../bin/g3config . )
./bin/g3config -q

# --- client zips: g3cli + g3tui -------------------------------------------
for entry in "${CLIENT_TARGETS[@]}"; do
  IFS=: read -r label goos goarch <<< "$entry"
  ext=""
  if [ "$goos" = "windows" ]; then ext=".exe"; fi
  echo "==> client build: $label"
  mkdir -p "dist/$label"
  for bin in g3cli g3tui; do
    ( cd "src/$bin" && \
      CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath -ldflags="$LDFLAGS" -o "../../dist/$label/$bin$ext" . )
  done
  # Flat zip: cd into the staging dir so the archive has the binaries at the
  # root (no embedded dist/<target>/ prefix).
  ( cd "dist/$label" && zip -q "../g3-$VERSION-$label.zip" ./* )
  sha256 "dist/g3-$VERSION-$label.zip"
  rm -rf "dist/$label"
done

# --- local zips: g3 + config/ ---------------------------------------------
for entry in "${LOCAL_TARGETS[@]}"; do
  IFS=: read -r label goos goarch <<< "$entry"
  echo "==> local build: $label"
  mkdir -p "dist/local-$label"
  ( cd src/g3 && \
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags="$LDFLAGS" -o "../../dist/local-$label/g3" . )
  # Ship config/ alongside g3 so an extracted zip is immediately runnable.
  # The .gitignore inside config/ is source-control bookkeeping only — drop
  # it from the artifact.
  cp -r config "dist/local-$label/config"
  rm -f "dist/local-$label/config/.gitignore"
  ( cd "dist/local-$label" && zip -qr "../g3-local-$VERSION-$label.zip" . )
  sha256 "dist/g3-local-$VERSION-$label.zip"
  rm -rf "dist/local-$label"
done

echo "==> done. Artifacts in dist/:"
ls -1 dist/*.zip dist/*.sha256
