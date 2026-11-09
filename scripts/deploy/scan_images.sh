#!/usr/bin/env bash
# Scans the images built by compose_verify.cjs. The scanner runs from an image pinned by digest, reads saved image
# archives from a read-only mount, and gets neither the Docker socket nor a token. (The Trivy GitHub Action is
# deliberately not used: its version tags were force-pushed to malicious commits in March 2026, GHSA-69fq-xp46-6x23.)
#
# Fails on fixable CRITICAL findings in the images this project owns; HIGH findings and the AI engine are reported only.
set -euo pipefail

TRIVY='aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb'
PROJECT='sentinelai-verify'
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; docker volume rm sentinel-trivy-cache >/dev/null 2>&1 || true' EXIT

scan() { # name severity exit-code
  docker run --rm -v "$WORK:/scan:ro" -v sentinel-trivy-cache:/root/.cache "$TRIVY" image \
    --input "/scan/$1.tar" --scanners vuln --severity "$2" --ignore-unfixed --no-progress --exit-code "$3" --format table
}

status=0
for image in backend frontend ai-engine; do
  docker save "$PROJECT-$image" -o "$WORK/$image.tar"
  echo "::group::$image: fixable HIGH (report only)"
  scan "$image" HIGH 0
  echo "::endgroup::"
  gate=1
  # The AI engine's libraries are pinned to the registered models and are outside this gate.
  [ "$image" = "ai-engine" ] && gate=0
  echo "== $image: fixable CRITICAL (gate: $gate)"
  scan "$image" CRITICAL "$gate" || status=1
done
exit "$status"
