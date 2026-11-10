#!/usr/bin/env bash
# Installs age from its official release into the given directory, refusing anything but the pinned digest.
set -euo pipefail

VERSION='v1.3.2'
SHA256='cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10'
DEST="${1:?usage: install_age.sh DESTINATION}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl -fsSL --retry 3 --max-time 120 -o "$WORK/age.tar.gz" \
  "https://github.com/FiloSottile/age/releases/download/$VERSION/age-$VERSION-linux-amd64.tar.gz"
echo "$SHA256  $WORK/age.tar.gz" | sha256sum -c -
mkdir -p "$DEST"
tar -xzf "$WORK/age.tar.gz" -C "$DEST" --strip-components=1 age/age age/age-keygen
"$DEST/age" --version
