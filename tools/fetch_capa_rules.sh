#!/usr/bin/env bash
# Fetch the pinned capa-rules corpus for the coverage wave 9
# capa evidence source (event_zero/capa_evidence.py).
#
# The flare-capa wheel does not bundle its rules corpus; the
# corpus is a separate repository and is pinned here by tag,
# commit, and archive SHA-256, the same discipline the wave
# applies to every Python dependency (see requirements-capa.txt
# and validation/COVERAGE-WAVE-9-LOG.md). The archive hash is
# verified before anything is extracted; a mismatch aborts.
#
# Install location: $EZ_CAPA_RULES_HOME, or by default
# ~/.cache/event-zero/capa-rules-9.4.0, which is the location
# the adapter resolves when EZ_CAPA_RULES is not set.
set -euo pipefail

VERSION="v9.4.0"
COMMIT="2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80"
SHA256="273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669"
URL="https://github.com/mandiant/capa-rules/archive/refs/tags/${VERSION}.tar.gz"
DEST="${EZ_CAPA_RULES_HOME:-$HOME/.cache/event-zero/capa-rules-9.4.0}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "fetching capa-rules ${VERSION} (${COMMIT})"
curl -sL -o "$tmp/capa-rules.tar.gz" "$URL"
echo "${SHA256}  $tmp/capa-rules.tar.gz" | sha256sum -c -

tar -xzf "$tmp/capa-rules.tar.gz" -C "$tmp"
src="$tmp/capa-rules-9.4.0"

mkdir -p "$(dirname "$DEST")"
rm -rf "$DEST"
mv "$src" "$DEST"

cat > "$DEST/.ez-capa-rules.json" <<EOF
{"corpus": "mandiant/capa-rules", "version": "${VERSION}", "commit": "${COMMIT}", "archive_sha256": "${SHA256}"}
EOF

count="$(find "$DEST" -name '*.yml' | wc -l)"
echo "installed ${count} rule files at ${DEST}"
