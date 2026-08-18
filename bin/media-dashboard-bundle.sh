#!/usr/bin/env bash
# Pack the installed dashboard into a tarball with the same layout as the git
# repository, so a bundle and a clone install identically.
#
#   media-dashboard-bundle.sh [/where/to/put/it.tar.gz]
#
# Code only: no accounts, no API tokens, no service passwords, no facts about
# this host. The target detects its own.
set -euo pipefail

OUT="${1:-/root/media-dashboard-$(date +%Y%m%d).tar.gz}"
BIN=/usr/local/bin
LIB=/usr/local/lib/mdash
DOC=/usr/local/share/media-dashboard

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
stage="$tmp/media-dashboard"
mkdir -p "$stage/bin" "$stage/lib" "$stage/docs"

for f in "$BIN"/media-dashboard.py "$BIN"/media-dashboard-web.py \
         "$BIN"/media-dashboard-runner.py "$BIN"/media-dashboard-passwd.py \
         "$BIN"/media-dashboard-fleet-token "$BIN"/media-dashboard-deploy.sh \
         "$BIN"/media-dashboard-bundle.sh; do
    [[ -f "$f" ]] || { echo "missing $f" >&2; exit 1; }
    cp "$f" "$stage/bin/"
done
cp "$LIB"/mdash_*.py "$stage/lib/"
[[ -f "$BIN/media-dashboard-install.sh" ]] \
    || { echo "missing $BIN/media-dashboard-install.sh" >&2; exit 1; }
cp "$BIN/media-dashboard-install.sh" "$stage/install.sh"
[[ -f "$DOC/README.md" ]] && cp "$DOC/README.md" "$stage/"
[[ -f "$DOC/DESIGN.md" ]] && cp "$DOC/DESIGN.md" "$stage/docs/"

chmod 0755 "$stage/install.sh" "$stage"/bin/*

# A bundle that accidentally carried a token would be a quiet disaster, so
# check rather than trust the file list above.
if grep -rlEi 'BEGIN [A-Z ]*PRIVATE KEY|[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{20,}' \
        "$stage" 2>/dev/null | grep -q .; then
    echo "refusing to bundle: something staged looks like a credential" >&2
    exit 1
fi

tar -czf "$OUT" -C "$tmp" media-dashboard
echo "wrote $OUT"
echo
echo "On the target Proxmox host:"
echo "  tar -xzf $(basename "$OUT") && cd media-dashboard && ./install.sh"
