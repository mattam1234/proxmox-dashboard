#!/usr/bin/env bash
# Install this dashboard on another Proxmox host, in one command.
#
#   media-dashboard-deploy.sh root@10.20.0.1
#   media-dashboard-deploy.sh root@10.20.0.1 --federate
#
# Bundles the current code, copies it over SSH, runs the installer there, and
# prints the new dashboard's URL and login. With --federate it also fetches the
# remote host's fleet token and adds it as a peer here, so the new host shows up
# on this dashboard's Fleet tab straight away.
#
# Needs: SSH access as root to the target (key auth, or you type the password
# the three times ssh asks). The target must be a Proxmox VE host.
set -euo pipefail

TARGET="${1:-}"
FEDERATE=0
[[ "${2:-}" == "--federate" ]] && FEDERATE=1

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ -n "$TARGET" ]] || die "usage: $(basename "$0") root@host [--federate]"
command -v ssh >/dev/null || die "ssh is required"
command -v scp >/dev/null || die "scp is required"

# Reuse one SSH connection for every step below, so key-based auth is checked
# once and password auth is typed once rather than four times.
CTL="$(mktemp -u /tmp/mdash-deploy-XXXXXX.sock)"
SSH=(ssh -o ControlMaster=auto -o ControlPath="$CTL" -o ControlPersist=120)
cleanup() { ssh -o ControlPath="$CTL" -O exit "$TARGET" 2>/dev/null || true; }
trap cleanup EXIT

say "checking $TARGET"
"${SSH[@]}" "$TARGET" true || die "cannot ssh to $TARGET"
"${SSH[@]}" "$TARGET" 'command -v pveversion >/dev/null' \
    || die "$TARGET does not look like a Proxmox VE host"
REMOTE_NAME="$("${SSH[@]}" "$TARGET" hostname)"
say "target is $REMOTE_NAME, $("${SSH[@]}" "$TARGET" 'pveversion | cut -d/ -f2')"

say "bundling"
TAR="$(mktemp -u /tmp/mdash-XXXXXX.tar.gz)"
/usr/local/bin/media-dashboard-bundle.sh "$TAR" >/dev/null || die "bundle failed"

say "copying"
scp -q -o ControlPath="$CTL" "$TAR" "$TARGET:/tmp/media-dashboard-deploy.tar.gz"
rm -f "$TAR"

say "installing on $REMOTE_NAME (this runs detection, so give it a minute)"
# The installer is fed no stdin deliberately: it then generates an admin
# password and prints it rather than waiting on a prompt that nothing can
# answer over a non-interactive channel.
OUT="$("${SSH[@]}" "$TARGET" 'set -e
    rm -rf /tmp/media-dashboard-deploy
    mkdir -p /tmp/media-dashboard-deploy
    tar -xzf /tmp/media-dashboard-deploy.tar.gz -C /tmp/media-dashboard-deploy
    cd /tmp/media-dashboard-deploy/media-dashboard
    ./install.sh < /dev/null
    rm -rf /tmp/media-dashboard-deploy /tmp/media-dashboard-deploy.tar.gz
' 2>&1)" || { echo "$OUT" >&2; die "install failed on $REMOTE_NAME"; }
echo "$OUT" | sed 's/^/    /'

if [[ $FEDERATE -eq 1 ]]; then
    say "federating $REMOTE_NAME into this dashboard"
    TOKEN="$("${SSH[@]}" "$TARGET" 'media-dashboard-fleet-token 2>/dev/null')" \
        || die "could not read the remote fleet token"
    [[ -n "$TOKEN" ]] || die "the remote host returned an empty fleet token"

    # The remote dashboard binds to its own internal bridge, which this host
    # may not be able to route. Ask it where it thinks it is, and sanity-check
    # that we can actually reach that before writing it down as a peer.
    URL="$("${SSH[@]}" "$TARGET" 'python3 -c "
import sys; sys.path.insert(0, \"/usr/local/lib/mdash\")
import mdash_site as site
h, p = site.bind_addr(8085); print(f\"http://{h}:{p}\")
"')"
    say "remote dashboard reports $URL"
    if ! curl -sf --max-time 6 -o /dev/null \
            -H "Authorization: Bearer $TOKEN" "$URL/api/fleet/export"; then
        warn "cannot reach $URL from this host"
        warn "that address is probably on a bridge this host cannot route."
        warn "add the peer by hand on /fleet using an address that IS reachable"
        warn "(the target's LAN address, or its public hostname), token:"
        echo "$TOKEN"
        exit 0
    fi
    python3 - "$REMOTE_NAME" "$URL" "$TOKEN" <<'PY'
import sys
sys.path.insert(0, "/usr/local/lib/mdash")
import mdash_fleet as fleet
name, url, token = sys.argv[1], sys.argv[2], sys.argv[3]
pid = "".join(c if c.isalnum() or c in "-_" else "-" for c in name.lower())[:48]
rows = [p for p in fleet.peers() if p["id"] != pid]
rows.append({"id": pid, "name": name, "url": url, "token": token,
             "insecure_tls": False, "enabled": True})
fleet.save_peers(rows)
entry = fleet.poll_one(next(p for p in fleet.peers() if p["id"] == pid))
print(f"peer {pid}: " + (entry["error"] or "polled OK"))
PY
    say "added - it will appear on this dashboard's Fleet tab"
fi

say "done"
