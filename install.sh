#!/usr/bin/env bash
# Install the dashboard on a Proxmox VE host.
#
# Safe to re-run: it replaces the program files and units, and never touches
# anything under /etc/media-dashboard that already exists (auth store, API
# tokens, service credentials, site overrides).
#
# Usage, from the root of a checkout (or an unpacked bundle - same layout):
#
#   ./install.sh              # install or upgrade
#   ./install.sh --uninstall  # stop and remove, keep data
#
# There is nothing to configure. The collector works out what this host is on
# its first run - containers, addresses, storage, what runs where - and every
# other part reads that. See mdash_site.py.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=/usr/local/bin
LIB=/usr/local/lib/mdash
ETC=/etc/media-dashboard
VAR=/var/lib/media-dashboard
WWW=/var/www/dashboard
UNITS=/etc/systemd/system

# Everything in bin/ is installed to /usr/local/bin, everything in lib/ to
# /usr/local/lib/mdash. Listing the directories rather than the files means
# adding a module is a new file, not an edit here as well.
mapfile -t PROGRAMS < <(cd "$SRC/bin" 2>/dev/null && ls) || true
mapfile -t MODULES  < <(cd "$SRC/lib" 2>/dev/null && ls mdash_*.py) || true

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"

if [[ "${1:-}" == "--uninstall" ]]; then
    say "stopping and disabling units"
    systemctl disable --now media-dashboard.timer media-dashboard-web.service \
        media-dashboard-runner.service 2>/dev/null || true
    rm -f "$UNITS"/media-dashboard{,-web,-runner}.service "$UNITS"/media-dashboard.timer
    rm -rf "$UNITS"/media-dashboard-web.service.d
    systemctl daemon-reload
    # Remove what is installed rather than what happens to be next to this
    # script: --uninstall is usually run from the installed copy, which has no
    # bin/ directory beside it to enumerate.
    rm -f "$BIN"/media-dashboard.py "$BIN"/media-dashboard-*.py \
          "$BIN"/media-dashboard-*.sh "$BIN"/media-dashboard-fleet-token
    rm -rf "$LIB" /usr/local/share/media-dashboard
    say "removed. $ETC and $VAR were left in place - delete them by hand if you"
    say "really want the accounts and history gone."
    exit 0
fi

# ---------------------------------------------------------------- preflight
command -v pct       >/dev/null || die "no pct - this is not a Proxmox VE host"
command -v pvesh     >/dev/null || die "no pvesh - this is not a Proxmox VE host"
command -v python3   >/dev/null || die "python3 is required"
command -v curl      >/dev/null || die "curl is required"
python3 - <<'PY' || die "python 3.9 or newer is required"
import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)
PY

[[ ${#PROGRAMS[@]} -gt 0 ]] || die "no bin/ directory next to this script"
[[ ${#MODULES[@]}  -gt 0 ]] || die "no lib/ directory next to this script"
for f in "${PROGRAMS[@]}"; do [[ -f "$SRC/bin/$f" ]] || die "missing bin/$f"; done
for f in "${MODULES[@]}";  do [[ -f "$SRC/lib/$f" ]] || die "missing lib/$f"; done

# ss and smartctl are used for discovery and disk health. Neither is fatal:
# without ss some services are found only through Docker, and without smartctl
# the disk table simply has no health column.
command -v smartctl >/dev/null || say "note: smartmontools not installed - no disk health"

# ------------------------------------------------------------------ install
say "installing programs into $BIN"
install -m 0755 -t "$BIN" "${PROGRAMS[@]/#/$SRC/bin/}"
# The installer installs itself too, so a host can bundle and deploy onward.
install -m 0755 "$SRC/install.sh" "$BIN/media-dashboard-install.sh"

say "installing modules into $LIB"
install -d -m 0755 "$LIB"
install -m 0644 -t "$LIB" "${MODULES[@]/#/$SRC/lib/}"
# A stale bytecode cache from an older layout confuses imports after upgrade.
rm -rf "$LIB/__pycache__"

if [[ -f "$SRC/README.md" ]]; then
    install -d -m 0755 /usr/local/share/media-dashboard
    install -m 0644 "$SRC/README.md" /usr/local/share/media-dashboard/README.md
    [[ -f "$SRC/docs/DESIGN.md" ]] && install -m 0644 "$SRC/docs/DESIGN.md" \
        /usr/local/share/media-dashboard/DESIGN.md
fi

say "creating state directories"
install -d -m 0700 "$ETC"
install -d -m 0755 "$VAR" "$VAR/jobs" "$VAR/icons" "$VAR/thumbs" "$VAR/fleet" "$WWW"

# ------------------------------------------------------------------- units
say "writing systemd units"
cat > "$UNITS/media-dashboard.service" <<'UNIT'
[Unit]
Description=Regenerate the dashboard and re-detect what this host is
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/media-dashboard.py
# Detection walks every running container, so allow for a slow or busy host.
TimeoutStartSec=300
UNIT

cat > "$UNITS/media-dashboard.timer" <<'UNIT'
[Unit]
Description=Refresh the dashboard every 2 minutes

[Timer]
OnBootSec=90
OnUnitActiveSec=2min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

cat > "$UNITS/media-dashboard-runner.service" <<'UNIT'
[Unit]
Description=Run privileged dashboard maintenance jobs (updates, app deploys)
After=network-online.target pve-cluster.service

[Service]
ExecStart=/usr/local/bin/media-dashboard-runner.py
Restart=on-failure
RestartSec=5
ProtectHome=read-only
PrivateTmp=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

# The web service is deliberately the most confined of the three: it may never
# touch pct. Everything privileged is described by it and carried out by the
# runner, which re-validates each request against the live host.
cat > "$UNITS/media-dashboard-web.service" <<'UNIT'
[Unit]
Description=Serve the dashboard (with login)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/media-dashboard-web.py
Restart=on-failure
RestartSec=5
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
ReadOnlyPaths=/var/www/dashboard
ReadWritePaths=/var/lib/media-dashboard /etc/media-dashboard

[Install]
WantedBy=multi-user.target
UNIT

# The admin terminal talks to the host tmux server over its socket in /tmp.
# PrivateTmp=yes hides it, so bind that one path back in.
install -d -m 0755 "$UNITS/media-dashboard-web.service.d"
cat > "$UNITS/media-dashboard-web.service.d/10-tmux.conf" <<'UNIT'
[Service]
BindPaths=/tmp/tmux-0
UNIT

# Storage roots are detected, so grant the web service access to whatever this
# host actually shares into its guests - that is what the file browser lists.
ROOTS="$(python3 - <<'PY'
import sys
sys.path.insert(0, "/usr/local/lib/mdash")
try:
    import mdash_site as site
    roots = [r for r in ([site.shared_root()] + site.bulk_roots()) if r]
    print(" ".join(roots))
except Exception:
    print("")
PY
)"
if [[ -n "$ROOTS" ]]; then
    say "granting the web service access to detected storage: $ROOTS"
    cat > "$UNITS/media-dashboard-web.service.d/20-storage.conf" <<UNIT
# Regenerated by media-dashboard-install.sh from detected storage roots.
[Service]
ReadWritePaths=$ROOTS
UNIT
fi

systemctl daemon-reload

# ------------------------------------------------------------------ first run
# The first account created becomes the admin. Prompt when there is a terminal
# to prompt on; when there is not - a scripted or piped install - generate one
# and print it, rather than hanging forever on a password prompt nobody sees.
NEW_PW=""
if [[ ! -f "$ETC/auth.json" ]]; then
    if [[ -t 0 ]]; then
        say "no account store yet - creating an admin login"
        "$BIN/media-dashboard-passwd.py" || die "could not create the admin account"
    else
        say "no account store yet and no terminal - generating an admin password"
        NEW_PW="$("$BIN/media-dashboard-passwd.py" admin --random 2>/dev/null)" \
            || die "could not create the admin account"
    fi
fi

say "detecting what this host is (this walks every running container)"
python3 "$LIB/mdash_site.py" --detect > /dev/null || die "detection failed"

say "starting services"
systemctl enable --now media-dashboard-runner.service
systemctl enable --now media-dashboard.timer
systemctl start media-dashboard.service
systemctl enable --now media-dashboard-web.service

ADDR="$(python3 - <<'PY'
import sys
sys.path.insert(0, "/usr/local/lib/mdash")
import mdash_site as site
h, p = site.bind_addr(8085)
print(f"http://{h}:{p}")
PY
)"

say "done"
echo
if [[ -n "$NEW_PW" ]]; then
    echo "  Login:      admin / $NEW_PW"
    echo "              (change it with: media-dashboard-passwd.py admin)"
fi
echo "  Dashboard:  $ADDR"
echo "  Fleet:      $ADDR/fleet   (add other hosts there)"
echo "  Detected:   $VAR/site.json   (rewritten every collector run)"
echo "  Overrides:  $ETC/site.json   (optional; anything here wins)"
echo
echo "Nothing else needs configuring. If something was detected wrongly, copy"
echo "the offending key out of site.json into the overrides file - see the"
echo "'Overriding detection' section of the README."
echo
echo "To watch this host from another dashboard, run here:"
echo "    media-dashboard-fleet-token"
echo "and paste the answer into that dashboard's Fleet tab."
