#!/usr/bin/env python3
"""What *this* Proxmox host actually is, worked out at run time.

Everything else in the dashboard used to carry this host's facts inline: the
internal subnet was spelled `10.10.10.<ctid>` in five files, the service list
was fourteen hand-written dicts naming containers 201-206, and the public
hostnames were `tower-*.ixot.nl` literals. That is fine for one box and
useless on any other, so this module separates the two kinds of knowledge that
were tangled together:

  * **Portable knowledge** - the `APPS` table below. How to recognise Jellyfin,
    where its version lives, which repo publishes its releases, which icon
    belongs to it. True on every host, ships with the code, never detected.

  * **Site facts** - which container Jellyfin is in, what address that
    container answers on, which compose directory it was deployed from, what
    public hostname the tunnel gives it. True only here, always detected,
    never written down in code.

`detect()` walks the live host and produces the second kind. `load()` returns
it merged under `/etc/media-dashboard/site.json`, which is an *override* file:
anything an admin puts there wins, and a fresh install needs nothing in it.
Detection is cached in `/var/lib/media-dashboard/site.json` because it costs a
few seconds of `pct exec`, and the collector refreshes it on every run.

Deploying to a different Proxmox host therefore means copying the files and
starting the timer. No editing.
"""

import json
import os
import re
import shutil
import subprocess

CONF_FILE = "/etc/media-dashboard/site.json"          # admin overrides
CACHE_FILE = "/var/lib/media-dashboard/site.json"     # detected facts

# Ports that are infrastructure rather than a service worth drawing, and
# backing stores that are part of a stack rather than a service of their own.
IGNORE_PORTS = {22, 25, 53, 111, 323, 631, 5355}
SIDECAR_IMAGES = ("mariadb", "mysql", "postgres", "redis", "valkey", "memcached",
                  "rabbitmq", "mongo", "elasticsearch", "meilisearch", "traefik")


# --------------------------------------------------------------------- shell
def run(cmd, timeout=15):
    """Run a command, return stdout or '' on any failure."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


# ------------------------------------------------------------ portable knowledge
#
# One entry per application the dashboard knows how to speak to. Every field is
# a statement about the *project*, not about this host.
#
#   match   - how to recognise an instance. `image` substrings are matched
#             against a running container's image ref, `unit` against systemd
#             unit names, `proc` against the process holding a listening port.
#             Any one hit identifies the app.
#   icon    - slug in the selfh.st icon set the dashboard already caches.
#   repo    - GitHub repo that publishes releases; `track` pins a release line
#             when the project ships more than one (InfluxDB 2 vs 3).
#   version - how to read the installed version. See `probe_version()`.
#   manage  - how updates and start/stop are carried out when detection cannot
#             tell on its own ("arr" apps look like plain systemd units but
#             update through their own API).
#   note    - shown in the update confirm dialog when an update is not routine.
#   warn    - shown in the stop/restart confirm dialog when the blast radius is
#             wider than the service name suggests.
#
# An app that is not in this table still appears everywhere - it is discovered
# by its listening port and drawn with a generic icon. This table only makes
# the result prettier and the version checks sharper.
APPS = {
    "Jellyfin": {
        "match": {"unit": ["jellyfin"], "proc": ["jellyfin"], "image": ["jellyfin"]},
        "icon": "jellyfin", "repo": "jellyfin/jellyfin", "apt": "jellyfin",
        "version": {"http": "/System/Info/Public", "field": "Version"},
        "role": "media server",
    },
    "Jellyseerr": {
        "match": {"image": ["jellyseerr", "seerr"], "unit": ["jellyseerr"]},
        "icon": "jellyseerr", "repo": "seerr-team/seerr",
        "version": {"http": "/api/v1/status", "field": "version"},
        "note": "Upstream renamed this project (jellyseerr -> seerr) and 3.x is a "
                "major release. A stack still pinned to the old image will report "
                "a successful pull without actually moving to 3.x. Migrating means "
                "editing the compose file and reading the upstream release notes.",
        "role": "requests",
    },
    "Gameyfin": {
        "match": {"image": ["gameyfin"], "unit": ["gameyfin"]},
        "icon": "gameyfin", "repo": "gameyfin/gameyfin",
        "version": {"jar": "/opt/gameyfin/application.jar", "cache": "gameyfin"},
        "role": "game library",
    },
    "Questarr": {
        "match": {"image": ["questarr"]},
        "icon": "generic", "repo": "Doezer/Questarr",
        "version": {"docker": True},
        "role": "quests",
    },
    "RomM": {
        "match": {"image": ["rommapp/romm", "/romm"]},
        "icon": "romm", "repo": "rommapp/romm",
        "version": {"docker": True},
        "note": "Pulling also moves the bundled database, which runs schema "
                "migrations on first start - give it a minute before the UI "
                "answers again.",
        "role": "rom library",
    },
    "Prowlarr": {
        "match": {"unit": ["prowlarr"], "proc": ["Prowlarr"], "image": ["prowlarr"]},
        "icon": "prowlarr", "repo": "Prowlarr/Prowlarr", "manage": "arr",
        "version": {"arr": "v1", "config": "/var/lib/prowlarr/config.xml"},
        "role": "indexers",
    },
    "Radarr": {
        "match": {"unit": ["radarr"], "proc": ["Radarr"], "image": ["radarr"]},
        "icon": "radarr", "repo": "Radarr/Radarr", "manage": "arr",
        "version": {"arr": "v3", "config": "/var/lib/radarr/config.xml"},
        "role": "movies",
    },
    "Sonarr": {
        "match": {"unit": ["sonarr"], "proc": ["Sonarr"], "image": ["sonarr"]},
        "icon": "sonarr", "repo": "Sonarr/Sonarr", "manage": "arr",
        "version": {"arr": "v3", "config": "/var/lib/sonarr/config.xml"},
        "role": "series",
    },
    "qBittorrent": {
        "match": {"unit": ["qbittorrent"], "proc": ["qbittorrent-nox", "qbittorrent"],
                  "image": ["qbittorrent"]},
        "icon": "qbittorrent", "repo": "qbittorrent/qBittorrent",
        "apt": "qbittorrent-nox",
        "version": {"dpkg": "qbittorrent-nox"},
        "warn": "Stopping this pauses every active torrent.",
        "role": "download client",
    },
    "Dispatcharr": {
        "match": {"image": ["dispatcharr"], "unit": ["dispatcharr"]},
        "icon": "dispatcharr", "repo": "Dispatcharr/Dispatcharr",
        "version": {"docker": True},
        "role": "iptv",
    },
    "Threadfin": {
        "match": {"image": ["threadfin"], "unit": ["threadfin"]},
        "icon": "threadfin", "repo": "Threadfin/Threadfin",
        # The image inherits org.opencontainers.image.version from its Ubuntu
        # base, and the HDHomeRun endpoint only advertises major.minor, which
        # would read as "update available" forever. The binary knows the truth.
        "version": {"threadfin": True, "cache": "threadfin",
                    "http": "/discover.json", "field": "ModelNumber"},
        "role": "iptv proxy",
    },
    "Grafana": {
        "match": {"unit": ["grafana-server", "grafana"], "proc": ["grafana"],
                  "image": ["grafana"]},
        "icon": "grafana", "repo": "grafana/grafana", "apt": "grafana",
        "version": {"http": "/api/health", "field": "version"},
        "role": "dashboards",
    },
    "InfluxDB": {
        "match": {"unit": ["influxdb"], "proc": ["influxd"], "image": ["influxdb"]},
        "icon": "influxdb", "repo": "influxdata/influxdb", "track": "2.",
        "apt": "influxdb2",
        "version": {"http": "/health", "field": "version", "strip": "v"},
        "health": "/health",
        "note": "Pinned to the 2.x line. InfluxDB 3 is a separate product, not an "
                "upgrade, and apt will not cross to it.",
        "warn": "Anything reading metrics from here goes blank until it is "
                "running again.",
        "role": "metrics store",
    },
    "Immich": {
        "match": {"image": ["immich-server"], "unit": ["immich"]},
        "icon": "immich", "repo": "immich-app/immich",
        "version": {"http": "/api/server/version", "field": ["major", "minor", "patch"],
                    "join": "."},
        "note": "Immich moves fast and occasionally needs manual migration steps "
                "between releases. Worth reading the release notes.",
        "role": "photos",
    },
    "cloudflared": {
        "match": {"unit": ["cloudflared"], "proc": ["cloudflared"],
                  "image": ["cloudflared", "cloudflare/cloudflared"]},
        "icon": "cloudflare", "repo": "cloudflare/cloudflared", "apt": "cloudflared",
        "version": {"exec": "cloudflared --version", "re": r"version (\S+)"},
        # The only port it listens on is the metrics endpoint, which is a
        # diagnostic feed rather than something to open in a browser.
        "ui": False,
        "note": "Updating the tunnel daemon restarts it, so remote access drops "
                "for a few seconds.",
        "warn": "This is the tunnel connector. Stopping it cuts off access to "
                "everything from outside the LAN - including, if you are not on "
                "the LAN right now, this dashboard.",
        "role": "tunnel",
    },
    # Common enough on a Proxmox media host to be worth recognising even though
    # this particular box does not run them. Costs nothing when absent.
    "Plex": {
        "match": {"unit": ["plexmediaserver"], "proc": ["Plex Media Server"],
                  "image": ["plex"]},
        "icon": "plex", "repo": "plexinc/pms-docker",
        "version": {"docker": True}, "role": "media server",
    },
    "Bazarr": {
        "match": {"unit": ["bazarr"], "proc": ["bazarr"], "image": ["bazarr"]},
        "icon": "bazarr", "repo": "morpheus65535/bazarr",
        "version": {"docker": True}, "role": "subtitles",
    },
    "Lidarr": {
        "match": {"unit": ["lidarr"], "proc": ["Lidarr"], "image": ["lidarr"]},
        "icon": "lidarr", "repo": "Lidarr/Lidarr", "manage": "arr",
        "version": {"arr": "v1", "config": "/var/lib/lidarr/config.xml"},
        "role": "music",
    },
    "Readarr": {
        "match": {"unit": ["readarr"], "proc": ["Readarr"], "image": ["readarr"]},
        "icon": "readarr", "repo": "Readarr/Readarr", "manage": "arr",
        "version": {"arr": "v1", "config": "/var/lib/readarr/config.xml"},
        "role": "books",
    },
    "Overseerr": {
        "match": {"image": ["overseerr"], "unit": ["overseerr"]},
        "icon": "overseerr", "repo": "sct/overseerr",
        "version": {"http": "/api/v1/status", "field": "version"},
        "role": "requests",
    },
    "SABnzbd": {
        "match": {"unit": ["sabnzbd"], "proc": ["sabnzbd"], "image": ["sabnzbd"]},
        "icon": "sabnzbd", "repo": "sabnzbd/sabnzbd",
        "version": {"docker": True},
        "warn": "Stopping this pauses every active download.",
        "role": "download client",
    },
    "Nextcloud": {
        "match": {"image": ["nextcloud"], "unit": ["nextcloud"]},
        "icon": "nextcloud", "repo": "nextcloud/server",
        "version": {"docker": True}, "role": "files",
    },
    "Home Assistant": {
        "match": {"image": ["home-assistant", "homeassistant"],
                  "unit": ["home-assistant", "homeassistant"]},
        "icon": "home-assistant", "repo": "home-assistant/core",
        "version": {"docker": True}, "role": "automation",
    },
    "AdGuard Home": {
        "match": {"image": ["adguardhome"], "unit": ["AdGuardHome"],
                  "proc": ["AdGuardHome"]},
        "icon": "adguard-home", "repo": "AdguardTeam/AdGuardHome",
        "version": {"http": "/control/status", "field": "version", "strip": "v"},
        "role": "dns",
    },
    "Pi-hole": {
        "match": {"image": ["pihole"], "unit": ["pihole-FTL"], "proc": ["pihole-FTL"]},
        "icon": "pi-hole", "repo": "pi-hole/pi-hole",
        "version": {"docker": True}, "role": "dns",
    },
    "Uptime Kuma": {
        "match": {"image": ["uptime-kuma"], "unit": ["uptime-kuma"]},
        "icon": "uptime-kuma", "repo": "louislam/uptime-kuma",
        "version": {"docker": True}, "role": "monitoring",
    },
    "Vaultwarden": {
        "match": {"image": ["vaultwarden"], "unit": ["vaultwarden"]},
        "icon": "vaultwarden", "repo": "dani-garcia/vaultwarden",
        "version": {"docker": True}, "role": "passwords",
    },
    "Paperless-ngx": {
        "match": {"image": ["paperless-ngx"], "unit": ["paperless"]},
        "icon": "paperless-ngx", "repo": "paperless-ngx/paperless-ngx",
        "version": {"docker": True}, "role": "documents",
    },
    "Navidrome": {
        "match": {"image": ["navidrome"], "unit": ["navidrome"], "proc": ["navidrome"]},
        "icon": "navidrome", "repo": "navidrome/navidrome",
        "version": {"docker": True}, "role": "music",
    },
    "Audiobookshelf": {
        "match": {"image": ["audiobookshelf"], "unit": ["audiobookshelf"]},
        "icon": "audiobookshelf", "repo": "advplyr/audiobookshelf",
        "version": {"docker": True}, "role": "audiobooks",
    },
    "Calibre-Web": {
        "match": {"image": ["calibre-web"], "unit": ["calibre-web"]},
        "icon": "calibre-web", "repo": "janeczku/calibre-web",
        "version": {"docker": True}, "role": "books",
    },
    "Nginx Proxy Manager": {
        "match": {"image": ["nginx-proxy-manager"], "unit": ["npm"]},
        "icon": "nginx-proxy-manager", "repo": "NginxProxyManager/nginx-proxy-manager",
        "version": {"docker": True}, "role": "reverse proxy",
    },
    "Portainer": {
        "match": {"image": ["portainer"], "unit": ["portainer"]},
        "icon": "portainer", "repo": "portainer/portainer",
        "version": {"docker": True}, "role": "container ui",
    },
}

# Canonical name for a bare process or unit name, used when a discovered
# service has no APPS entry but its name is still recognisable.
_MATCH_CACHE = None


def _match_index():
    """Reverse index from every match token to its canonical app name."""
    global _MATCH_CACHE
    if _MATCH_CACHE is not None:
        return _MATCH_CACHE
    idx = {"image": [], "unit": {}, "proc": {}}
    for name, meta in APPS.items():
        m = meta.get("match", {})
        for tok in m.get("image", []):
            idx["image"].append((tok.lower(), name))
        for tok in m.get("unit", []):
            idx["unit"][tok.lower()] = name
        for tok in m.get("proc", []):
            idx["proc"][tok.lower()] = name
    # Longest image token first, so "immich-server" beats a bare "immich".
    idx["image"].sort(key=lambda t: -len(t[0]))
    _MATCH_CACHE = idx
    return idx


def identify(image=None, unit=None, proc=None):
    """Canonical app name for a running thing, or None if we do not know it."""
    idx = _match_index()
    if image:
        low = image.lower()
        for tok, name in idx["image"]:
            if tok in low:
                return name
    for key, val in (("unit", unit), ("proc", proc)):
        if val:
            hit = idx[key].get(val.lower().replace(".service", ""))
            if hit:
                return hit
    return None


def app_meta(name):
    """Portable knowledge for an app, or an empty dict for a discovered one."""
    return APPS.get(name, {})


def is_sidecar(image):
    """True for the databases and caches that back a stack rather than being it.

    They publish no useful UI and their versions track the stack that owns
    them, so drawing them as services of their own is just noise.
    """
    low = (image or "").lower()
    return any(s in low for s in SIDECAR_IMAGES)


# ------------------------------------------------------------------ detection
def _bridges():
    """Which bridge is the uplink and which is the internal one.

    The uplink is whichever interface carries the default route - it is DHCP on
    this host and its address changes, so it is never a fixed fact. Anything
    else with an address and at least one guest veth on it is internal; if a
    host has several, the one carrying the most guests wins.
    """
    addrs = {}
    for line in run("ip -o -4 addr show scope global").splitlines():
        p = line.split()
        if len(p) >= 4:
            addrs.setdefault(p[1], p[3])        # iface -> a.b.c.d/len

    m = re.search(r"dev (\S+)", run("ip route show default"))
    uplink = m.group(1) if m else ""

    # Count guest interfaces enslaved to each bridge.
    counts = {}
    for br in addrs:
        n = len(os.listdir(f"/sys/class/net/{br}/brif")) \
            if os.path.isdir(f"/sys/class/net/{br}/brif") else 0
        counts[br] = n

    internal = ""
    best = -1
    for br, cidr in addrs.items():
        if br == uplink or br == "lo":
            continue
        if counts.get(br, 0) > best:
            internal, best = br, counts.get(br, 0)
    # Single-bridge hosts are legitimate: guests share the uplink. Fall back to
    # it rather than pretending there is no internal network at all.
    if not internal:
        internal = uplink

    def split(iface):
        cidr = addrs.get(iface, "")
        ip = cidr.split("/")[0]
        return {"iface": iface, "cidr": cidr, "ip": ip}

    return {"uplink": split(uplink), "internal": split(internal)}


def _guests():
    """Every non-template guest, with its primary address, from the live host."""
    rows = []
    out = run("pvesh get /cluster/resources --type vm --output-format json", timeout=25)
    try:
        for g in json.loads(out or "[]"):
            if g.get("template"):
                continue
            rows.append({"id": g.get("vmid"),
                         "name": g.get("name") or str(g.get("vmid")),
                         "type": g.get("type") or "lxc",
                         "status": g.get("status") or "unknown"})
    except Exception:
        pass
    if not rows:                        # pvesh unavailable - fall back to the CLIs
        for kind, cmd in (("lxc", "pct list"), ("qemu", "qm list")):
            for line in run(cmd).splitlines()[1:]:
                p = line.split()
                if p and p[0].isdigit():
                    rows.append({"id": int(p[0]),
                                 "name": p[-1] if kind == "lxc" else p[1],
                                 "type": kind,
                                 "status": p[1] if kind == "lxc" else p[2]})
    for g in rows:
        g["ip"] = _guest_ip(g)
    rows.sort(key=lambda r: r["id"])
    return rows


def _guest_ip(g):
    """Primary IPv4 of a guest, from its config or its QEMU guest agent.

    DHCP containers have no address in the config, so the running guest is
    asked directly - which is also the only thing that works for a guest whose
    address was changed after creation.
    """
    if g["type"] == "lxc":
        cfg = run(f"pct config {g['id']}", timeout=10)
        m = re.search(r"ip=([0-9.]+)", cfg)
        if m:
            return m.group(1)
        if g["status"] == "running":
            out = run(f"pct exec {g['id']} -- ip -o -4 addr show scope global",
                      timeout=10)
            m = re.search(r"inet ([0-9.]+)", out)
            if m:
                return m.group(1)
        return ""
    out = run(f"qm guest cmd {g['id']} network-get-interfaces", timeout=10)
    try:
        for nic in json.loads(out or "[]"):
            for a in nic.get("ip-addresses") or []:
                ip = a.get("ip-address", "")
                if a.get("ip-address-type") == "ipv4" and not ip.startswith("127."):
                    return ip
    except Exception:
        pass
    return ""


def _storage(guests):
    """Shared and bulk storage, from what is actually bind-mounted into guests.

    A path mounted into several containers is the shared scratch/library tree;
    the separate filesystems underneath a common parent are the bulk disks.
    Both are read off the pct configs rather than assumed to be /srv/media and
    /srv/disks, so a host that keeps its media somewhere else still works.
    """
    mounts = {}                          # host path -> [(cid, ct path, ro)]
    for g in guests:
        if g["type"] != "lxc":
            continue
        for line in run(f"pct config {g['id']}", timeout=10).splitlines():
            if not re.match(r"^mp\d+:", line):
                continue
            parts = line.split(":", 1)[1].strip().split(",")
            host_path = parts[0]
            ro = any(p.strip() == "ro=1" for p in parts)
            ct_path = next((p[3:] for p in parts if p.startswith("mp=")), host_path)
            mounts.setdefault(host_path, []).append([g["id"], ct_path, ro])

    # A bulk root is a directory whose children are separate mounted
    # filesystems - that is what /srv/disks is here, without naming it.
    parents = {}
    for path in mounts:
        parent = os.path.dirname(path.rstrip("/"))
        if parent and parent != "/":
            parents.setdefault(parent, []).append(path)
    bulk_roots = []
    for parent, kids in parents.items():
        real = [k for k in kids
                if run(f"findmnt -rno TARGET --target {k} 2>/dev/null",
                       timeout=8) == k]
        if len(real) >= 2:
            bulk_roots.append(parent)

    # The shared tree is the most widely mounted path that is not a bulk disk.
    bulk_children = {k for p in bulk_roots for k in parents.get(p, [])}
    shared = ""
    best = 0
    for path, users in mounts.items():
        if path in bulk_children:
            continue
        if len(users) > best:
            shared, best = path, len(users)

    return {"shared": shared, "bulk_roots": sorted(bulk_roots), "mounts": mounts}


def _docker_inventory(cid):
    """Running containers in one CT: name, image, compose dir, published ports.

    The compose working directory comes from the label Docker Compose stamps on
    every container it starts, so update and restart actions know where to run
    without anyone writing /opt/<app> down anywhere.
    """
    fmt = ('{{.Names}}\t{{.Image}}\t'
           '{{.Label "com.docker.compose.project.working_dir"}}\t{{.Ports}}')
    out = run(f"pct exec {cid} -- docker ps --format '{fmt}'", timeout=15)
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 4:
            continue
        ports = sorted({int(m.group(1)) for m in re.finditer(r":(\d+)->", p[3])})
        rows.append({"name": p[0].strip(), "image": p[1].strip(),
                     "dir": p[2].strip(), "ports": ports})
    return rows


def _units(cid):
    """Running systemd service unit names in one CT."""
    out = run(f"pct exec {cid} -- systemctl list-units --type=service "
              f"--state=running --no-legend --no-pager", timeout=15)
    names = []
    for line in out.splitlines():
        p = line.split()
        if p and p[0].endswith(".service"):
            names.append(p[0][:-len(".service")])
    return names


def _listening(cid):
    """port -> process name for every externally reachable listener in one CT."""
    out = run(f"pct exec {cid} -- ss -lntpH", timeout=15)
    found = {}
    for line in out.splitlines():
        m = re.match(r"\s*\S+\s+\S+\s+\S+\s+(\S+):(\d+)\s", line)
        if not m:
            continue
        addr, port = m.group(1), int(m.group(2))
        if addr in ("127.0.0.1", "[::1]") or port in IGNORE_PORTS:
            continue
        pm = re.search(r'users:\(\("([^"]+)"', line)
        found.setdefault(port, (pm.group(1) if pm else ""))
    return found


def _tunnel(services, guests):
    """Where the Cloudflare connector runs and what zone it serves.

    Found by looking for the connector rather than by naming a container: its
    metrics port is read out of the running command line, and the zone is the
    common suffix of the hostnames it is already serving. A host with no tunnel
    gets an empty dict and the routing tab says so.
    """
    cf = next((s for s in services if s["name"] == "cloudflared"), None)
    if not cf:
        return {}
    cid = cf["cid"]
    cmd = run(f"pct exec {cid} -- bash -c "
              f"\"tr '\\0' ' ' < /proc/$(pgrep -f 'cloudflared.*tunnel' "
              f"| head -1)/cmdline 2>/dev/null\"", timeout=12)
    m = re.search(r"--metrics[= ]([0-9.]+:\d+|\S+:\d+)", cmd)
    metrics = m.group(1) if m else ""
    # A metrics listener bound to 0.0.0.0 or localhost is still reachable at the
    # container's own address, which is what the dashboard has to use.
    if metrics:
        h, _, port = metrics.rpartition(":")
        if h in ("", "0.0.0.0", "127.0.0.1", "localhost", "[::]"):
            metrics = f"{cf['ip']}:{port}"
    elif cf["ip"]:
        metrics = f"{cf['ip']}:20241"       # cloudflared's own default

    tid = ""
    m = re.search(r"run\s+(?:--token\s+\S+\s+)?([0-9a-f-]{36})", cmd)
    if m:
        tid = m.group(1)

    zone = ""
    hosts = []
    cfg = run(f"curl -sf --max-time 5 http://{metrics}/config", timeout=8) if metrics else ""
    try:
        ing = (json.loads(cfg).get("config") or {}).get("ingress") or []
        hosts = [r.get("hostname") for r in ing if r.get("hostname")]
    except Exception:
        pass
    if hosts:
        # The zone is the longest suffix every published hostname shares.
        parts = [h.split(".") for h in hosts]
        common = []
        for i in range(1, min(len(p) for p in parts) + 1):
            tail = parts[0][-i:]
            if all(p[-i:] == tail for p in parts):
                common = tail
            else:
                break
        if len(common) >= 2:
            zone = ".".join(common)

    return {"cid": cid, "ip": cf["ip"], "connector": f"http://{metrics}" if metrics else "",
            "zone": zone, "tunnel_id": tid, "hostnames": hosts}


def _public_hosts(tunnel, services):
    """service name -> public hostname, matched through the tunnel's own ingress.

    The mapping is derived from where each route actually points, so renaming a
    hostname in Cloudflare is reflected here on the next run and nothing has to
    be kept in step by hand.
    """
    out = {}
    if not tunnel.get("connector"):
        return out
    cfg = run(f"curl -sf --max-time 5 {tunnel['connector']}/config", timeout=8)
    try:
        ing = (json.loads(cfg).get("config") or {}).get("ingress") or []
    except Exception:
        return out
    by_origin = {}
    for r in ing:
        host, svc = r.get("hostname"), r.get("service") or ""
        if not host or not svc:
            continue
        m = re.search(r"//([0-9a-zA-Z.\-]+):(\d+)", svc)
        if m:
            by_origin.setdefault((m.group(1), int(m.group(2))), host)
    for s in services:
        hit = by_origin.get((s.get("ip"), s.get("port")))
        if hit:
            out[s["name"]] = hit
    return out


def _detect_services(guests):
    """Every service on the host, found by looking rather than by being told.

    Three sources are merged, in order of how much they know: Docker containers
    (which carry an image name and a compose directory), systemd units, and
    finally anything else holding a listening port. Each is matched against the
    APPS table for a canonical name; unmatched listeners still become services,
    just with a generic icon and no version check.
    """
    out = []
    for g in guests:
        if g["type"] != "lxc" or g["status"] != "running":
            continue
        cid, ip = g["id"], g["ip"]
        listeners = _listening(cid)
        docker = _docker_inventory(cid)
        units = _units(cid)
        claimed = set()                  # ports already explained

        # A compose stack is one service, not one per container. The container
        # publishing ports is the service; the rest - databases, caches, the ML
        # worker Immich talks to over the compose network - are its internals.
        stack_owner = {}
        for c in docker:
            if c["dir"] and c["ports"]:
                stack_owner.setdefault(c["dir"], c["name"])

        for c in docker:
            known = identify(image=c["image"])
            if is_sidecar(c["image"]) and not known:
                claimed.update(c["ports"])
                continue
            if not c["ports"] and stack_owner.get(c["dir"], c["name"]) != c["name"]:
                continue
            name = known or c["name"].replace("_", " ").title()
            port = c["ports"][0] if c["ports"] else None
            claimed.update(c["ports"])
            out.append({"name": name, "cid": cid, "ct": g["name"], "ip": ip,
                        "port": port, "manage": "docker", "dir": c["dir"],
                        "container": c["name"], "image": c["image"],
                        "known": name in APPS})

        for u in units:
            name = identify(unit=u)
            if not name or any(s["name"] == name for s in out):
                continue
            meta = APPS[name]
            # Pair the unit with whichever listening port its process holds.
            port = None
            for p, proc in sorted(listeners.items()):
                if identify(proc=proc) == name and p not in claimed:
                    port = p
                    break
            if port is None:
                for p, proc in sorted(listeners.items()):
                    if p not in claimed and proc and proc.lower() in u.lower():
                        port = p
                        break
            if port is not None:
                claimed.add(port)
            out.append({"name": name, "cid": cid, "ct": g["name"], "ip": ip,
                        "port": port, "manage": meta.get("manage", "apt"),
                        "unit": u, "pkg": meta.get("apt", u), "known": True})

        for port, proc in sorted(listeners.items()):
            if port in claimed:
                continue
            if proc == "docker-proxy":
                continue                 # a stack we already listed, or a sidecar
            name = identify(proc=proc)
            if name and any(s["name"] == name for s in out):
                continue
            label = name or (proc or f"port {port}")
            out.append({"name": label.title() if label.islower() else label,
                        "cid": cid, "ct": g["name"], "ip": ip, "port": port,
                        "manage": "unknown", "proc": proc,
                        "known": bool(name), "discovered": True})

    for s in out:
        meta = APPS.get(s["name"], {})
        s["icon"] = meta.get("icon", "generic")
        s["role"] = meta.get("role", "")
        ui = meta.get("ui", True) and s.get("ip") and s.get("port")
        s["url"] = f"http://{s['ip']}:{s['port']}" if ui else ""
    return out


def detect():
    """Build the whole site picture from the live host."""
    guests = _guests()
    services = _detect_services(guests)
    tunnel = _tunnel(services, guests)
    hosts = _public_hosts(tunnel, services)
    for s in services:
        s["host"] = hosts.get(s["name"], "")
    return {"bridges": _bridges(), "guests": guests, "storage": _storage(guests),
            "tunnel": tunnel, "services": services}


# ------------------------------------------------------------------- loading
def _read(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _write(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        shutil.move(tmp, path)
    except Exception:
        pass


def _merge(base, over):
    """Overrides win, but only for the keys they actually mention."""
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


_SITE = None


def load(refresh=False):
    """The site picture: detected facts under the admin's overrides.

    Only refresh=True walks the host, and only the collector passes it. Every
    other reader takes the cache as it stands, for two reasons: detection costs
    a few seconds of `pct exec`, and the web service runs under a sandbox that
    denies it pct anyway - letting it detect would cache an empty picture over
    a good one on the first request after a reboot. An empty cache degrades to
    an empty site until the collector's next run, which is a page with nothing
    on it rather than a page with wrong things on it.
    """
    global _SITE
    if _SITE is not None and not refresh:
        return _SITE
    if refresh:
        data = detect()
        _write(CACHE_FILE, data)
    else:
        data = _read(CACHE_FILE)
    _SITE = _merge(data, _read(CONF_FILE))
    return _SITE


# ------------------------------------------------------------------ accessors
def host_ip():
    """The address guests reach this host on - the internal bridge, not the
    uplink, which is DHCP and moves."""
    return (load().get("bridges", {}).get("internal", {}) or {}).get("ip", "127.0.0.1")


def uplink_ip():
    return (load().get("bridges", {}).get("uplink", {}) or {}).get("ip", "")


def ct_ip(cid):
    """Address of one guest, or '' if it has none we can see."""
    for g in load().get("guests", []):
        if g.get("id") == cid:
            return g.get("ip", "")
    return ""


def guests_list():
    return load().get("guests", [])


def services_list():
    return load().get("services", [])


def find(name):
    """The detected instance of one app, or None if it is not on this host."""
    for s in services_list():
        if s.get("name") == name:
            return s
    return None


def base_url(name):
    """http://ip:port for an app, or '' when it is not here."""
    s = find(name)
    return (s or {}).get("url", "")


def tunnel_info():
    return load().get("tunnel", {}) or {}


def storage_info():
    return load().get("storage", {}) or {}


def shared_root():
    return storage_info().get("shared", "")


def bulk_roots():
    return storage_info().get("bulk_roots", [])


def trusted_proxies():
    """Guests allowed to set forwarded-for headers - only the tunnel connector.

    Anything else on the internal bridge could otherwise rotate its apparent
    address per request and never trip the login rate limit.
    """
    t = tunnel_info()
    return {t["ip"]} if t.get("ip") else set()


def bind_addr(port=8085):
    """Where the web UI listens. The internal bridge, so it is never exposed on
    the uplink by accident."""
    return (host_ip(), port)


def upstream_map():
    """app name -> release-tracking repo, for the update checker."""
    out = {}
    for s in services_list():
        meta = APPS.get(s["name"])
        if meta and meta.get("repo"):
            out[s["name"]] = {"repo": meta["repo"]}
            if meta.get("track"):
                out[s["name"]]["track"] = meta["track"]
    return out


def icon_map():
    """app name -> icon slug, for every service actually present."""
    return {s["name"]: s.get("icon") or "generic" for s in services_list()}


def update_recipe(name):
    """How to update one app, derived from how it was found to be installed."""
    s = find(name)
    if not s:
        return None
    meta = APPS.get(name, {})
    note = meta.get("note")
    if s.get("manage") == "docker" and s.get("dir"):
        r = {"action": "update.docker", "params": {"cid": s["cid"], "dir": s["dir"]}}
    elif s.get("manage") == "arr":
        r = {"action": "update.arr",
             "params": {"cid": s["cid"], "app": name.lower()}}
    elif s.get("manage") == "apt" and s.get("pkg"):
        r = {"action": "update.apt", "params": {"cid": s["cid"], "pkg": s["pkg"]}}
    else:
        return None
    if note:
        r["note"] = note
    return r


def control_recipe(name):
    """How to start/stop one app, derived the same way."""
    s = find(name)
    if not s:
        return None
    meta = APPS.get(name, {})
    if s.get("manage") == "docker" and s.get("dir"):
        r = {"action": "service.docker", "params": {"cid": s["cid"], "dir": s["dir"]}}
    elif s.get("unit"):
        r = {"action": "service.systemd",
             "params": {"cid": s["cid"], "unit": s["unit"]}}
    else:
        return None
    if meta.get("warn"):
        r["warn"] = meta["warn"]
    return r


# ------------------------------------------------------------ version probing
VERSION_CACHE = "/var/lib/media-dashboard/versions.json"


def _vcache():
    return _read(VERSION_CACHE)


def _vcache_put(key, image_id, version):
    c = _vcache()
    c[key] = {"image": image_id, "version": version}
    _write(VERSION_CACHE, c)


def _curl_json(url, header=None, timeout=8):
    h = f"-H '{header}'" if header else ""
    out = run(f"curl -sf --max-time {timeout} {h} '{url}'", timeout=timeout + 4)
    try:
        return json.loads(out) if out else None
    except Exception:
        return None


def http_code(url, timeout=6):
    return run(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time {timeout} '{url}'",
               timeout=timeout + 4) or "000"


def _docker_label_version(cid, container):
    """OCI version label, but ignore it when it is clearly the base image's.

    Some images inherit org.opencontainers.image.version from their Ubuntu or
    Debian base, which would report "24.04" as the app version forever.
    """
    def insp(field):
        return run(f"pct exec {cid} -- docker inspect -f '{field}' {container}",
                   timeout=12)
    lbl = insp('{{index .Config.Labels "org.opencontainers.image.version"}}')
    ref = insp('{{index .Config.Labels "org.opencontainers.image.ref.name"}}')
    if lbl and lbl != "<no value>" and ref not in ("ubuntu", "debian", "alpine"):
        return lbl
    img = insp("{{.Config.Image}}")
    return img.split(":")[-1] if img else None


def _jar_version(cid, container, jar_path, key):
    """Implementation-Version out of a Spring Boot jar, cached per image id.

    Copying a jar out of a container and unzipping it is slow, so the answer is
    kept until the image underneath actually changes.
    """
    image_id = run(f"pct exec {cid} -- docker inspect -f '{{{{.Image}}}}' {container}",
                   timeout=12)
    if not image_id:
        return None
    hit = _vcache().get(key)
    if hit and hit.get("image") == image_id:
        return hit.get("version")
    ver = run(
        f"pct exec {cid} -- bash -c \""
        f"docker cp {container}:{jar_path} /tmp/_v.jar >/dev/null 2>&1 && "
        f"python3 -c \\\"import zipfile;print([l.split(': ',1)[1] for l in "
        f"zipfile.ZipFile('/tmp/_v.jar').read('META-INF/MANIFEST.MF')"
        f".decode(errors='ignore').splitlines() "
        f"if l.startswith('Implementation-Version')][0])\\\" 2>/dev/null; "
        f"rm -f /tmp/_v.jar\"", timeout=90).strip() or None
    if ver:
        _vcache_put(key, image_id, ver)
    return ver


def _threadfin_version(cid, container, key):
    """Threadfin's own -info report, cached per image id."""
    image_id = run(f"pct exec {cid} -- docker inspect -f '{{{{.Image}}}}' {container}",
                   timeout=12)
    if not image_id:
        return None
    hit = _vcache().get(key)
    if hit and hit.get("image") == image_id:
        return hit.get("version")
    out = run(f"pct exec {cid} -- docker exec {container} "
              f"/home/threadfin/bin/threadfin -info 2>/dev/null", timeout=60)
    m = re.search(r"Version:\s*Threadfin\s+(\S+)", out)
    ver = m.group(1) if m else None
    if ver:
        _vcache_put(key, image_id, ver)
    return ver


def arr_key(svc):
    """API key for an *arr app, read from the config.xml in its own container."""
    meta = APPS.get(svc.get("name"), {})
    cfg = (meta.get("version") or {}).get("config") \
        or f"/var/lib/{svc['name'].lower()}/config.xml"
    return run(f"pct exec {svc['cid']} -- grep -oP '(?<=<ApiKey>)[^<]+' {cfg} "
               f"2>/dev/null", timeout=10)


def probe_version(svc):
    """Installed version of one detected service, by whatever means it exposes.

    Every recipe is declared in APPS and every parameter comes from detection,
    so adding an app is a table entry rather than another branch in the
    collector. Anything unrecognised simply returns None, which the UI reports
    as unknown rather than guessing.
    """
    name = svc.get("name")
    meta = APPS.get(name, {})
    rec = meta.get("version")
    if not rec:
        # Not a known app, but if it is a container we can still read its tag.
        if svc.get("manage") == "docker" and svc.get("container"):
            return _docker_label_version(svc["cid"], svc["container"])
        return None
    url = svc.get("url") or (f"http://{svc['ip']}:{svc['port']}"
                             if svc.get("ip") and svc.get("port") else "")

    if rec.get("jar") and svc.get("container"):
        v = _jar_version(svc["cid"], svc["container"], rec["jar"],
                         rec.get("cache", name))
        if v:
            return v
    if rec.get("threadfin") and svc.get("container"):
        v = _threadfin_version(svc["cid"], svc["container"], rec.get("cache", name))
        if v:
            return v
    if rec.get("dpkg"):
        v = run(f"pct exec {svc['cid']} -- dpkg-query -W -f='${{Version}}' "
                f"{rec['dpkg']}", timeout=10)
        if v:
            return v
    if rec.get("exec"):
        out = run(f"pct exec {svc['cid']} -- {rec['exec']}", timeout=15)
        m = re.search(rec.get("re", r"(\d[\d.]*)"), out)
        if m:
            return m.group(1)
    if rec.get("arr") and url:
        key = arr_key(svc)
        if key:
            d = _curl_json(f"{url}/api/{rec['arr']}/system/status",
                           header=f"X-Api-Key: {key}")
            if d and d.get("version"):
                return d["version"]
    if rec.get("http") and url:
        d = _curl_json(url + rec["http"])
        if d:
            f = rec["field"]
            if isinstance(f, list):
                if all(k in d for k in f):
                    return rec.get("join", ".").join(str(d[k]) for k in f)
            elif d.get(f):
                v = str(d[f])
                return v.lstrip(rec["strip"]) if rec.get("strip") else v
    if rec.get("docker") and svc.get("container"):
        return _docker_label_version(svc["cid"], svc["container"])
    # Last resort for a known app deployed as a container by other means.
    if svc.get("manage") == "docker" and svc.get("container"):
        return _docker_label_version(svc["cid"], svc["container"])
    return None


def health_code(svc):
    """HTTP status the service answers with, or '000' when nothing answers."""
    url = svc.get("url")
    if not url:
        # A service with no browsable UI is judged by whether its unit is up.
        if svc.get("unit"):
            act = run(f"pct exec {svc['cid']} -- systemctl is-active {svc['unit']}",
                      timeout=10)
            return "200" if act == "active" else "000"
        return "000"
    meta = APPS.get(svc.get("name"), {})
    return http_code(url + meta.get("health", "/"))


def ct_warn(cid):
    """Why stopping a whole container might be worse than it looks."""
    t = tunnel_info()
    if t.get("cid") == cid:
        return (f"Container {cid} runs the tunnel connector. Stopping it cuts off "
                f"outside access to everything, including this dashboard if you "
                f"are not on the LAN.")
    return None


if __name__ == "__main__":
    import sys
    if "--detect" in sys.argv:
        d = detect()
        _write(CACHE_FILE, d)
        print(json.dumps(d, indent=2, sort_keys=True))
    else:
        print(json.dumps(load(), indent=2, sort_keys=True))
