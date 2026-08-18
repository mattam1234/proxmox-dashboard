#!/usr/bin/env python3
"""Collects status + version for the stack on this host and renders a static page.

Runs on the PVE host (needs pct/pveversion/nvidia-smi). Output: /var/www/dashboard/index.html

Nothing here knows which containers exist, what runs in them, or what the
internal subnet is. All of that comes from mdash_site, which works it out from
the live host on every run, so this collector is the same file on any Proxmox
box - see that module's docstring for the split between portable knowledge and
site facts.
"""
import json
import re
import shutil
import subprocess
import datetime
import html
import os
import sys
import time

sys.path.insert(0, "/usr/local/lib/mdash")
import mdash_site as site                                # noqa: E402
import mdash_fleet as fleet                              # noqa: E402

OUT_DIR = "/var/www/dashboard"
OUT_FILE = os.path.join(OUT_DIR, "index.html")

_GUESTS = None


def guests():
    """Every guest on this host, discovered at run time - LXC and VMs alike.

    Nothing about the stack is hardcoded here, so creating a container or a VM
    makes it appear on the next collection run without touching this file.
    """
    global _GUESTS
    if _GUESTS is not None:
        return _GUESTS
    rows = []
    out = run("pvesh get /cluster/resources --type vm --output-format json", timeout=25)
    try:
        for g in json.loads(out or "[]"):
            if g.get("template"):
                continue
            rows.append({"id": g.get("vmid"), "name": g.get("name") or str(g.get("vmid")),
                         "type": g.get("type") or "lxc", "status": g.get("status") or "unknown",
                         "maxmem": g.get("maxmem") or 0, "mem": g.get("mem") or 0,
                         "uptime": g.get("uptime") or 0, "maxcpu": g.get("maxcpu") or 0})
    except Exception:
        pass
    if not rows:                       # pvesh unavailable - fall back to the CLIs
        for kind, cmd in (("lxc", "pct list"), ("qemu", "qm list")):
            for line in run(cmd).splitlines()[1:]:
                p = line.split()
                if p and p[0].isdigit():
                    rows.append({"id": int(p[0]), "name": p[-1] if kind == "lxc" else p[1],
                                 "type": kind, "status": p[1] if kind == "lxc" else p[2],
                                 "maxmem": 0, "mem": 0, "uptime": 0, "maxcpu": 0})
    rows.sort(key=lambda r: r["id"])
    _GUESTS = rows
    return rows


def lxc_ids():
    return [g["id"] for g in guests() if g["type"] == "lxc"]


def guest_ip(g):
    """Primary IPv4 of a guest, from its config or its QEMU guest agent."""
    if g["type"] == "lxc":
        m = re.search(r"ip=([0-9.]+)", run(f"pct config {g['id']}", timeout=10))
        return m.group(1) if m else ""
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


def run(cmd, timeout=15):
    """Run a command, return stdout or '' on any failure."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def curl_json(url, headers=None, timeout=8):
    h = f"-H '{headers}'" if headers else ""
    out = run(f"curl -sf --max-time {timeout} {h} '{url}'", timeout=timeout + 4)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def http_code(url, timeout=6):
    return run(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time {timeout} '{url}'",
               timeout=timeout + 4) or "000"


# ---------------------------------------------------------------- host facts
def host_info():
    pve = run("pveversion").replace("pve-manager/", "").split("/")[0]
    kernel = run("uname -r")
    uptime = run("uptime -p").replace("up ", "")
    load = run("cut -d' ' -f1-3 /proc/loadavg")

    mem = run("free -m | awk '/^Mem:/{print $3\" \"$2}'").split()
    mem_str = f"{int(mem[0])/1024:.1f} / {int(mem[1])/1024:.1f} GiB" if len(mem) == 2 else "?"
    mem_pct = round(int(mem[0]) / int(mem[1]) * 100) if len(mem) == 2 else 0

    disk = run("df -h / | awk 'NR==2{print $3\" \"$2\" \"$5}'").split()
    disk_str = f"{disk[0]} / {disk[1]} ({disk[2]})" if len(disk) == 3 else "?"
    disk_pct = int(disk[2].rstrip("%")) if len(disk) == 3 else 0

    thin = run("lvs --noheadings -o data_percent pve/data 2>/dev/null")
    thin_pct = round(float(thin)) if thin else 0

    gpus = []
    nv = run("nvidia-smi --query-gpu=name,driver_version,temperature.gpu,utilization.gpu,memory.used,memory.total "
             "--format=csv,noheader,nounits")
    for line in nv.splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) >= 6:
            gpus.append({"name": p[0], "driver": p[1], "temp": p[2],
                         "util": p[3], "mem_used": p[4], "mem_total": p[5]})

    reboot_required = os.path.exists("/var/run/reboot-required")
    upd = run("apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst '")
    pending = int(upd) if upd.isdigit() else 0

    return {"pve": pve, "kernel": kernel, "uptime": uptime, "load": load,
            "mem": mem_str, "mem_pct": mem_pct, "disk": disk_str, "disk_pct": disk_pct,
            "thin_pct": thin_pct, "gpus": gpus,
            "reboot_required": reboot_required, "pending_updates": pending}


def human(n):
    n = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024 or u == "T":
            return f"{n:.1f}{u}"
        n /= 1024.0


def media_disks():
    """Bulk media volumes, with a SMART verdict per device.

    Which directory holds them is detected rather than assumed: a bulk root is
    a directory whose children are separate mounted filesystems shared into the
    guests. On this host that is /srv/disks; on another it is wherever the
    admin put it.
    """
    rows = []
    roots = site.bulk_roots()
    if not roots:
        return rows
    globs = " ".join(f"{r}/*" for r in roots)
    out = run(f"df -B1 --output=source,target,size,used,avail,pcent {globs} "
              f"2>/dev/null | tail -n +2")
    for line in out.splitlines():
        p = line.split()
        if len(p) < 6:
            continue
        dev = p[0]
        base = re.sub(r"\d+$", "", dev.replace("/dev/", ""))
        health = run(f"smartctl -H /dev/{base} 2>/dev/null | grep -iE 'overall-health|SMART Health' "
                     f"| awk -F: '{{print $2}}'", timeout=20).strip()
        realloc = run(f"smartctl -A /dev/{base} 2>/dev/null | awk '/Reallocated_Sector_Ct/{{print $10}}'", timeout=20).strip()
        pending = run(f"smartctl -A /dev/{base} 2>/dev/null | awk '/Current_Pending_Sector/{{print $10}}'", timeout=20).strip()
        warn = []
        if realloc.isdigit() and int(realloc) > 0:
            warn.append(f"{realloc} realloc")
        if pending.isdigit() and int(pending) > 0:
            warn.append(f"{pending} pending")
        rows.append({"dev": dev, "mount": os.path.basename(p[1].rstrip("/")),
                     "size": human(p[2]), "used": human(p[3]), "avail": human(p[4]),
                     "pct": int(p[5].rstrip("%")), "health": health or "?",
                     "warn": ", ".join(warn)})
    return rows


JELLYFIN_KEY_FILE = "/root/.jellyfin-key"


def jellyfin_base():
    """Where Jellyfin answers on this host, or '' if it does not run here."""
    return site.base_url("Jellyfin")


def recently_added(limit=18):
    """Newest items Jellyfin has indexed. Empty when there is no Jellyfin."""
    base = jellyfin_base()
    if not base:
        return []
    try:
        with open(JELLYFIN_KEY_FILE) as f:
            key = f.read().strip()
    except Exception:
        return []
    if not key:
        return []
    users = curl_json(f"{base}/Users", headers=f"X-Emby-Token: {key}")
    if not users:
        return []
    uid = users[0]["Id"]
    pub = curl_json(f"{base}/System/Info/Public") or {}
    server_id = pub.get("Id", "")
    items = curl_json(
        f"{base}/Users/{uid}/Items/Latest?Limit={limit}"
        f"&Fields=DateCreated,ProductionYear,RunTimeTicks",
        headers=f"X-Emby-Token: {key}", timeout=12)
    out = []
    for i in items or []:
        added = (i.get("DateCreated") or "")[:16].replace("T", " ")
        ticks = i.get("RunTimeTicks") or 0
        mins = int(ticks / 600000000) if ticks else 0
        out.append({"name": i.get("Name") or "?",
                    "type": i.get("Type") or "",
                    "year": i.get("ProductionYear") or "",
                    "runtime": f"{mins} min" if mins else "",
                    "added": added,
                    "id": i.get("Id") or "",
                    "server": server_id})
    return out


def _dur(seconds):
    """Seconds -> '3 days, 4 hours' style string, matching `uptime -p`."""
    seconds = int(seconds or 0)
    if seconds <= 0:
        return "-"
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    parts = [f"{d} day{'s' if d != 1 else ''}" if d else "",
             f"{h} hour{'s' if h != 1 else ''}" if h else "",
             f"{m} min" if m and not d else ""]
    return ", ".join(p for p in parts if p) or "just started"


def ct_info():
    """Status of every guest, whatever it is and however many there are."""
    rows = []
    for g in guests():
        running = g["status"] == "running"
        up = mem = "-"
        if running:
            # Prefer the guest's own view; fall back to what the hypervisor reports
            # so VMs (which we cannot pct exec into) still get real numbers.
            if g["type"] == "lxc":
                up = run(f"pct exec {g['id']} -- uptime -p", timeout=10).replace("up ", "")
                m = run(f"pct exec {g['id']} -- free -m | awk '/^Mem:/{{print $3\" \"$2}}'",
                        timeout=10).split()
                if len(m) == 2:
                    mem = f"{int(m[0])}/{int(m[1])} MiB"
            if up in ("", "-"):
                up = _dur(g["uptime"])
            if mem == "-" and g["maxmem"]:
                mem = f"{g['mem'] // 1048576}/{g['maxmem'] // 1048576} MiB"
        rows.append({"id": g["id"], "name": g["name"], "status": g["status"],
                     "uptime": up or "-", "mem": mem, "type": g["type"]})
    return rows


# ------------------------------------------------------------ service facts
#
# There is no list of services here. mdash_site walks the host - Docker
# inventories, systemd units, listening sockets - matches what it finds against
# its portable app table, and reports what is actually installed. This function
# only reshapes that into the rows the page and the graph expect.
def services():
    """Every service on this host, discovered and version-probed."""
    out = []
    for s in site.services_list():
        row = {"name": s["name"], "ct": f"{s['cid']} {s['ct']}",
               "url": s.get("url") or "-",
               "host": s.get("host") or ("internal only" if s.get("url")
                                         else s.get("role") or ""),
               "version": site.probe_version(s),
               "code": site.health_code(s),
               "icon": s.get("icon") or "generic",
               "cid": s["cid"], "port": s.get("port")}
        if not s.get("known"):
            # An unrecognised listener is reported as found, not as broken -
            # see topology(), which renders it "idle" rather than "down".
            row["discovered"] = True
        out.append(row)

    # The tunnel connector has no web UI, so its useful signal is how often it
    # has had to re-register rather than an HTTP code.
    t = site.tunnel_info()
    if t.get("cid"):
        cf = next((r for r in out if r["name"] == "cloudflared"), None)
        if cf:
            conns = run(f"pct exec {t['cid']} -- journalctl -u cloudflared "
                        f"--since '-24h' --no-pager 2>/dev/null "
                        f"| grep -c 'Registered tunnel connection'", timeout=15)
            cf["host"] = "tunnel"
            if conns:
                cf["note"] = f"{conns} conns/24h"
    out.sort(key=lambda r: (r["cid"], r["name"]))
    return out


def _arr_keys():
    """Each *arr app on this host, with its API key and base URL.

    Found wherever it happens to run, so moving one to a different container
    does not silently break the dependency graph.
    """
    found = {}
    for s in site.services_list():
        if s.get("manage") != "arr":
            continue
        key = site.arr_key(s)
        if key and s.get("url"):
            found[s["name"].lower()] = {"key": key, "cid": s["cid"],
                                        "base": s["url"]}
    return found


# ------------------------------------------------------------ update checks
# "Up to date" here means the version the service itself reports matches the
# newest release its project has published - both halves are probed, neither is
# inferred from an image tag. A service whose version could not be read is
# reported as unknown rather than quietly assumed current.
UPDATE_FILE = "/var/lib/media-dashboard/updates.json"
UPDATE_TTL = 6 * 3600       # how long a fetched release stays fresh
UPDATE_FAIL_TTL = 30 * 60   # back off this long after a lookup fails
UPDATE_BUDGET = 4           # API calls per run - see check_updates()

# Which repo publishes a project's releases is portable knowledge, so it lives
# in the APPS table in mdash_site alongside the icon and the version probe.
# UPSTREAM is that table narrowed to the apps this host actually runs; track=
# pins a project to one release line where it ships more than one (InfluxDB 3
# is a different product from the InfluxDB 2 that is installed, not an upgrade
# of it, so offering it would be wrong).
UPSTREAM = site.upstream_map()


_VER_RE = re.compile(r"(\d+(?:\.\d+)*)")
_PRE_RE = re.compile(r"alpha|beta|\brc\b|-rc|nightly|preview|snapshot|develop", re.I)


def _vnorm(s):
    """The numeric core of a version string.

    Copes with "v10.11.11", "release-5.2.3", Debian's "5.1.0-2" and Threadfin's
    bare "1.2" alike: everything around the first dotted numeric run is
    packaging noise rather than the upstream version.
    """
    if not s:
        return None
    m = _VER_RE.search(str(s))
    return m.group(1) if m else None


def _vcmp(a, b):
    """Compare two normalised versions at the precision both actually report.

    A source that only gives major.minor must not be compared against a full
    major.minor.patch tag - it would read as permanently out of date. Trimming
    to the shorter side can miss a patch bump, but it never invents one.
    """
    pa = [int(x) for x in a.split(".")]
    pb = [int(x) for x in b.split(".")]
    n = min(len(pa), len(pb))
    pa, pb = pa[:n], pb[:n]
    return (pa > pb) - (pa < pb)


def _gh_latest(repo, track=None):
    """Newest stable release of a GitHub repo, optionally pinned to a line.

    Without a track this is the project's own "latest release" pointer, which
    is what the project considers current. With one, releases are not usable -
    an old line stops being "latest" - so the tag list is filtered instead.
    """
    if track:
        d = curl_json(f"https://api.github.com/repos/{repo}/tags?per_page=100", timeout=15)
        if not isinstance(d, list):
            return None
        best = None
        for t in d:
            name = t.get("name") or ""
            v = _vnorm(name)
            if not v or not v.startswith(track) or _PRE_RE.search(name):
                continue
            if best is None or _vcmp(v, best) > 0:
                best = v
        return best
    d = curl_json(f"https://api.github.com/repos/{repo}/releases/latest", timeout=15)
    if not isinstance(d, dict) or d.get("prerelease"):
        return None
    return _vnorm(d.get("tag_name"))


def check_updates(svcs):
    """Latest upstream release per service, refreshed a few entries at a time.

    The collector runs every two minutes but the unauthenticated GitHub API
    allows 60 calls an hour, so each run refreshes only the UPDATE_BUDGET
    stalest entries and everything else is served from the cache on disk. In
    the steady state that is ~13 calls per six hours; a cold start fills in
    over a handful of runs rather than tripping the limit on the first one.
    """
    cache = {}
    try:
        with open(UPDATE_FILE) as f:
            cache = json.load(f)
    except Exception:
        pass
    if not isinstance(cache, dict):
        cache = {}

    now = time.time()
    stale = []
    for s in svcs:
        src = UPSTREAM.get(s["name"])
        if not src:
            continue
        hit = cache.get(s["name"]) or {}
        # A failed lookup is retried sooner than a good one is refreshed, but
        # not so soon that a repo that has gone away burns the whole budget.
        ttl = UPDATE_TTL if hit.get("latest") else UPDATE_FAIL_TTL
        if now - hit.get("checked", 0) >= ttl:
            stale.append((hit.get("checked", 0), s["name"], src))
    stale.sort()

    for _, name, src in stale[:UPDATE_BUDGET]:
        latest = _gh_latest(src["repo"], src.get("track"))
        entry = dict(cache.get(name) or {})
        entry["checked"] = now
        entry["repo"] = src["repo"]
        if latest:
            # Only overwrite on success: a transient failure should leave the
            # last known release in place rather than blank the column.
            entry["latest"] = latest
            entry.pop("error", None)
        else:
            entry["error"] = "lookup failed"
        cache[name] = entry

    try:
        os.makedirs(os.path.dirname(UPDATE_FILE), exist_ok=True)
        tmp = UPDATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cache, f)
        shutil.move(tmp, UPDATE_FILE)
        os.chmod(UPDATE_FILE, 0o644)
    except Exception:
        pass
    return cache


def update_state(installed, latest):
    """One of current / update / ahead / unknown.

    "ahead" is a real outcome, not an error: a service tracking a develop or
    nightly build legitimately sits in front of the newest stable release.
    """
    a, b = _vnorm(installed), _vnorm(latest)
    if not a or not b:
        return "unknown"
    c = _vcmp(a, b)
    return "current" if c == 0 else ("update" if c < 0 else "ahead")


# ----------------------------------------------------------------- topology
# A machine-readable map of the stack: containers, the services inside them,
# the volumes those services use and the physical disks underneath - plus the
# links between them. Everything here is *probed*, never assumed, so a link
# that is missing from the graph is genuinely missing from the config.
TOPO_FILE = "/var/lib/media-dashboard/topology.json"

def _base_disk(dev):
    """Walk a device node down to the physical disk backing it."""
    out = run(f"lsblk -snlo NAME,TYPE {dev} 2>/dev/null", timeout=10)
    for line in out.splitlines():
        p = line.split()
        if len(p) == 2 and p[1] == "disk":
            return p[0]
    return None


def _ct_mounts():
    """host path -> list of (ct id, in-CT path, read-only) from the pct configs."""
    out = {}
    for cid in lxc_ids():
        cfg = run(f"pct config {cid}", timeout=10)
        for line in cfg.splitlines():
            if not re.match(r"^mp\d+:", line):
                continue
            spec = line.split(":", 1)[1].strip()
            parts = spec.split(",")
            host_path = parts[0]
            ro = any(p.strip() == "ro=1" for p in parts)
            ct_path = host_path
            for p in parts:
                if p.startswith("mp="):
                    ct_path = p[3:]
            out.setdefault(host_path, []).append((cid, ct_path, ro))
    return out


def _fstab():
    """Mountpoint -> declared (fstype, options) for everything in /etc/fstab."""
    tab = {}
    try:
        with open("/etc/fstab") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                p = line.split()
                if len(p) >= 4:
                    tab[p[1]] = {"fstype": p[2], "opts": p[3]}
    except Exception:
        pass
    return tab


def _volume_facts(host_path, tab=None):
    """Resolve a host path to its mountpoint, device, filesystem and options."""
    src = run(f"findmnt -rno SOURCE,FSTYPE,OPTIONS --target {host_path} 2>/dev/null",
              timeout=10)
    mp = run(f"findmnt -rno TARGET --target {host_path} 2>/dev/null", timeout=10)
    dev = fstype = opts = ""
    if src:
        bits = src.split(None, 2)
        dev = bits[0] if bits else ""
        fstype = bits[1] if len(bits) > 1 else ""
        opts = bits[2] if len(bits) > 2 else ""
    declared = (tab or {}).get(host_path)
    return {"mountpoint": mp, "dev": dev, "fstype": fstype, "opts": opts,
            "mounted": mp == host_path, "declared": declared,
            "ro": opts.split(",")[0] == "ro" if opts else False}


def _service_volumes(keys):
    """Which host paths each service actually reads or writes, from live config."""
    use = {}

    def add(svc, path, role):
        if path:
            use.setdefault(svc, []).append((path, role))

    # Jellyfin: every library location it has been given.
    try:
        with open(JELLYFIN_KEY_FILE) as f:
            jk = f.read().strip()
    except Exception:
        jk = ""
    if jk:
        for lib in curl_json(f"{jellyfin_base()}/Library/VirtualFolders",
                             headers=f"X-Emby-Token: {jk}") or []:
            for loc in lib.get("Locations") or []:
                add("Jellyfin", loc, f"library: {lib.get('Name')}")

    # Radarr / Sonarr: their root folders.
    for app in ("radarr", "sonarr"):
        a = keys.get(app)
        if not a:
            continue
        for rf in curl_json(f"{a['base']}/api/v3/rootfolder",
                            headers=f"X-Api-Key: {a['key']}") or []:
            add(app.capitalize(), rf.get("path"), "root folder")

    # qBittorrent: the global save path plus every category override.
    qp = _qbit("app/preferences")
    if qp:
        add("qBittorrent", qp.get("save_path"), "save path")
        if qp.get("temp_path_enabled"):
            add("qBittorrent", qp.get("temp_path"), "incomplete")
    for cat in (_qbit("torrents/categories") or {}).values():
        add("qBittorrent", cat.get("savePath"), f"category: {cat.get('name')}")

    # Immich's external library, read from the volumes its stack declares
    # rather than assumed to be a particular disk.
    im = site.find("Immich")
    if im and im.get("container"):
        binds = run(f"pct exec {im['cid']} -- docker inspect -f "
                    f"'{{{{range .HostConfig.Binds}}}}{{{{println .}}}}{{{{end}}}}' "
                    f"{im['container']}", timeout=12)
        for b in binds.splitlines():
            host_path = b.split(":")[0]
            if host_path.startswith("/") and any(
                    host_path.startswith(r) for r in site.bulk_roots()):
                add("Immich", host_path, "external library")
    return use


def _qbit(endpoint):
    """qBittorrent API call. The host subnet is whitelisted, so no login needed."""
    base = site.base_url("qBittorrent")
    return curl_json(f"{base}/api/v2/{endpoint}", timeout=6) if base else None


def _service_links(keys):
    """Service-to-service links, read from each app's own configuration."""
    links = []

    def link(a, b, label):
        links.append({"from": f"svc:{a}", "to": f"svc:{b}",
                      "kind": "net", "label": label})

    # Prowlarr pushes indexers into the apps it has registered.
    p = keys.get("prowlarr")
    if p:
        base, hdr = f"{p['base']}/api/v1", f"X-Api-Key: {p['key']}"
        idx = curl_json(f"{base}/indexer", headers=hdr) or []
        for app in curl_json(f"{base}/applications", headers=hdr) or []:
            impl = app.get("implementation")
            if impl in ("Radarr", "Sonarr"):
                link("Prowlarr", impl,
                     f"{len(idx)} indexer(s), {app.get('syncLevel')}")
        for dc in curl_json(f"{base}/downloadclient", headers=hdr) or []:
            if dc.get("enable"):
                link("Prowlarr", "qBittorrent", "manual grabs")

    # Radarr / Sonarr -> download client, and -> Jellyfin for library refresh.
    for app in ("radarr", "sonarr"):
        a = keys.get(app)
        if not a:
            continue
        svc = app.capitalize()
        base, hdr = f"{a['base']}/api/v3", f"X-Api-Key: {a['key']}"
        for dc in curl_json(f"{base}/downloadclient", headers=hdr) or []:
            if dc.get("enable") and dc.get("implementation") == "QBittorrent":
                cat = next((f.get("value") for f in dc.get("fields", [])
                            if f["name"] in ("movieCategory", "tvCategory")), "")
                link(svc, "qBittorrent", f"sends torrents ({cat})" if cat else "sends torrents")
        for n in curl_json(f"{base}/notification", headers=hdr) or []:
            if n.get("implementation") == "MediaBrowser":
                link(svc, "Jellyfin", "library refresh on import")

    # Jellyseerr fans requests out to the arrs and reads Jellyfin's libraries.
    js = {}
    for cid in lxc_ids():
        st = run(f"pct exec {cid} -- cat /var/lib/jellyseerr/settings.json 2>/dev/null",
                 timeout=10)
        if st:
            try:
                js = json.loads(st)
                break
            except Exception:
                pass
    if js.get("jellyfin", {}).get("apiKey"):
        link("Jellyseerr", "Jellyfin", "library + user auth")
    for r in js.get("radarr") or []:
        link("Jellyseerr", "Radarr", f"movie requests -> {r.get('activeDirectory') or '?'}")
    for r in js.get("sonarr") or []:
        link("Jellyseerr", "Sonarr", f"TV requests -> {r.get('activeDirectory') or '?'}")

    # Grafana reads from InfluxDB; the host pushes its metrics in.
    gf = site.find("Grafana")
    if gf and run(f"pct exec {gf['cid']} -- grep -rl influxdb "
                  f"/etc/grafana/provisioning/datasources 2>/dev/null", timeout=10):
        link("Grafana", "InfluxDB", "datasource")
    if run("pvesh get /cluster/metrics/server --output-format json 2>/dev/null", timeout=15):
        links.append({"from": "host", "to": "svc:InfluxDB", "kind": "net",
                      "label": "PVE metrics push"})
    return links


def topology(h, cts, svcs, disks):
    keys = _arr_keys()
    nodes, edges, issues, updates = [], [], [], []
    upstream = check_updates(svcs)

    def node(**kw):
        nodes.append(kw)

    # --- the internet edge ------------------------------------------------
    node(id="internet", kind="internet", label="Internet", sub="via Cloudflare",
         zone="edge", status="ok", icon="cloudflare",
         meta=[["Zone", site.tunnel_info().get("zone") or "-"],
               ["Transport", "Cloudflare Tunnel (outbound only)"]])

    # --- the host ---------------------------------------------------------
    gpu = h["gpus"][0] if h.get("gpus") else None
    # The host's "update" is apt's pending package count, not a version compare,
    # so it gets the same badge but keeps its own wording.
    pending = h.get("pending_updates", 0)
    hostname = run("hostname") or "pve"
    node(id="host", kind="host", label=hostname, sub=f"Proxmox {h['pve']}",
         zone="edge", status="warn" if h.get("reboot_required") else "ok", icon="proxmox",
         update="update" if pending else "current",
         meta=[["Kernel", h["kernel"]], ["Uptime", h["uptime"]], ["Load", h["load"]],
               ["Memory", h["mem"]], ["Root disk", h["disk"]],
               ["Pending updates", str(pending)],
               ["Reboot required", "yes" if h.get("reboot_required") else "no"]])
    if pending:
        updates.append({"id": "host", "name": f"{hostname} (apt)",
                        "detail": f"{pending} package{'s' if pending != 1 else ''} pending",
                        "url": None})
    if gpu:
        node(id="gpu", kind="gpu", label=gpu["name"], sub=f"driver {gpu['driver']}",
             zone="edge", status="ok", icon="nvidia",
             meta=[["Temp", f"{gpu['temp']} C"], ["Utilisation", f"{gpu['util']} %"],
                   ["VRAM", f"{gpu['mem_used']} / {gpu['mem_total']} MiB"]])

    # --- guests -----------------------------------------------------------
    gmap = {g["id"]: g for g in guests()}
    for c in cts:
        running = c["status"] == "running"
        g = gmap.get(c["id"], {})
        ip = guest_ip(g) if g else ""
        kind_label = "VM" if c.get("type") == "qemu" else "LXC"
        node(id=f"ct:{c['id']}", kind="ct", label=f"{c['id']} {c['name']}",
             sub=ip or kind_label, zone="compute",
             status="ok" if running else "bad",
             icon="vm" if c.get("type") == "qemu" else "lxc",
             meta=[["Type", kind_label], ["Status", c["status"]],
                   ["Uptime", c["uptime"]], ["Memory", c["mem"]],
                   ["vCPU", str(g.get("maxcpu") or "-")],
                   ["IP", ip or "unknown"]])
        edges.append({"from": "host", "to": f"ct:{c['id']}", "kind": "host",
                      "label": f"hosts ({kind_label})"})
        if not running:
            issues.append(f"{kind_label} {c['id']} ({c['name']}) is {c['status']}")

    # --- services, each pinned inside its guest ----------------------------
    known_ids = {c["id"] for c in cts}
    for s in svcs:
        cid = int(s["ct"].split()[0])
        if cid not in known_ids:
            continue
        up = s["code"] in ("200", "301", "302", "307", "308", "401", "403")
        # A discovered port that does not speak HTTP is not broken - it is just
        # not a web service (a BitTorrent listener, say). Never call it down.
        status = "ok" if up else ("idle" if s.get("discovered") else "bad")
        sub = s.get("version") or ("non-HTTP port" if not up and s.get("discovered")
                                   else "discovered" if s.get("discovered") else "?")

        # A service nobody publishes releases for (a discovered port, say) has
        # no upstream to compare against - that is "not tracked", not "current".
        up_src = upstream.get(s["name"]) or {}
        latest = up_src.get("latest")
        ustate = update_state(s.get("version"), latest) if latest else "unknown"
        umeta = [["Latest", latest or ("not tracked" if s["name"] not in UPSTREAM
                                       else "lookup pending")]]
        if ustate == "update":
            # Report the version the service actually reports, Debian revision
            # and all - the normalised form is only used for the comparison.
            umeta.append(["Update", f"{s.get('version')} → {latest}"])
        elif ustate == "ahead":
            umeta.append(["Update", "running ahead of the latest stable release"])

        node(id=f"svc:{s['name']}", kind="service", label=s["name"], sub=sub,
             zone="compute", group=f"ct:{cid}",
             status=status, icon=s.get("icon") or "generic",
             link=s["url"] if s["url"].startswith("http") else None,
             discovered=bool(s.get("discovered")),
             update=ustate, latest=latest,
             meta=[["Version", s.get("version") or "unknown"]] + umeta +
                  [["HTTP", s["code"]], ["Local", s["url"]],
                   ["Public", s.get("host") or "-"]]
                  + ([["Note", s["note"]]] if s.get("note") else []))
        if status == "bad":
            issues.append(f"{s['name']} is not responding (HTTP {s['code']})")
        if ustate == "update":
            updates.append({"id": f"svc:{s['name']}", "name": s["name"],
                            "detail": f"{s.get('version')} → {latest}",
                            "url": f"https://github.com/{up_src['repo']}/releases"
                                   if up_src.get("repo") else None})
        # Anything with a real public hostname is reachable through the tunnel.
        host = s.get("host") or ""
        if "." in host and host != "internal only":
            edges.append({"from": "svc:cloudflared", "to": f"svc:{s['name']}",
                          "kind": "tunnel", "label": host})

    edges.append({"from": "internet", "to": "svc:cloudflared", "kind": "tunnel",
                  "label": "outbound tunnel"})
    if gpu:
        edges.append({"from": "gpu", "to": "svc:Jellyfin", "kind": "gpu",
                      "label": "NVENC transcode"})

    # --- volumes and the disks under them ---------------------------------
    ctm = _ct_mounts()
    svc_vol = _service_volumes(keys)
    tab = _fstab()
    seen_disk = set()

    # Every host path a CT is given, plus any path a service actually uses,
    # plus everything /etc/fstab says should be there - so a volume that failed
    # to mount is still drawn, rather than quietly vanishing from the graph.
    roots = tuple(r for r in ([site.shared_root()] + site.bulk_roots()) if r)
    vol_paths = set(ctm) | {m for m in tab if roots and m.startswith(roots)}
    for uses in svc_vol.values():
        for path, _ in uses:
            # Collapse a library path down to the volume that holds it.
            for root in list(ctm) + [r for r in [site.shared_root()] if r]:
                if path == root or path.startswith(root.rstrip("/") + "/"):
                    vol_paths.add(root)
                    break

    for path in sorted(vol_paths):
        f = _volume_facts(path, tab)
        consumers = ctm.get(path, [])
        ro_all = consumers and all(ro for _, _, ro in consumers)
        status = "ok"
        sub = f["fstype"] or "?"
        # Mounted, but not the way /etc/fstab asks for it - the classic symptom
        # of a volume that came up degraded and will be wrong again next boot.
        if f["mounted"] and f["declared"]:
            want_ro = "ro" in f["declared"]["opts"].split(",")
            if f["ro"] and not want_ro:
                status = "warn"
                sub = f"{f['fstype']}, READ-ONLY (fstab asks for rw)"
                issues.append(f"{path} is mounted read-only but /etc/fstab declares "
                              f"rw - it will fail again on reboot")
            elif f["declared"]["fstype"] not in ("auto", f["fstype"]) and \
                    not (f["declared"]["fstype"] == "ntfs-3g" and f["fstype"] == "fuseblk"):
                status = "warn"
                sub = f"{f['fstype']} (fstab says {f['declared']['fstype']})"
        if not f["mounted"]:
            # A path that resolves to / has no disk of its own: it is a plain
            # directory on the boot volume. That may be intentional, but it is
            # worth flagging because the boot SSD is small.
            if f["mountpoint"] == "/":
                status = "warn"
                sub = f"on the boot volume ({f['fstype']})"
                issues.append(f"{path} has no disk of its own - it lives on the "
                              f"root filesystem ({h['disk']})")
            else:
                status = "bad"
                sub = f"NOT MOUNTED (falls back to {f['mountpoint']})"
                issues.append(f"{path} is not mounted - writes land on {f['mountpoint']}")
        elif ro_all:
            status = "warn"
        node(id=f"vol:{path}", kind="mount",
             label=os.path.basename(path.rstrip("/")) or path,
             sub=sub, zone="storage", status=status, icon="folder",
             meta=[["Host path", path], ["Mountpoint", f["mountpoint"]],
                   ["Device", f["dev"] or "-"], ["Filesystem", f["fstype"] or "-"],
                   ["Mounted", "yes" if f["mounted"] else "no"],
                   ["Shared with", ", ".join(f"{c}{' (ro)' if ro else ''}"
                                             for c, _, ro in consumers) or "-"]])

        for cid, ct_path, ro in consumers:
            edges.append({"from": f"ct:{cid}", "to": f"vol:{path}", "kind": "storage",
                          "label": f"{ct_path}{' (ro)' if ro else ''}"})

        base = _base_disk(f["dev"]) if f["dev"] else None
        if base:
            did = f"disk:{base}"
            if did not in seen_disk:
                seen_disk.add(did)
            edges.append({"from": f"vol:{path}", "to": did, "kind": "storage",
                          "label": f["dev"]})

    # Services pointed at a volume.
    for svc, uses in svc_vol.items():
        for path, role in uses:
            for root in sorted(vol_paths, key=len, reverse=True):
                if path == root or path.startswith(root.rstrip("/") + "/"):
                    edges.append({"from": f"svc:{svc}", "to": f"vol:{root}",
                                  "kind": "storage", "label": f"{role}: {path}"})
                    break

    # --- every physical disk, mounted or not ------------------------------
    disk_pct = {d["dev"]: d for d in disks}
    inv = run("lsblk -dnpo NAME,SIZE,MODEL,ROTA 2>/dev/null", timeout=15)
    for line in inv.splitlines():
        p = line.split(None, 1)
        if len(p) != 2:
            continue
        devpath = p[0]
        rest = p[1].rsplit(None, 1)
        size = rest[0].split()[0] if rest else "?"
        model = " ".join(rest[0].split()[1:]) if rest else ""
        rota = rest[1] if len(rest) > 1 else "1"
        base = os.path.basename(devpath)
        did = f"disk:{base}"

        health = run(f"smartctl -H {devpath} 2>/dev/null | grep -iE 'overall-health|SMART Health' "
                     f"| awk -F: '{{print $2}}'", timeout=25).strip()
        realloc = run(f"smartctl -A {devpath} 2>/dev/null | "
                      f"awk '/Reallocated_Sector_Ct/{{print $10}}'", timeout=25).strip()
        pend = run(f"smartctl -A {devpath} 2>/dev/null | "
                   f"awk '/Current_Pending_Sector/{{print $10}}'", timeout=25).strip()
        hours = run(f"smartctl -A {devpath} 2>/dev/null | "
                    f"awk '/Power_On_Hours/{{print $10}}'", timeout=25).strip()

        status, notes = "ok", []
        if realloc.isdigit() and int(realloc) > 0:
            notes.append(f"{realloc} reallocated sectors")
            status = "bad" if int(realloc) > 100 else "warn"
        if pend.isdigit() and int(pend) > 0:
            notes.append(f"{pend} pending sectors")
            status = "bad"
        if health and "PASSED" not in health.upper() and "OK" not in health.upper():
            status = "bad"
            notes.append(f"SMART: {health}")
        in_use = did in seen_disk
        if not in_use and status == "ok":
            status = "idle"

        # Fullness of whichever volume sits on this disk.
        fill = ""
        for d in disks:
            if _base_disk(d["dev"]) == base:
                fill = f"{d['pct']}% full, {d['avail']} free"
                if d["pct"] >= 95:
                    status = "warn" if status == "ok" else status
                    issues.append(f"{d['mount']} is {d['pct']}% full ({d['avail']} free)")
                break

        node(id=did, kind="disk", label=base, sub=f"{size} {'HDD' if rota == '1' else 'SSD'}",
             zone="device", status=status, icon="disk",
             meta=[["Model", model or "-"], ["Size", size],
                   ["SMART", health or "unknown"],
                   ["Power-on hours", hours or "-"],
                   ["Usage", fill or ("in use" if in_use else "not mounted")],
                   ["Notes", "; ".join(notes) or "-"]])
        if status == "bad" and notes:
            issues.append(f"{base}: {'; '.join(notes)}")

    edges.extend(_service_links(keys))

    # Drop edges whose endpoints did not materialise.
    ids = {n["id"] for n in nodes}
    edges = [e for e in edges if e["from"] in ids and e["to"] in ids]

    return {"generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "nodes": nodes, "edges": edges, "issues": issues, "updates": updates}


# ------------------------------------------------------------------- render
CSS = """
/* ===== SHARED CORE =========================================================
   This block is duplicated byte-for-byte in media-dashboard.py (which writes
   the static status page) and media-dashboard-web.py (which serves every
   other page and grafts the nav onto the status page). Both have to agree or
   the pages drift apart, so edit it in one file and copy it to the other:
     diff <(sed -n '/SHARED CORE ===/,/END SHARED CORE/p' media-dashboard.py) \
          <(sed -n '/SHARED CORE ===/,/END SHARED CORE/p' media-dashboard-web.py)
   ========================================================================= */
:root{--bg:#f6f7f9;--card:#fff;--fg:#14161a;--muted:#6b7280;--line:#e5e7eb;
--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--accent:#4f46e5;
--pad:24px;--gap:16px;--r:12px;--maxw:1900px;
--shadow:0 1px 2px rgba(16,24,40,.04),0 1px 3px rgba(16,24,40,.06)}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;
--ok:#3fb950;--warn:#d29922;--bad:#f85149;--accent:#818cf8;
--shadow:0 1px 2px rgba(0,0,0,.28),0 1px 3px rgba(0,0,0,.22)}}
/* One knob drives the page rhythm: gutters and gaps shrink with the viewport. */
@media (max-width:900px){:root{--pad:14px;--gap:12px}}
@media (max-width:520px){:root{--pad:11px;--r:10px}}
*{box-sizing:border-box}
/* The width cap lives on body, not .wrap: only four of the eleven pages wrap
   their content in one, and on an ultrawide monitor the rest would otherwise
   stretch a six-column table across the whole screen. */
body{margin:0 auto;padding:var(--pad);max-width:calc(var(--maxw) + var(--pad)*2);
background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
-webkit-text-size-adjust:100%}
.wrap{max-width:none;margin:0}
h1{font-size:clamp(19px,3.4vw,23px);margin:0 0 4px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
.banner{border-radius:var(--r);padding:10px 14px;margin-bottom:16px;font-size:13px;
background:color-mix(in srgb,var(--warn) 14%,transparent);
border:1px solid color-mix(in srgb,var(--warn) 40%,transparent)}

/* Nav: a floating bar that follows you down the page on desktop, and one
   swipeable row on phones (nine links wrapped to three rows before). */
.nav{position:sticky;top:8px;z-index:40;display:flex;gap:6px;align-items:center;
margin:0 0 18px;padding:8px;border:1px solid var(--line);border-radius:var(--r);
background:color-mix(in srgb,var(--card) 88%,transparent);box-shadow:var(--shadow);
-webkit-backdrop-filter:blur(12px) saturate(1.4);
backdrop-filter:blur(12px) saturate(1.4);flex-wrap:wrap}
.nav a{display:inline-flex;align-items:center;min-height:34px;padding:0 13px;
border-radius:8px;border:1px solid var(--line);background:var(--card);
font-size:13px;font-weight:500;color:var(--accent);text-decoration:none;
white-space:nowrap}
.nav a:hover{text-decoration:none;border-color:var(--accent)}
.nav a.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.nav .sp{flex:1}
.nav .who{font-size:12px;color:var(--muted);padding:0 8px;white-space:nowrap}
@media (max-width:820px){
.nav{flex-wrap:nowrap;overflow-x:auto;overscroll-behavior-x:contain;top:0;
border-radius:0;border-width:0 0 1px;box-shadow:none;
margin:calc(var(--pad)*-1) calc(var(--pad)*-1) 14px;padding:8px var(--pad);
scrollbar-width:none;-ms-overflow-style:none}
.nav::-webkit-scrollbar{display:none}
.nav a{flex:0 0 auto}
.nav .sp,.nav .who{display:none}}

/* Stat cards */
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr));
gap:var(--gap);margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
padding:14px;box-shadow:var(--shadow)}
.card h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 10px}
.kv{display:flex;justify-content:space-between;gap:12px;padding:3px 0;font-size:13px}
.kv span:first-child{color:var(--muted)}
.kv span:last-child{text-align:right;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.bar{height:5px;background:var(--line);border-radius:3px;overflow:hidden;margin-top:6px}
.bar i{display:block;height:100%;background:var(--accent)}
.bar i.warn{background:var(--warn)} .bar i.bad{background:var(--bad)}

/* Tables */
.tablewrap{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
overflow-x:auto;box-shadow:var(--shadow)}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);font-weight:600;padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:10px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600}
.pill.ok{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
.pill.warn{background:color-mix(in srgb,var(--warn) 16%,transparent);color:var(--warn)}
.pill.bad{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}
.ver{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}

/* Below 760px a six-column table can only be read by dragging it sideways, so
   table.resp turns every row into a stacked card and each cell re-prints the
   header it lost as a data-label. Rows are tagged tr.hd so the header hides. */
@media (max-width:760px){
table.resp,table.resp tbody,table.resp tr,table.resp td{display:block;width:auto}
table.resp tr.hd{display:none}
table.resp tr{padding:11px 14px;border-bottom:1px solid var(--line)}
table.resp tr:last-child{border-bottom:0}
table.resp td{padding:2px 0;border:0;white-space:normal;overflow-wrap:anywhere;
display:flex;gap:14px;align-items:baseline;justify-content:space-between}
table.resp td[data-label]::before{content:attr(data-label);color:var(--muted);
font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;
flex:0 0 auto}
table.resp td:empty{display:none}
table.resp td:first-child,table.resp td[colspan]{display:block;font-size:15px}
table.resp td:first-child{margin-bottom:5px}
table.resp td .bar{flex:1;min-width:70px;margin-top:0}
/* Header-less tables (credentials) have nothing to label - just let them wrap. */
table.wrapcells td{white-space:normal;overflow-wrap:anywhere}}

/* Touch input: 16px keeps iOS Safari from zooming the page on focus, and
   finger-sized hit areas replace the 24px-tall mouse buttons.
   The :not() pairs are load-bearing, not decoration. A bare `input` selector
   scores (0,0,1) and loses to every class rule in this file and the page CSS
   that follows it (.fi is 14px, .tools input is 13px), so the anti-zoom rule
   silently did nothing on most pages. Two :not() clauses lift each selector to
   (0,2,1), which outranks any single-class rule. Keep them. */
@media (pointer:coarse){
input:not([type=checkbox]):not([type=radio]),
select:not([multiple]):not([size]),
textarea:not([readonly]):not([disabled]){font-size:16px}
button:not(.carobtn),.nav a,.fb{min-height:40px}}
/* ===== END SHARED CORE ===== */

/* to-do: real table cells so row rhythm matches the other tables */
#downloads,#filebrowser{display:block;margin-top:20px}
/* The browsed path lives in the file browser's header row, which the stacked
   mobile layout hides - this row carries it instead, and only there. */
tr.fbhead{display:none}
@media (max-width:760px){table.resp tr.fbhead{display:block}}
.midright .tablewrap{width:100%}
table.todo{width:100%;table-layout:fixed}
table.todo td{vertical-align:top;white-space:nowrap}
.todo .tcheck{width:32px;padding-right:0}
.todo .tcheck input{width:16px;height:16px;margin:3px 0 0;cursor:pointer;accent-color:var(--accent)}
.todo .ttext{white-space:normal;line-height:1.45;width:auto;overflow-wrap:anywhere}
.todo .ttext label{cursor:pointer;display:block}
.todo .ttext label.tdone{text-decoration:line-through;color:var(--muted)}
.todo .tdate{display:block;margin-top:3px;font-size:12px;color:var(--muted)}
.todo .tdel{width:34px;text-align:right;padding-left:0}
.todo .tdel a{color:var(--muted);font-size:18px;line-height:1;text-decoration:none;
display:inline-block;min-width:26px;text-align:center}
.todo .tdel a:hover{color:var(--bad);text-decoration:none}
.todo .tadd form{display:flex;gap:8px}
.todo .tadd input{flex:1;min-width:0;padding:7px 10px;border:1px solid var(--line);
border-radius:7px;background:var(--bg);color:var(--fg);font-size:14px}
.todo .tadd input:focus{outline:2px solid var(--accent);outline-offset:1px}
.todo .tadd button{padding:7px 14px;border:0;border-radius:7px;background:var(--accent);
color:#fff;font-weight:600;cursor:pointer;font-size:14px}
@media (pointer:coarse){
.todo .tcheck{width:40px}
.todo .tcheck input{width:20px;height:20px}
.todo .tdel a{min-width:36px;min-height:36px;line-height:36px}}
.mid{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);
gap:var(--gap);align-items:stretch;margin-top:20px}
/* Both columns take the height of the taller one, and the three tables are
   distributed down that height instead of bunching at the top. */
.midleft{display:flex;flex-direction:column;gap:var(--gap);justify-content:space-between;min-width:0}
.midright{min-width:0}
/* clears the sticky nav bar rather than sliding under it */
.midright #todo{position:sticky;top:66px}
@media (max-width:1150px){.mid{grid-template-columns:1fr}
.midright #todo{position:static}}
/* Fill the column: every cell shrinks to its content except the first,
   which absorbs the remaining width so the table spans the pane. Confined to
   wide screens - below 760px table.resp stacks these same tables, and these
   width rules would otherwise out-order it at equal specificity. */
@media (min-width:761px){
table.fill{width:100%;table-layout:auto}
table.fill th,table.fill td{width:1%;white-space:nowrap}
table.fill th:first-child,table.fill td:first-child{width:auto;white-space:normal}
/* Services also lets the public-hostname column breathe. */
table.fill2 th:last-child,table.fill2 td:last-child{width:auto}}
.sec2{margin:22px 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.carousel{position:relative}
.ptrack{display:flex;gap:14px;overflow-x:auto;scroll-behavior:smooth;
scroll-snap-type:x proximity;padding:4px 2px 12px;scrollbar-width:thin;
scrollbar-color:var(--line) transparent}
.ptrack::-webkit-scrollbar{height:8px}
.ptrack::-webkit-scrollbar-track{background:transparent}
.ptrack::-webkit-scrollbar-thumb{background:var(--line);border-radius:4px}
/* Fluid poster width: ~3 per screen on a phone, 150px once there is room. */
.poster{flex:0 0 clamp(112px,30vw,150px);scroll-snap-align:start;
display:block;background:var(--card);border:1px solid var(--line);border-radius:var(--r);
overflow:hidden;text-decoration:none;color:var(--fg);transition:transform .12s,border-color .12s}
.carobtn{position:absolute;top:34%;z-index:2;width:36px;height:36px;border-radius:50%;
border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;
font-size:20px;line-height:1;display:grid;place-items:center;opacity:.92}
.carobtn:hover{border-color:var(--accent);color:var(--accent)}
.carobtn.prev{left:-8px}.carobtn.next{right:-8px}
@media (hover:none){.carobtn{display:none}}
.poster:hover{transform:translateY(-3px);border-color:var(--accent);text-decoration:none}
.poster img{display:block;width:100%;aspect-ratio:2/3;object-fit:cover;background:var(--line)}
.poster .pt{display:block;padding:8px 10px 0;font-size:13px;font-weight:600;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.poster .pm{display:block;padding:0 10px 10px;font-size:12px;color:var(--muted)}
footer{color:var(--muted);font-size:12px;margin-top:18px;text-align:center}
"""


def bar(pct):
    cls = "bad" if pct >= 90 else ("warn" if pct >= 75 else "")
    return f'<div class="bar"><i class="{cls}" style="width:{min(pct,100)}%"></i></div>'


def render(h, cts, svcs, disks, latest):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    p = []
    p.append("<!doctype html>")
    p.append("<!-- generated by media-dashboard.py -->")
    p.append('<meta charset="utf-8">')
    p.append(f"<title>{html.escape(run('hostname') or 'pve')} stack</title>")
    p.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    # Tells the browser both themes are supported, so form controls and the
    # mobile address bar follow the page instead of staying light.
    p.append('<meta name="color-scheme" content="light dark">')
    p.append('<meta name="theme-color" content="#f6f7f9" '
             'media="(prefers-color-scheme:light)">')
    p.append('<meta name="theme-color" content="#0d1117" '
             'media="(prefers-color-scheme:dark)">')
    p.append('<meta http-equiv="refresh" content="120">')
    p.append(f"<style>{CSS}</style>")
    p.append('<div class="wrap">')
    p.append("<h1>Media stack</h1>")
    br = site.load().get("bridges", {})
    wan = (br.get("uplink") or {}).get("cidr") or "no address"
    lan = (br.get("internal") or {}).get("cidr") or "-"
    p.append(f'<div class="sub">{html.escape(run("hostname") or "pve")} '
             f'&middot; uplink {html.escape(wan)} '
             f'&middot; internal {html.escape(lan)} &middot; refreshed {now}</div>')

    if h["reboot_required"]:
        p.append('<div class="banner"><b>Reboot required</b> &mdash; a package update needs a host restart.</div>')
    if h["pending_updates"]:
        p.append(f'<div class="banner">{h["pending_updates"]} package update(s) pending on the host.</div>')

    # host + gpu cards
    p.append('<div class="grid">')
    p.append('<div class="card"><h2>Host</h2>')
    for k, v in (("Proxmox", h["pve"]), ("Kernel", h["kernel"]),
                 ("Uptime", h["uptime"]), ("Load", h["load"])):
        p.append(f'<div class="kv"><span>{k}</span><span>{html.escape(str(v))}</span></div>')
    p.append("</div>")

    p.append('<div class="card"><h2>Resources</h2>')
    p.append(f'<div class="kv"><span>Memory</span><span>{h["mem"]}</span></div>{bar(h["mem_pct"])}')
    p.append(f'<div class="kv"><span>Root disk</span><span>{h["disk"]}</span></div>{bar(h["disk_pct"])}')
    p.append(f'<div class="kv"><span>LVM thin</span><span>{h["thin_pct"]}%</span></div>{bar(h["thin_pct"])}')
    p.append("</div>")

    for i, g in enumerate(h["gpus"]):
        p.append(f'<div class="card"><h2>GPU {i}</h2>')
        p.append(f'<div class="kv"><span>Model</span><span>{html.escape(g["name"])}</span></div>')
        p.append(f'<div class="kv"><span>Driver</span><span class="ver">{g["driver"]}</span></div>')
        p.append(f'<div class="kv"><span>Temp</span><span>{g["temp"]} &deg;C</span></div>')
        p.append(f'<div class="kv"><span>VRAM</span><span>{g["mem_used"]} / {g["mem_total"]} MiB</span></div>')
        p.append("</div>")
    p.append("</div>")

    # Two-column band: tables on the left, to-do sidebar on the right.
    p.append('<div class="mid"><div class="midleft">')

    # media disks
    if disks:
        p.append('<div class="tablewrap"><table class="fill resp">'
                 '<tr class="hd"><th>Media disk</th><th>Device</th><th>Used</th><th>Free</th>'
                 '<th>Full</th><th>SMART</th></tr>')
        for d in disks:
            hcls = "ok" if d["health"].upper() == "PASSED" and not d["warn"] else "bad"
            hlabel = d["health"] + (f' — {d["warn"]}' if d["warn"] else "")
            pcls = "bad" if d["pct"] >= 90 else ("warn" if d["pct"] >= 75 else "")
            p.append(f'<tr><td><b>{html.escape(d["mount"])}</b></td>'
                     f'<td class="ver" data-label="Device">{d["dev"]}</td>'
                     f'<td data-label="Used">{d["used"]} / {d["size"]}</td>'
                     f'<td data-label="Free">{d["avail"]}</td>'
                     f'<td data-label="Full" style="min-width:110px">{d["pct"]}%{bar(d["pct"])}</td>'
                     f'<td data-label="SMART">'
                     f'<span class="pill {hcls}">{html.escape(hlabel)}</span></td></tr>')
        p.append("</table></div>")

    # containers
    p.append('<div class="tablewrap"><table class="fill resp"><tr class="hd">'
             '<th>Container</th><th>Status</th><th>Uptime</th><th>Memory</th></tr>')
    for c in cts:
        cls = "ok" if c["status"] == "running" else "bad"
        p.append(f'<tr><td>{c["id"]} {html.escape(c["name"])}</td>'
                 f'<td data-label="Status"><span class="pill {cls}">{c["status"]}</span></td>'
                 f'<td data-label="Uptime">{html.escape(c["uptime"])}</td>'
                 f'<td data-label="Memory">{c["mem"]}</td></tr>')
    p.append("</table></div>")

    # services
    p.append('<div class="tablewrap"><table class="fill fill2 resp">'
             '<tr class="hd"><th>Service</th><th>Version</th><th>Status</th><th>Container</th>'
             '<th>Local</th><th>Public</th></tr>')
    for s in svcs:
        up = s["code"] not in ("000", "", "502", "503", "504")
        cls = "ok" if up else "bad"
        label = s["code"] if up else "down"
        ver = s["version"] or "&mdash;"
        note = f' <span style="color:var(--muted);font-size:12px">{s["note"]}</span>' if s.get("note") else ""
        link = (f'<a href="{s["url"]}" target="_blank" rel="noopener">{s["url"].replace("http://","")}</a>'
                if s["url"] != "-" else "&mdash;")
        # Public column: link real hostnames, leave markers like "internal only" as text.
        host = s["host"]
        if "." in host:
            pub = (f'<a href="https://{html.escape(host)}" target="_blank" rel="noopener">'
                   f'{html.escape(host)}</a>')
        else:
            pub = f'<span style="color:var(--muted)">{html.escape(host)}</span>'
        p.append(f'<tr><td><b>{html.escape(s["name"])}</b>{note}</td>'
                 f'<td class="ver" data-label="Version">{ver}</td>'
                 f'<td data-label="Status"><span class="pill {cls}">{label}</span></td>'
                 f'<td data-label="Container">{s["ct"]}</td>'
                 f'<td data-label="Local">{link}</td>'
                 f'<td class="ver" data-label="Public">{pub}</td></tr>')
    p.append("</table></div>")

    # close left column, open the to-do sidebar
    p.append('</div><div class="midright"><div id="todo"></div></div></div>')

    # recently added to Jellyfin
    if latest:
        p.append('<div class="sec2">Recently added to Jellyfin</div>')
        p.append('<div class="carousel">'
                 '<button class="carobtn prev" aria-label="scroll left" '
                 'onclick="ptScroll(-1)">&#8249;</button>'
                 '<div class="ptrack" id="ptrack">')
        for it in latest:
            # Poster is proxied through the dashboard so the Jellyfin API key
            # never reaches the browser.
            # Prefer the public hostname the tunnel actually publishes for
            # Jellyfin; fall back to its LAN address when it has none.
            jf = site.find("Jellyfin") or {}
            jf_base = (f"https://{jf['host']}" if jf.get("host")
                       else jf.get("url") or "")
            play = (f'{jf_base}/web/#/details'
                    f'?id={it["id"]}&serverId={it["server"]}')
            meta = " &middot; ".join(x for x in (str(it["year"]), it["runtime"]) if x)
            p.append(
                f'<a class="poster" href="{play}" target="_blank" rel="noopener" '
                f'title="Play {html.escape(it["name"])} in Jellyfin">'
                f'<img loading="lazy" src="/api/poster?id={it["id"]}" alt="">'
                f'<span class="pt">{html.escape(it["name"])}</span>'
                f'<span class="pm">{meta}</span></a>')
        p.append('</div><button class="carobtn next" aria-label="scroll right" '
                 'onclick="ptScroll(1)">&#8250;</button></div>')
        p.append('<script>function ptScroll(d){var t=document.getElementById("ptrack");'
                 'if(t)t.scrollBy({left:d*t.clientWidth*0.8,behavior:"smooth"});}</script>')

    # live panels rendered client-side by the web server
    p.append('<div id="downloads"></div>')
    p.append('<div id="filebrowser"></div>')

    p.append('<footer>Auto-refreshes every 2 minutes &middot; '
             'regenerated by media-dashboard.timer every 2 minutes</footer>')
    p.append("</div>")
    return "\n".join(p)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    # Re-walk the host first: containers get created, services get moved, the
    # uplink gets a new lease. Everything below reads the result, and the web
    # UI reads the cache this leaves behind rather than paying for detection.
    try:
        site.load(refresh=True)
    except Exception as e:
        print(f"site detection failed, using last known: {e}")
        site.load()
    h, cts, svcs, disks = host_info(), ct_info(), services(), media_disks()
    page = render(h, cts, svcs, disks, recently_added())
    tmp = OUT_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(page)
    shutil.move(tmp, OUT_FILE)
    os.chmod(OUT_FILE, 0o644)

    # The topology snapshot is a bonus - never let it break the status page.
    topo = None
    try:
        topo = topology(h, cts, svcs, disks)
        os.makedirs(os.path.dirname(TOPO_FILE), exist_ok=True)
        tmp = TOPO_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(topo, f)
        shutil.move(tmp, TOPO_FILE)
        os.chmod(TOPO_FILE, 0o644)
    except Exception as e:
        print(f"topology collection failed: {e}")

    # What this host publishes to any dashboard federating it. Written here
    # rather than computed on request so serving it is a file read and the web
    # service needs no extra privilege - see mdash_fleet.
    try:
        fleet.write_export(fleet.build_export(
            host=h, guests=cts, services=svcs, disks=disks,
            issues=(topo or {}).get("issues") or [],
            updates=(topo or {}).get("updates") or [],
            bridges=site.load().get("bridges", {}),
            storage=site.storage_info(), tunnel=site.tunnel_info(),
            name=run("hostname") or "pve"))
    except Exception as e:
        print(f"fleet export failed: {e}")


if __name__ == "__main__":
    main()
