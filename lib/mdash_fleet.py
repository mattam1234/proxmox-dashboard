#!/usr/bin/env python3
"""Several Proxmox hosts, one dashboard.

Each host runs its own dashboard exactly as before - it detects itself, renders
its own pages, and runs its own privileged jobs. This module adds a second way
to read one: a signed, read-only export that another dashboard can poll. Point
one dashboard at the others and it becomes the place you look, without any host
giving up control of itself.

Why federate rather than reach into the other hosts directly:

  * **`pct exec` is local.** Service detection - what is actually running in a
    container, what version it is - cannot be done over the Proxmox API from
    somewhere else. Only a dashboard *on* the host can see that, so the useful
    unit to share is its finished picture, not its credentials.
  * **No new trust.** The aggregator never gets root anywhere. A peer token
    reads one JSON file and can do nothing else - it cannot spool a job, read
    the credentials page, or open a terminal. Losing one is an information
    disclosure, not a compromise.
  * **Peers stay independent.** A host that is down, unreachable or mid-reboot
    shows as stale on the fleet page and changes nothing else. There is no
    shared database to corrupt and no leader to elect.

The export is written by the collector (`fleet-export.json`) rather than
computed on request, so serving it costs a file read and the web service needs
no new privileges to answer.

Layout:

  /etc/media-dashboard/peers.json      who to poll, and with which token (0600)
  /etc/media-dashboard/fleet-token     the token *this* host demands of callers
  /var/lib/media-dashboard/fleet/      last good answer per peer, plus errors
  /var/lib/media-dashboard/fleet-export.json   what this host publishes
"""

import hmac
import json
import os
import secrets
import shutil
import ssl
import threading
import time
import urllib.error
import urllib.request

PEERS_FILE = "/etc/media-dashboard/peers.json"
TOKEN_FILE = "/etc/media-dashboard/fleet-token"
EXPORT_FILE = "/var/lib/media-dashboard/fleet-export.json"
CACHE_DIR = "/var/lib/media-dashboard/fleet"

POLL_INTERVAL = 60          # seconds between sweeps
FETCH_TIMEOUT = 10          # per peer, per attempt
STALE_AFTER = 300           # an answer older than this is called stale
MAX_EXPORT = 4 * 1024 * 1024

_lock = threading.Lock()
_poller = None


# ------------------------------------------------------------------ storage
def _read(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def _write(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.chmod(tmp, mode)
    shutil.move(tmp, path)


# -------------------------------------------------------------------- token
def local_token(create=False):
    """The token this host demands from anything polling its export.

    Created on demand rather than at install time, so a host that is never
    federated never has one lying around.
    """
    try:
        with open(TOKEN_FILE) as f:
            tok = f.read().strip()
        if tok:
            return tok
    except Exception:
        pass
    if not create:
        return ""
    tok = secrets.token_urlsafe(32)
    os.makedirs(os.path.dirname(TOKEN_FILE), mode=0o700, exist_ok=True)
    tmp = TOKEN_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(tok + "\n")
    os.chmod(tmp, 0o600)
    shutil.move(tmp, TOKEN_FILE)
    return tok


def token_ok(presented):
    """Constant-time check of a caller's bearer token."""
    want = local_token()
    if not want or not presented:
        return False
    return hmac.compare_digest(want, presented.strip())


# -------------------------------------------------------------------- peers
def _norm_url(url):
    url = (url or "").strip().rstrip("/")
    if url and "://" not in url:
        url = "http://" + url
    return url


def peers():
    """Configured peers. Tokens are included - never hand this to a browser."""
    d = _read(PEERS_FILE, {})
    out = []
    for p in (d.get("peers") or []):
        if not isinstance(p, dict) or not p.get("url"):
            continue
        out.append({"id": str(p.get("id") or p.get("url")),
                    "name": str(p.get("name") or p.get("id") or p["url"]),
                    "url": _norm_url(p["url"]),
                    "token": str(p.get("token") or ""),
                    "insecure_tls": bool(p.get("insecure_tls")),
                    "enabled": p.get("enabled", True) is not False})
    return out


def peers_public():
    """Peers as the UI may see them: everything except the token."""
    return [{k: v for k, v in p.items() if k != "token"} for p in peers()]


def save_peers(rows):
    _write(PEERS_FILE, {"peers": rows}, mode=0o600)


def add_peer(pid, name, url, token, insecure_tls=False):
    rows = peers()
    if any(p["id"] == pid for p in rows):
        raise ValueError(f"a peer with id {pid!r} already exists")
    rows.append({"id": pid, "name": name, "url": _norm_url(url), "token": token,
                 "insecure_tls": bool(insecure_tls), "enabled": True})
    save_peers(rows)


def remove_peer(pid):
    rows = [p for p in peers() if p["id"] != pid]
    save_peers(rows)
    try:
        os.remove(os.path.join(CACHE_DIR, _safe(pid) + ".json"))
    except OSError:
        pass


def set_enabled(pid, on):
    rows = peers()
    for p in rows:
        if p["id"] == pid:
            p["enabled"] = bool(on)
    save_peers(rows)


def _safe(pid):
    """A peer id reduced to something that cannot escape the cache directory."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in pid)[:64] or "peer"


# ------------------------------------------------------------------ fetching
def fetch(peer):
    """Poll one peer. Returns (payload, error) - never raises."""
    url = peer["url"] + "/api/fleet/export"
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + peer["token"],
        "Accept": "application/json",
        "User-Agent": "media-dashboard-fleet/1",
    })
    ctx = None
    if url.startswith("https://") and peer.get("insecure_tls"):
        # Opt-in per peer, for a host behind its own self-signed certificate.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT, context=ctx) as r:
            raw = r.read(MAX_EXPORT + 1)
        if len(raw) > MAX_EXPORT:
            return None, "export too large"
        data = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(data, dict):
            return None, "export was not an object"
        return data, None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return None, "peer rejected the token"
        if e.code == 404:
            return None, "peer has no fleet export (older dashboard?)"
        return None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"unreachable: {getattr(e, 'reason', e)}"
    except json.JSONDecodeError:
        return None, "peer returned something that was not JSON"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _cache_path(pid):
    return os.path.join(CACHE_DIR, _safe(pid) + ".json")


def poll_one(peer):
    """Fetch a peer and cache the result. Returns the cache entry."""
    data, err = fetch(peer)
    prev = _read(_cache_path(peer["id"]), {})
    entry = {"id": peer["id"], "name": peer["name"], "url": peer["url"],
             "checked": int(time.time())}
    if err:
        # Keep the last good picture and mark it stale rather than blanking the
        # host - "unreachable since 09:12" is more use than an empty card.
        entry["error"] = err
        entry["data"] = prev.get("data")
        entry["fetched"] = prev.get("fetched")
    else:
        entry["error"] = None
        entry["data"] = data
        entry["fetched"] = int(time.time())
    _write(_cache_path(peer["id"]), entry)
    return entry


def poll_all():
    """Sweep every enabled peer, each in its own thread so one slow host does
    not hold up the rest."""
    rows = [p for p in peers() if p["enabled"]]
    if not rows:
        return []
    out = [None] * len(rows)

    def work(i, p):
        try:
            out[i] = poll_one(p)
        except Exception as e:
            out[i] = {"id": p["id"], "name": p["name"], "url": p["url"],
                      "checked": int(time.time()), "error": str(e), "data": None}

    threads = [threading.Thread(target=work, args=(i, p), daemon=True)
               for i, p in enumerate(rows)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(FETCH_TIMEOUT + 5)
    return [o for o in out if o]


def start_poller():
    """Background sweep, started once by the web service.

    Polling here rather than in the collector keeps a slow or unreachable peer
    away from the thing that has a 300 second start timeout, and means the
    fleet page is fresh even between collector runs.
    """
    global _poller
    with _lock:
        if _poller is not None:
            return
        def loop():
            while True:
                try:
                    if peers():
                        poll_all()
                except Exception:
                    pass
                time.sleep(POLL_INTERVAL)
        _poller = threading.Thread(target=loop, daemon=True)
        _poller.start()


# ------------------------------------------------------------------ assembly
def local_entry():
    """This host, in the same shape a peer arrives in.

    The local host is not special-cased in the UI - it is just the entry that
    never has a fetch error, so one host and ten hosts render identically.
    """
    data = _read(EXPORT_FILE, {})
    if not data:
        return None
    return {"id": data.get("id") or "local", "name": data.get("name") or "this host",
            "url": "", "local": True, "error": None,
            "fetched": data.get("generated"), "checked": int(time.time()),
            "data": data}


def fleet(include_local=True):
    """Every host, local first, each annotated with how fresh it is."""
    out = []
    if include_local:
        le = local_entry()
        if le:
            out.append(le)
    for p in peers():
        entry = _read(_cache_path(p["id"]), None)
        if not entry:
            entry = {"id": p["id"], "name": p["name"], "url": p["url"],
                     "error": "not polled yet", "data": None,
                     "fetched": None, "checked": None}
        entry["enabled"] = p["enabled"]
        entry["url"] = p["url"]
        entry["name"] = p["name"]
        out.append(entry)

    now = int(time.time())
    for e in out:
        f = e.get("fetched")
        e["age"] = (now - f) if f else None
        e["stale"] = bool(f and (now - f) > STALE_AFTER)
        e["ok"] = bool(e.get("data")) and not e.get("error") and not e["stale"]
    return out


def rollup(entries):
    """What needs attention, across every host, newest problem first.

    This is the reason to look at a fleet page rather than ten dashboards: the
    per-host detail is below, but the first thing on screen should be the union
    of everything wrong anywhere.
    """
    issues, updates, unreachable = [], [], []
    hosts = guests = services = 0
    running = svc_up = 0

    for e in entries:
        d = e.get("data") or {}
        if e.get("error") or e.get("stale"):
            unreachable.append({"host": e["name"], "why": e.get("error")
                                or f"last seen {_ago(e.get('age'))} ago"})
        if not d:
            continue
        hosts += 1
        gs = d.get("guests") or []
        guests += len(gs)
        running += sum(1 for g in gs if g.get("status") == "running")
        svcs = d.get("services") or []
        services += len(svcs)
        svc_up += sum(1 for s in svcs if s.get("up"))
        for i in d.get("issues") or []:
            issues.append({"host": e["name"], "text": i})
        for u in d.get("updates") or []:
            updates.append({"host": e["name"], "name": u.get("name"),
                            "detail": u.get("detail"), "url": u.get("url")})
    return {"hosts": hosts, "guests": guests, "guests_running": running,
            "services": services, "services_up": svc_up,
            "issues": issues, "updates": updates, "unreachable": unreachable}


def _ago(seconds):
    if seconds is None:
        return "never"
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 5400:
        return f"{int(seconds // 60)}m"
    if seconds < 172800:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"


# ------------------------------------------------------------------- export
def build_export(host, guests, services, disks, issues, updates, bridges,
                 storage, tunnel, name):
    """Assemble what this host publishes to its peers.

    Deliberately narrow: enough to render a host's card and drill into its
    services, and nothing that would help someone attack it. No API keys, no
    tokens, no credentials file, no job history, no compose contents.
    """
    return {
        "schema": 1,
        "id": name,
        "name": name,
        "generated": int(time.time()),
        "host": {
            "pve": host.get("pve"), "kernel": host.get("kernel"),
            "uptime": host.get("uptime"), "load": host.get("load"),
            "mem": host.get("mem"), "mem_pct": host.get("mem_pct"),
            "disk": host.get("disk"), "disk_pct": host.get("disk_pct"),
            "thin_pct": host.get("thin_pct"),
            "gpus": host.get("gpus") or [],
            "reboot_required": bool(host.get("reboot_required")),
            "pending_updates": host.get("pending_updates") or 0,
        },
        "network": {"uplink": (bridges.get("uplink") or {}).get("cidr", ""),
                    "internal": (bridges.get("internal") or {}).get("cidr", "")},
        "tunnel": {"zone": tunnel.get("zone", ""),
                   "routes": len(tunnel.get("hostnames") or [])},
        "storage": {"shared": storage.get("shared", ""),
                    "bulk_roots": storage.get("bulk_roots") or []},
        "guests": [{"id": g.get("id"), "name": g.get("name"),
                    "type": g.get("type"), "status": g.get("status"),
                    "uptime": g.get("uptime"), "mem": g.get("mem")}
                   for g in guests],
        "services": [{"name": s.get("name"), "ct": s.get("ct"),
                      "cid": s.get("cid"), "icon": s.get("icon"),
                      "version": s.get("version"), "code": s.get("code"),
                      "up": s.get("code") in ("200", "301", "302", "307", "308",
                                              "401", "403"),
                      "host": s.get("host"), "url": s.get("url"),
                      "discovered": bool(s.get("discovered"))}
                     for s in services],
        "disks": [{"mount": d.get("mount"), "size": d.get("size"),
                   "used": d.get("used"), "avail": d.get("avail"),
                   "pct": d.get("pct"), "health": d.get("health"),
                   "warn": d.get("warn")} for d in disks],
        "issues": list(issues or []),
        "updates": [{"name": u.get("name"), "detail": u.get("detail"),
                     "url": u.get("url")} for u in (updates or [])],
    }


def write_export(payload):
    _write(EXPORT_FILE, payload)
