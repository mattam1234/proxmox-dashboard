"""Admin-only Cloudflare tunnel routing for the media dashboard.

Lives in its own module so the dashboard script needs only a few lines to wire
it in. Everything here is reached through the dashboard's own session cookie and
admin role - there is no second listening port and no second credential.

Wiring (in media-dashboard-web.py):

    import mdash_tunnel

    # in do_GET, after the session check:
    if mdash_tunnel.handle_get(self, path, qs):
        return

    # at the top of do_POST (it checks the session itself):
    if mdash_tunnel.handle_post(self, p):
        return

    # in nav(), inside the `if admin:` block:
    out += a("/tunnel", "Routing")

Where each half of this comes from.

*Reads come from the connector.* Which container it runs in and what it
listens on are detected (see mdash_site), never configured. It exposes its own
effective config and health on the internal bridge via --metrics, so the route
table and connection count need no credentials at all and show what is
genuinely being served rather than what an API says should be.

*Writes have to go through the API* when the tunnel is remotely managed, which
is the common case: the connector runs `cloudflared tunnel run --token-file`
and Cloudflare stores the ingress
and pushes it down. That a local config.yml cannot take over was tested on this
host, not assumed - running cloudflared with credentials-file plus a
config.yml holding an extra rule still served the pushed remote config, and the
extra rule never appeared in /config. Making the local file authoritative means
deleting the remote config, which itself needs an API token. `cloudflared
tunnel route dns` is likewise unavailable: it authenticates only with an origin
cert from the interactive `cloudflared tunnel login`, never run here. So writes
use the same API calls /root/cf-configure-tunnel.sh already uses, and nothing
about how the tunnel runs has to change.

Publishing a hostname puts a LAN service on the public internet, so: admin is
re-checked per request, hostnames are constrained to the configured zone, a DNS
record belonging to a *different* tunnel is never overwritten, the catch-all
404 rule is always kept last, and every change is written to the audit log.

The API token is read from /etc/media-dashboard/cf-token when present;
otherwise the page asks for one per change and it is never stored. It is never
logged and never sent back to the browser.
"""
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, "/usr/local/lib/mdash")
import mdash_site as site                              # noqa: E402

CF_API = "https://api.cloudflare.com/client/v4"
TOKEN_FILE = "/etc/media-dashboard/cf-token"
CONF_FILE = "/etc/media-dashboard/cloudflare.json"

# The connector exposes its own effective config and health on the internal
# bridge. Reading routes from there needs no API token and shows what is
# actually being served, rather than what an API call says should be. Where it
# runs and what it listens on are detected, not configured.
CONNECTOR_TIMEOUT = 4
CLOUDFLARED_UNIT = "cloudflared"


def connector_base():
    return site.tunnel_info().get("connector") or ""


def cloudflared_ct():
    """Container the connector runs in, or None when this host has no tunnel."""
    return site.tunnel_info().get("cid")


def ct_label():
    """How to refer to the connector's container in a sentence."""
    cid = cloudflared_ct()
    return f"CT {cid}" if cid else "the connector container"


# The account and tunnel ids identify a Cloudflare account, so they cannot be
# read off this host - put {"account":...,"tunnel":...} in CONF_FILE. The zone
# is inferred from the hostnames the connector is already serving, so an
# existing tunnel needs no configuration at all.
DEFAULTS = {"account": "", "tunnel": "", "zone": ""}

HTTP_TIMEOUT = 25
PROBE_TIMEOUT = 1.5
PROBE_WORKERS = 12
MAX_BODY = 16 * 1024
MAX_RULES = 100

# A label per RFC 1123, joined into a name inside the configured zone.
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SERVICE_SCHEMES = ("http", "https", "tcp", "ssh", "rdp")
PORT_RE = re.compile(r"^[0-9]{1,5}$")
CATCH_ALL = {"service": "http_status:404"}

_zone_id_cache = [None]           # (zone name, id) - a zone id never changes
_lock = threading.Lock()


def _main_attr(name, default=None):
    """Borrow nav()/audit()/enqueue() from the dashboard without importing it."""
    return getattr(sys.modules.get("__main__"), name, default)


def _audit(user, msg):
    fn = _main_attr("audit")
    if fn:
        try:
            fn(user, msg)
        except Exception:
            pass


def mode():
    """'api' (default) or 'local'.

    'local' means the connector's own config.yml is the source of truth and
    changes go through the runner's tunnel.ingress action. That is only correct once the
    tunnel's remote config has been deleted - until then Cloudflare's pushed
    config wins and edits to the local file do nothing. Set it with
    {"mode": "local"} in CONF_FILE, at the same time as that cutover.
    """
    return "local" if conf().get("mode") == "local" else "api"


def conf():
    c = dict(DEFAULTS)
    t = site.tunnel_info()
    if t.get("zone"):
        c["zone"] = t["zone"]
    if t.get("tunnel_id"):
        c["tunnel"] = t["tunnel_id"]
    try:
        with open(CONF_FILE) as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            for k in ("account", "tunnel", "zone", "mode"):
                if isinstance(loaded.get(k), str) and loaded[k].strip():
                    c[k] = loaded[k].strip()
    except Exception:
        pass
    return c


def tunnel_target(c=None):
    return f"{(c or conf())['tunnel']}.cfargotunnel.com"


def file_token():
    try:
        with open(TOKEN_FILE) as f:
            return f.read().strip() or None
    except Exception:
        return None


# ------------------------------------------------------------------ API calls
def cf(method, path, token, body=None):
    """One Cloudflare API call -> (ok, result, error_message).

    Errors come back as text for the UI; the token never appears in either.
    """
    if not token:
        return False, None, "no API token"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(CF_API + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            payload = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return False, None, f"HTTP {e.code}"
        errs = payload.get("errors") or []
        msg = (errs[0].get("message") if errs and isinstance(errs[0], dict)
               else None) or f"HTTP {e.code}"
        return False, None, str(msg)[:300]
    except Exception as e:
        return False, None, f"{type(e).__name__}: {str(e)[:200]}"

    if not payload.get("success"):
        errs = payload.get("errors") or []
        msg = (errs[0].get("message") if errs and isinstance(errs[0], dict)
               else None) or "request rejected"
        return False, None, str(msg)[:300]
    return True, payload.get("result"), None


def zone_id(token, c):
    with _lock:
        cached = _zone_id_cache[0]
        if cached and cached[0] == c["zone"]:
            return cached[1], None
    ok, res, err = cf("GET", "/zones?name=" + urllib.parse.quote(c["zone"]), token)
    if not ok:
        return None, err
    if not res:
        return None, f"zone {c['zone']} not found on this account"
    zid = res[0].get("id")
    with _lock:
        _zone_id_cache[0] = (c["zone"], zid)
    return zid, None


def get_ingress(token, c):
    """Current tunnel configuration -> (full config dict, error)."""
    ok, res, err = cf("GET", f"/accounts/{c['account']}/cfd_tunnel/{c['tunnel']}"
                             "/configurations", token)
    if not ok:
        return None, err
    return (res or {}).get("config") or {}, None


def put_ingress(token, c, config):
    ok, _res, err = cf("PUT", f"/accounts/{c['account']}/cfd_tunnel/{c['tunnel']}"
                              "/configurations", token, {"config": config})
    return ok, err


def get_tunnel(token, c):
    ok, res, err = cf("GET", f"/accounts/{c['account']}/cfd_tunnel/{c['tunnel']}", token)
    return (res or {}) if ok else None, err


def list_dns(token, c):
    """CNAME records in the zone -> ({name: record}, error)."""
    zid, err = zone_id(token, c)
    if err:
        return None, err
    ok, res, err = cf("GET", f"/zones/{zid}/dns_records?type=CNAME&per_page=500", token)
    if not ok:
        return None, err
    return {r["name"]: r for r in (res or []) if r.get("name")}, None


def upsert_dns(token, c, hostname, force=False):
    """Point hostname at this tunnel. Refuses to steal another tunnel's record."""
    zid, err = zone_id(token, c)
    if err:
        return False, err
    records, err = list_dns(token, c)
    if err:
        return False, err
    target = tunnel_target(c)
    existing = records.get(hostname)
    if existing and (existing.get("content") or "") != target and not force:
        return False, (f"{hostname} already points at {existing.get('content')}, "
                       "which is not this tunnel")
    payload = {"type": "CNAME", "name": hostname, "content": target,
               "proxied": True, "ttl": 1}
    if existing:
        ok, _r, err = cf("PUT", f"/zones/{zid}/dns_records/{existing['id']}",
                         token, payload)
    else:
        ok, _r, err = cf("POST", f"/zones/{zid}/dns_records", token, payload)
    return ok, err


def delete_dns(token, c, hostname):
    """Remove the CNAME, but only while it still points at this tunnel."""
    zid, err = zone_id(token, c)
    if err:
        return False, err
    records, err = list_dns(token, c)
    if err:
        return False, err
    rec = records.get(hostname)
    if not rec:
        return True, None
    if (rec.get("content") or "") != tunnel_target(c):
        return False, f"{hostname} points at {rec.get('content')}, leaving it alone"
    ok, _r, err = cf("DELETE", f"/zones/{zid}/dns_records/{rec['id']}", token)
    return ok, err


# ------------------------------------------------------------- the connector
def _connector_get(path):
    try:
        base = connector_base()
        if not base:
            raise OSError("no tunnel connector on this host")
        with urllib.request.urlopen(base + path,
                                    timeout=CONNECTOR_TIMEOUT) as r:
            return r.read().decode("utf-8", "replace"), None
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:120]}"


def connector_config():
    """Ingress rules the connector is actually serving -> (rules, version, err)."""
    raw, err = _connector_get("/config")
    if err:
        return None, None, err
    try:
        d = json.loads(raw)
        return (d.get("config") or {}).get("ingress") or [], d.get("version"), None
    except Exception as e:
        return None, None, f"unreadable connector config: {str(e)[:120]}"


def connector_ready():
    """Connection health straight from the connector -> (dict, err)."""
    raw, err = _connector_get("/ready")
    if err:
        return None, err
    try:
        return json.loads(raw), None
    except Exception as e:
        return None, f"unreadable connector status: {str(e)[:120]}"


# ----------------------------------------------------------------- validation
def valid_hostname(host, zone):
    """Hostname must sit inside the configured zone. Returns (host, error)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return None, "hostname is required"
    if len(host) > 253:
        return None, "hostname too long"
    if host != zone and not host.endswith("." + zone):
        # A bare label is the common case ("myservice"); qualify it.
        # Anything already dotted but outside the zone is a mistake, not a
        # prefix, so it is refused rather than silently re-homed.
        if "." in host:
            return None, f"hostname must be inside {zone}"
        host = f"{host}.{zone}"
    prefix = "" if host == zone else host[:-(len(zone) + 1)]
    if prefix:
        for label in prefix.split("."):
            if not LABEL_RE.match(label):
                return None, f"invalid hostname part {label!r}"
    return host, None


def valid_service(service):
    """Origin the tunnel forwards to. Returns (service, error)."""
    service = (service or "").strip()
    if not service:
        return None, "service is required"
    if service.startswith("http_status:"):
        return None, "http_status is reserved for the catch-all rule"
    parsed = urllib.parse.urlsplit(service)
    if parsed.scheme not in SERVICE_SCHEMES:
        return None, "service must start with " + ", ".join(
            s + "://" for s in SERVICE_SCHEMES)
    if not parsed.hostname:
        return None, "service needs a host"
    if parsed.port is None:
        # A bare host is legal for http/https but ambiguous for a LAN backend,
        # so require the port that the operator actually meant.
        return None, ("service needs an explicit port, e.g. "
                      + (site.base_url("Jellyfin") or "http://10.0.0.10:8096"))
    if parsed.path not in ("", "/"):
        return None, "path is not supported here, point at host:port"
    return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}", None


def probe(service):
    """Can this host reach the origin? Distinguishes a bad route from a dead app."""
    try:
        parsed = urllib.parse.urlsplit(service)
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            return None
        with socket.create_connection((host, port), PROBE_TIMEOUT):
            return True
    except Exception:
        return False


def probe_all(services):
    out = {}
    lock = threading.Lock()
    todo = list(services)

    def work():
        while True:
            with lock:
                if not todo:
                    return
                svc = todo.pop()
            r = probe(svc)
            with lock:
                out[svc] = r

    threads = [threading.Thread(target=work, daemon=True)
               for _ in range(min(PROBE_WORKERS, max(1, len(services))))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=PROBE_TIMEOUT * 3)
    return out


# --------------------------------------------------------------- assembled view
def split_rules(ingress):
    """Ingress list -> (hostname rules, catch-all rule)."""
    rules = [r for r in (ingress or []) if isinstance(r, dict)]
    hosts = [r for r in rules if r.get("hostname")]
    tail = [r for r in rules if not r.get("hostname")]
    catch = tail[-1] if tail else dict(CATCH_ALL)
    return hosts, catch


def origin_map():
    """'ip:port' -> the service detection found there.

    A route's origin is just an address, which tells a reader nothing. The
    dashboard already knows what is listening on every address in the stack, so
    the two are matched up here and the routing table can show each route as
    the service it actually publishes - name and logo - rather than a bare
    host:port. Anything pointing somewhere we do not recognise (the Proxmox UI
    on the host, say) simply gets no entry and renders as before.
    """
    out = {}
    for svc in site.services_list():
        if svc.get("ip") and svc.get("port"):
            out[f"{svc['ip']}:{svc['port']}"] = {
                "name": svc["name"], "icon": svc.get("icon") or "generic"}
    # The host itself is a legitimate origin - the dashboard and the PVE UI
    # are both published this way.
    hip = site.host_ip()
    if hip:
        out.setdefault(f"{hip}:8085", {"name": "Dashboard", "icon": "generic"})
        out.setdefault(f"{hip}:8006", {"name": "Proxmox VE", "icon": "proxmox"})
    return out


def state(token, do_probe=True):
    """Everything the page shows in one call."""
    c = conf()
    out = {"zone": c["zone"], "tunnel": c["tunnel"], "account": c["account"],
           "target": tunnel_target(c), "token_from_file": bool(file_token()),
           "mode": mode(),
           "routes": [], "orphans": [], "catch_all": CATCH_ALL["service"],
           "origins": origin_map(),
           "tunnel_status": None, "connections": [], "error": None}

    # Prefer the connector: it needs no token and reports what is genuinely
    # being served. The API is the fallback for when it is unreachable.
    ingress, version, cerr = connector_config()
    if ingress is not None:
        out["source"] = "connector"
        out["config_version"] = version
    elif token:
        out["source"] = "api"
        out["connector_error"] = cerr
        config, err = get_ingress(token, c)
        if err:
            out["error"] = err
            return out
        ingress = config.get("ingress")
    else:
        out["error"] = (f"cannot reach the connector in {ct_label()} ({cerr}) "
                        "and no API token is available")
        return out

    hosts, catch = split_rules(ingress)
    out["catch_all"] = catch.get("service", CATCH_ALL["service"])

    # DNS state is only knowable through the API, so without a token the
    # routes still list - their DNS column just reads as unknown.
    records = {}
    if token:
        records, dns_err = list_dns(token, c)
        if dns_err:
            out["dns_error"] = dns_err
            records = {}
    target = tunnel_target(c)

    services = [r.get("service", "") for r in hosts]
    reach = probe_all([s for s in services if s.startswith(("http://", "https://",
                                                            "tcp://"))]) if do_probe else {}

    claimed = set()
    for r in hosts:
        host = r.get("hostname") or ""
        claimed.add(host)
        rec = records.get(host)
        if not token:
            dns = "unknown"
        elif not rec:
            dns = "missing"
        elif (rec.get("content") or "") == target:
            dns = "ok" if rec.get("proxied") else "unproxied"
        else:
            dns = "foreign"
        origin = r.get("originRequest") or {}
        out["routes"].append({
            "hostname": host,
            "service": r.get("service", ""),
            "no_tls_verify": bool(origin.get("noTLSVerify")),
            "dns": dns,
            "dns_target": (rec or {}).get("content"),
            "reachable": reach.get(r.get("service", "")),
        })

    # CNAMEs aimed at this tunnel with no rule behind them answer with the
    # catch-all 404, which looks like an outage rather than a missing route.
    for name, rec in (records or {}).items():
        if name not in claimed and (rec.get("content") or "") == target:
            out["orphans"].append({"hostname": name})

    # Health from the connector itself - no token, and it reflects this
    # machine's tunnel rather than the account's view of it.
    ready, rerr = connector_ready()
    if ready:
        out["ready_connections"] = ready.get("readyConnections")
        out["connector_id"] = ready.get("connectorId")
        out["tunnel_status"] = ("healthy" if ready.get("readyConnections")
                                else "no connections")
    else:
        out["connector_error"] = out.get("connector_error") or rerr

    if token:
        info, _err = get_tunnel(token, c)
        if info:
            out["tunnel_status"] = info.get("status") or out.get("tunnel_status")
            out["tunnel_name"] = info.get("name")
            out["connections"] = [
                {"colo": conn.get("colo_name"), "origin_ip": conn.get("origin_ip"),
                 "opened": conn.get("opened_at")}
                for conn in (info.get("connections") or [])]
    return out


# ------------------------------------------------------------------- mutations
def apply_route(user, token, hostname, service, no_tls_verify=False,
                want_dns=True, force=False, old_hostname=None):
    """Add or update one route, then its DNS record. Returns (result, error)."""
    c = conf()
    host, err = valid_hostname(hostname, c["zone"])
    if err:
        return None, err
    svc, err = valid_service(service)
    if err:
        return None, err

    # Check DNS ownership before writing anything. Pushing ingress first would
    # leave a live rule behind whenever the record turns out to belong to a
    # different tunnel, which reads as a half-applied route.
    if want_dns and not force:
        records, derr = list_dns(token, c)
        if derr:
            return None, derr
        existing = (records or {}).get(host)
        if existing and (existing.get("content") or "") != tunnel_target(c):
            return None, (f"{host} already points at {existing.get('content')}, "
                          "which is not this tunnel")

    config, err = get_ingress(token, c)
    if err:
        return None, err
    hosts, catch = split_rules(config.get("ingress"))

    rule = {"hostname": host, "service": svc}
    if no_tls_verify:
        rule["originRequest"] = {"noTLSVerify": True}

    renamed = bool(old_hostname) and old_hostname != host
    kept, replaced = [], False
    for r in hosts:
        h = r.get("hostname")
        if h == host:
            # Preserve any originRequest keys set elsewhere (Zero Trust UI),
            # overriding only the flag this page owns.
            origin = dict(r.get("originRequest") or {})
            origin.pop("noTLSVerify", None)
            if no_tls_verify:
                origin["noTLSVerify"] = True
            if origin:
                rule["originRequest"] = origin
            kept.append(rule)
            replaced = True
            continue
        if renamed and h == old_hostname:
            continue                      # the rename drops the old rule
        kept.append(r)
    if not replaced:
        if len(kept) >= MAX_RULES:
            return None, f"too many rules (limit {MAX_RULES})"
        kept.append(rule)

    config["ingress"] = kept + [catch]
    ok, err = put_ingress(token, c, config)
    if not ok:
        return None, err
    _audit(user, f"TUNNEL ROUTE {'update' if replaced else 'add'} {host} -> {svc}"
                 f"{' noTLSVerify' if no_tls_verify else ''}"
                 + (f" (renamed from {old_hostname})" if renamed else ""))

    result = {"hostname": host, "service": svc, "dns": "skipped"}
    if want_dns:
        ok, err = upsert_dns(token, c, host, force=force)
        result["dns"] = "ok" if ok else "failed"
        if not ok:
            _audit(user, f"TUNNEL DNS FAIL {host}: {err}")
            return result, err
        _audit(user, f"TUNNEL DNS {host} -> {tunnel_target(c)}")
    if renamed:
        ok, derr = delete_dns(token, c, old_hostname)
        _audit(user, f"TUNNEL DNS remove {old_hostname}"
                     + ("" if ok else f" FAILED: {derr}"))
    return result, None


def delete_route(user, token, hostname, drop_dns=True):
    c = conf()
    host, err = valid_hostname(hostname, c["zone"])
    if err:
        return None, err
    config, err = get_ingress(token, c)
    if err:
        return None, err
    hosts, catch = split_rules(config.get("ingress"))
    kept = [r for r in hosts if r.get("hostname") != host]
    if len(kept) == len(hosts):
        # Nothing in ingress; it may still be a stray DNS record.
        if not drop_dns:
            return None, "no such route"
    else:
        config["ingress"] = kept + [catch]
        ok, err = put_ingress(token, c, config)
        if not ok:
            return None, err
        _audit(user, f"TUNNEL ROUTE delete {host}")

    result = {"hostname": host, "dns": "kept"}
    if drop_dns:
        ok, err = delete_dns(token, c, host)
        result["dns"] = "deleted" if ok else "failed"
        if not ok:
            _audit(user, f"TUNNEL DNS FAIL {host}: {err}")
            return result, err
        _audit(user, f"TUNNEL DNS delete {host}")
    return result, None


def _rules_now():
    """Current rules as plain dicts, as the connector is serving them."""
    ingress, _version, err = connector_config()
    if err:
        return None, err
    hosts, _catch = split_rules(ingress)
    return [{"hostname": r.get("hostname"), "service": r.get("service", ""),
             "no_tls_verify": bool((r.get("originRequest") or {}).get("noTLSVerify"))}
            for r in hosts], None


def _queue_rules(user, rules, what):
    """Hand a complete rule set to the runner, which writes and validates it."""
    enqueue = _main_attr("enqueue")
    if not enqueue:
        return None, "runner queue unavailable"
    try:
        jid = enqueue("tunnel.ingress",
                      {"cid": cloudflared_ct(), "rules": rules}, user)
    except Exception as e:
        return None, str(e)[:200]
    _audit(user, f"TUNNEL {what} via {ct_label()} job={jid} "
                 f"({len(rules)} rules)")
    return jid, None


def apply_route_local(user, hostname, service, no_tls_verify=False,
                      old_hostname=None):
    """Add or update a route by rewriting the connector's config.yml via the runner."""
    c = conf()
    host, err = valid_hostname(hostname, c["zone"])
    if err:
        return None, err
    svc, err = valid_service(service)
    if err:
        return None, err
    rules, err = _rules_now()
    if err:
        return None, f"cannot read current routes from {ct_label()}: {err}"

    renamed = bool(old_hostname) and old_hostname != host
    kept, replaced = [], False
    for r in rules:
        if r["hostname"] == host:
            kept.append({"hostname": host, "service": svc,
                         "no_tls_verify": no_tls_verify})
            replaced = True
            continue
        if renamed and r["hostname"] == old_hostname:
            continue
        kept.append(r)
    if not replaced:
        kept.append({"hostname": host, "service": svc,
                     "no_tls_verify": no_tls_verify})

    jid, err = _queue_rules(user, kept,
                            f"route {'update' if replaced else 'add'} {host} -> {svc}")
    if err:
        return None, err
    return {"hostname": host, "service": svc, "job": jid}, None


def delete_route_local(user, hostname):
    c = conf()
    host, err = valid_hostname(hostname, c["zone"])
    if err:
        return None, err
    rules, err = _rules_now()
    if err:
        return None, f"cannot read current routes from {ct_label()}: {err}"
    kept = [r for r in rules if r["hostname"] != host]
    if len(kept) == len(rules):
        return None, "no such route"
    if not kept:
        return None, ("that is the last route - removing it would leave the "
                      "tunnel serving nothing")
    jid, err = _queue_rules(user, kept, f"route delete {host}")
    if err:
        return None, err
    return {"hostname": host, "job": jid}, None


def restart_connector(user):
    """Hand the restart to the privileged runner, like every other host action."""
    enqueue = _main_attr("enqueue")
    if not enqueue:
        return None, "runner queue unavailable"
    try:
        jid = enqueue("service.systemd",
                      {"cid": cloudflared_ct(), "unit": CLOUDFLARED_UNIT,
                       "op": "restart"}, user)
    except Exception as e:
        return None, str(e)[:200]
    _audit(user, f"TUNNEL connector restart queued job={jid}")
    return jid, None


# ----------------------------------------------------------------------- page
CSS = """
.tun .hdr{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);
  padding:8px 12px;background:var(--card);border:1px solid var(--line);
  border-radius:8px;margin-bottom:12px;align-items:center}
.tun .hdr b{color:var(--fg);font-weight:600}
.tun .st{font-weight:600}
.tun .st.ok{color:#16a34a}
.tun .st.off{color:var(--bad)}
.tun table{width:100%;border-collapse:collapse;background:var(--card);
  border:1px solid var(--line);border-radius:8px;overflow:hidden}
.tun th,.tun td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);
  font-size:13px;vertical-align:middle}
.tun th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.tun tr:last-child td{border-bottom:0}
.tun td.svc{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
/* Each route is shown as the service it publishes. The initial sits behind the
   logo and is hidden once it loads, so an origin we recognise but have no
   artwork for still gets a tile instead of a broken-image box, and one we do
   not recognise at all just renders the hostname as before. */
.tun td.hostcell{display:table-cell}
.tun .hostwrap{display:flex;align-items:center;gap:9px}
.tun .tico{width:26px;height:26px;flex:0 0 26px;border-radius:6px;
  background:var(--bg);border:1px solid var(--line);position:relative;
  overflow:hidden;display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:11px;color:var(--muted)}
.tun .tico.has{color:transparent}
.tun .tico img{width:100%;height:100%;object-fit:contain;padding:4px;
  position:absolute;inset:0}
.tun .hostmeta{min-width:0}
.tun .svcname{display:block;font-size:11px;color:var(--muted);
  text-transform:uppercase;letter-spacing:.05em}
.tun a.host{color:var(--accent);text-decoration:none;font-weight:600}
.tun a.host:hover{text-decoration:underline}
.pill{display:inline-block;font-size:11px;border-radius:999px;padding:1px 8px;
  border:1px solid var(--line);color:var(--muted)}
.pill.ok{color:#16a34a;border-color:color-mix(in srgb,#16a34a 45%,transparent)}
.pill.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
.pill.warn{color:#d97706;border-color:color-mix(in srgb,#d97706 45%,transparent)}
.tb{padding:5px 10px;border:1px solid var(--line);border-radius:7px;background:var(--bg);
  color:var(--fg);font:inherit;font-size:12px;cursor:pointer}
.tb:hover{border-color:var(--accent)}
.tb.del:hover{border-color:var(--bad);color:var(--bad)}
.tun .card{background:var(--card);border:1px solid var(--line);border-radius:8px;
  padding:14px;margin-top:14px}
.tun .card h2{font-size:14px;margin:0 0 10px}
.frow{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:9px}
.frow label{font-size:12px;color:var(--muted);min-width:78px}
.fi{padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);
  color:var(--fg);font:inherit;font-size:13px}
.fi:focus{outline:2px solid var(--accent);outline-offset:1px}
#t-host{width:190px}#t-svchost{width:150px}#t-svcport{width:90px}
.cbtn{padding:8px 16px;border:0;border-radius:8px;background:var(--accent);color:#fff;
  font:inherit;font-weight:600;cursor:pointer}
.cbtn:disabled{opacity:.5;cursor:default}
.cbtn.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
#t-note{font-size:12px;color:var(--muted);margin-left:4px}
#t-note.bad{color:var(--bad)}
#t-note.good{color:#16a34a}
.warn{font-size:12px;color:var(--muted);border-left:3px solid var(--bad);
  padding:6px 10px;margin-bottom:12px}
.tokbox{border-left:3px solid #d97706}
/* Phones: the route table would need sideways dragging, so it scrolls in its
   own box; the add-route form drops to one field per line at full width. */
@media (max-width:760px){
/* table.resp (shared core) stacks each route into a card; these just tidy the
   result - the action buttons get their own full-width row underneath. */
.tun table{background:transparent;border:0;border-radius:0}
.tun table.resp tr{background:var(--card);border:1px solid var(--line);
border-radius:8px;margin-bottom:8px;padding:11px 13px}
.tun table.resp td{padding:2px 0}
.tun table.resp td.acts{display:flex;gap:8px;margin-top:9px;white-space:normal}
.tun table.resp td.acts::before{display:none}
.tun table.resp td.acts .tb{flex:1}
.frow{gap:5px}
.frow label{min-width:0;flex-basis:100%}
.fi,#t-host,#t-svchost,#t-svcport{width:100%;flex:1 1 100%}
.cbtn{width:100%}
#t-note{margin-left:0}
}
@media (pointer:coarse){
.tb{min-height:36px;padding:0 12px;font-size:13px}
.fi{font-size:16px}
.cbtn{min-height:42px}
}
"""

PAGE = """<!doctype html>
<meta charset="utf-8"><title>Routing</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
<div class="wrap">
__NAV__
<h1>Tunnel routing</h1>
<p class="warn">Every route here publishes a LAN service on the public
internet through Cloudflare. Anything without its own login is reachable by
anyone who knows the hostname - put a Cloudflare Access policy in front of it.</p>
<div class="tun">
  <div class="hdr" id="t-hdr">loading...</div>
  <div id="t-tokbox" style="display:none" class="warn tokbox">
    Routes above are read live from the connector in __CT__, which needs no
    credentials. <b>Changing</b> them does: this tunnel is remotely managed, so
    Cloudflare stores the ingress and pushes it to __CT__ - a local config.yml
    there is ignored while that remote config exists (verified on this host).
    A token needs <b>Account &middot; Cloudflare Tunnel &middot; Edit</b> and
    <b>Zone &middot; DNS &middot; Edit</b>. Store it at
    <code>/etc/media-dashboard/cf-token</code> to stop being asked.
    <div class="frow" style="margin-top:8px">
      <input id="t-token" class="fi" type="password" placeholder="Cloudflare API token"
             style="width:320px" autocomplete="off">
      <button class="cbtn ghost" id="t-load">Load routes</button>
    </div>
  </div>
  <table id="t-table" class="resp"><thead><tr class="hd">
    <th>Hostname</th><th>Origin</th><th>DNS</th><th>Reachable</th><th></th>
  </tr></thead><tbody id="t-rows"></tbody></table>

  <div class="card">
    <h2 id="t-formtitle">Add a route</h2>
    <div class="frow">
      <label for="t-host">Hostname</label>
      <input id="t-host" class="fi" placeholder="__HOSTEG__" autocomplete="off">
      <span id="t-zone" style="font-size:13px;color:var(--muted)"></span>
    </div>
    <div class="frow">
      <label for="t-scheme">Origin</label>
      <select id="t-scheme" class="fi">
        <option value="http">http://</option>
        <option value="https">https://</option>
        <option value="tcp">tcp://</option>
        <option value="ssh">ssh://</option>
        <option value="rdp">rdp://</option>
      </select>
      <input id="t-svchost" class="fi" placeholder="__ORIGINEG__" autocomplete="off">
      <span style="color:var(--muted)">:</span>
      <input id="t-svcport" class="fi" placeholder="34400" autocomplete="off">
    </div>
    <div class="frow">
      <label></label>
      <label style="min-width:0"><input type="checkbox" id="t-notls"> no TLS verify
        (needed for self-signed origins like Proxmox)</label>
    </div>
    <div class="frow">
      <label></label>
      <label style="min-width:0"><input type="checkbox" id="t-dns" checked>
        create/update the DNS record</label>
    </div>
    <div class="frow">
      <label></label>
      <button class="cbtn" id="t-save">Publish route</button>
      <button class="cbtn ghost" id="t-cancel" style="display:none">Cancel</button>
      <span id="t-note"></span>
    </div>
  </div>

  <div class="card" id="t-orphanbox" style="display:none">
    <h2>DNS pointing here with no route</h2>
    <p style="font-size:12px;color:var(--muted);margin:0 0 8px">
      These hostnames resolve to this tunnel but have no ingress rule, so they
      answer with the catch-all 404.</p>
    <div id="t-orphans"></div>
  </div>

  <div class="card">
    <h2>Connector</h2>
    <div class="frow">
      <span id="t-conn" style="font-size:13px">-</span>
    </div>
    <div class="frow">
      <button class="cbtn ghost" id="t-restart">Restart cloudflared in __CT__</button>
      <span style="font-size:12px;color:var(--muted)">Queued to the runner.
        Briefly drops every public hostname, including this dashboard.</span>
    </div>
  </div>
</div>
</div>
<script>__JS__</script>
"""

JS = """
const CT = __CT_JS__;
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;',
  '>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const $=id=>document.getElementById(id);
let ZONE='',EDITING=null,DATA=null;

function note(t,cls){const n=$('t-note');n.textContent=t||'';n.className=cls||'';}
function token(){const e=$('t-token');return e?e.value.trim():'';}

function pill(kind,text){return '<span class="pill '+kind+'">'+esc(text)+'</span>';}

/* Match a route's origin back to the service listening there, so the table
   reads as "Jellyfin" rather than a bare host:port. */
function originOf(service){
  var i=String(service||'').indexOf('://');
  if(i<0)return null;
  var rest=service.slice(i+3), j=rest.indexOf('/');
  return (DATA.origins||{})[j<0?rest:rest.slice(0,j)] || null;
}
function svcTile(o,host){
  var label=(o&&o.name)||host||'?';
  var init=label.replace(/[^A-Za-z0-9]/g,'').charAt(0).toUpperCase()||'?';
  var s='<span class="tico">'+esc(init);
  /* 'generic' is the placeholder for a service with no published logo -
     asking for it would just be a 404, so go straight to the initial. */
  if(o&&o.icon&&o.icon!=='generic')s+='<img loading="lazy" alt="" src="/api/svcicon?name='
    +encodeURIComponent(o.icon)+'" onload="this.parentNode.className=\\'tico has\\'"'
    +' onerror="this.remove()">';
  return s+'</span>';
}

function dnsPill(r){
  if(r.dns==='ok')return pill('ok','ok');
  if(r.dns==='unknown')return pill('','needs token');
  if(r.dns==='missing')return pill('bad','missing');
  if(r.dns==='unproxied')return pill('warn','not proxied');
  if(r.dns==='foreign')return pill('bad','other tunnel');
  return pill('','?');
}
function reachPill(r){
  if(r.reachable===true)return pill('ok','up');
  if(r.reachable===false)return pill('bad','no answer');
  return pill('','-');
}

function render(d){
  DATA=d; ZONE=d.zone||''; $('t-zone').textContent='.'+ZONE;
  $('t-tokbox').style.display=d.token_from_file?'none':'';
  const st=d.tunnel_status||'unknown';
  const good=st==='healthy';
  $('t-hdr').innerHTML='<span>tunnel <b>'+esc(d.tunnel_name||d.tunnel.slice(0,8))+'</b></span>'
    +'<span>zone <b>'+esc(d.zone)+'</b></span>'
    +'<span>routes <b>'+d.routes.length+'</b></span>'
    +'<span>status <span class="st '+(good?'ok':'off')+'">'+esc(st)+'</span></span>'
    +'<span>read from <b>'+(d.source==='connector'?CT+' connector':'API')+'</b>'
    +(d.config_version!=null?' (v'+esc(d.config_version)+')':'')+'</span>'
    +'<span>writes via <b>'+(d.mode==='local'?CT+' config.yml':'Cloudflare API')
    +'</b></span>'
    +'<span>token <b>'+(d.token_from_file?'stored'
      :(d.mode==='local'?'only for DNS':'needed for changes'))+'</b></span>';

  if(d.error){
    $('t-rows').innerHTML='<tr><td colspan="5">'+esc(d.error)+'</td></tr>';
  }else if(!d.routes.length){
    $('t-rows').innerHTML='<tr><td colspan="5">no routes yet</td></tr>';
  }else{
    $('t-rows').innerHTML=d.routes.map(r=>
      '<tr><td class="hostcell"><span class="hostwrap">'
      +svcTile(originOf(r.service),r.hostname)
      +'<span class="hostmeta">'
      +'<a class="host" href="https://'+esc(r.hostname)+'" target="_blank"'
      +' rel="noopener">'+esc(r.hostname)+'</a>'
      +(r.no_tls_verify?' '+pill('','no TLS verify'):'')
      +(originOf(r.service)?'<span class="svcname">'
        +esc(originOf(r.service).name)+'</span>':'')
      +'</span></span></td>'
      +'<td class="svc" data-label="Origin">'+esc(r.service)+'</td>'
      +'<td data-label="DNS">'+dnsPill(r)+'</td>'
      +'<td data-label="Reachable">'+reachPill(r)+'</td>'
      +'<td class="acts" style="white-space:nowrap">'
      +'<button class="tb" data-edit="'+esc(r.hostname)+'">Edit</button> '
      +'<button class="tb del" data-del="'+esc(r.hostname)+'">Delete</button></td></tr>'
    ).join('');
  }
  $('t-rows').querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>edit(b.dataset.edit));
  $('t-rows').querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>del(b.dataset.del));

  $('t-orphanbox').style.display=d.orphans.length?'':'none';
  $('t-orphans').innerHTML=d.orphans.map(o=>
    '<div class="frow"><span class="svc">'+esc(o.hostname)+'</span>'
    +'<button class="tb del" data-orph="'+esc(o.hostname)+'">Delete record</button></div>'
  ).join('');
  $('t-orphans').querySelectorAll('[data-orph]').forEach(b=>
    b.onclick=()=>del(b.dataset.orph,true));

  const c=d.connections||[];
  let conn='';
  if(d.ready_connections!=null){
    conn=CT+' connector reports <b>'+d.ready_connections+'</b> ready connection'
      +(d.ready_connections===1?'':'s');
    if(d.connector_id)conn+=' &middot; id '+esc(String(d.connector_id).slice(0,8));
  }else{
    conn='connector unreachable'+(d.connector_error?': '+esc(d.connector_error):'');
  }
  if(c.length)conn+=' &middot; edge: '+c.map(x=>esc(x.colo||'?')).join(', ');
  $('t-conn').innerHTML=conn;
}

async function load(){
  note('loading...');
  let d;
  try{
    const q=token()?('?token='+encodeURIComponent(token())):'';
    d=await (await fetch('/api/tunnel'+q,{cache:'no-store'})).json();
  }catch(e){note('request failed','bad');return;}
  note(d.error?d.error:'',d.error?'bad':'');
  render(d);
}

function edit(host){
  const r=(DATA.routes||[]).find(x=>x.hostname===host);
  if(!r)return;
  EDITING=host;
  $('t-formtitle').textContent='Edit '+host;
  $('t-host').value=host.endsWith('.'+ZONE)?host.slice(0,-(ZONE.length+1)):host;
  const m=/^([a-z]+):\\/\\/([^:]+):(\\d+)$/.exec(r.service||'');
  if(m){$('t-scheme').value=m[1];$('t-svchost').value=m[2];$('t-svcport').value=m[3];}
  $('t-notls').checked=!!r.no_tls_verify;
  $('t-dns').checked=true;
  $('t-save').textContent='Save changes';
  $('t-cancel').style.display='';
  window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'});
}

function resetForm(){
  EDITING=null;
  $('t-formtitle').textContent='Add a route';
  $('t-host').value='';$('t-svchost').value='';$('t-svcport').value='';
  $('t-notls').checked=false;$('t-dns').checked=true;
  $('t-save').textContent='Publish route';
  $('t-cancel').style.display='none';
}

async function save(){
  const sub=$('t-host').value.trim().replace(/\\.$/,'');
  if(!sub){note('hostname is required','bad');return;}
  const host=sub.endsWith(ZONE)?sub:sub+'.'+ZONE;
  const svc=$('t-scheme').value+'://'+$('t-svchost').value.trim()
    +':'+$('t-svcport').value.trim();
  if(!EDITING&&!confirm('Publish '+host+' to the public internet, forwarding to '
    +svc+'?'))return;
  $('t-save').disabled=true;note('applying...');
  let d;
  try{
    d=await (await fetch('/api/tunnel/route',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({hostname:host,service:svc,
        no_tls_verify:$('t-notls').checked,dns:$('t-dns').checked,
        old_hostname:EDITING,token:token()})})).json();
  }catch(e){note('request failed','bad');$('t-save').disabled=false;return;}
  $('t-save').disabled=false;
  if(d.error){note(d.error,'bad');}
  else{note('saved '+host,'good');resetForm();}
  load();
}

async function del(host,dnsOnly){
  if(!confirm((dnsOnly?'Delete the DNS record for ':'Stop publishing ')+host+'?'))return;
  note('deleting...');
  let d;
  try{
    d=await (await fetch('/api/tunnel/route/delete',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({hostname:host,dns:true,token:token()})})).json();
  }catch(e){note('request failed','bad');return;}
  note(d.error?d.error:'deleted '+host,d.error?'bad':'good');
  load();
}

async function restart(){
  if(!confirm('Restart cloudflared in '+CT+'? Every public hostname drops for a '
    +'few seconds, including this page.'))return;
  note('queueing...');
  let d;
  try{
    d=await (await fetch('/api/tunnel/restart',{method:'POST',
      headers:{'Content-Type':'application/json'},body:'{}'})).json();
  }catch(e){note('request failed','bad');return;}
  note(d.error?d.error:'restart queued as job '+d.job,d.error?'bad':'good');
}

$('t-save').onclick=save;
$('t-cancel').onclick=()=>{resetForm();note('');};
$('t-restart').onclick=restart;
if($('t-load'))$('t-load').onclick=load;
load();
"""


# -------------------------------------------------------------------- routing
def _json(h, obj, code=200):
    h.send_body(json.dumps(obj), code, "application/json")


def _body(h):
    try:
        n = int(h.headers.get("Content-Length") or 0)
    except ValueError:
        return None, "bad length"
    if n > MAX_BODY:
        return None, "too large"
    if not n:
        return {}, None
    try:
        return json.loads(h.rfile.read(n).decode("utf-8", "replace")), None
    except Exception:
        return None, "bad json"


def _token_for(request_token):
    """Stored token wins; a pasted one is used for this request only."""
    return file_token() or (request_token or "").strip() or None


def handle_get(h, path, qs):
    """Handle a routing route. Returns True when it took the request.

    The caller must already have checked that a session cookie is valid; the
    admin role is checked here, per request.
    """
    if path not in ("/tunnel", "/api/tunnel"):
        return False
    if not h.is_admin():
        if path.startswith("/api/"):
            _json(h, {"error": "forbidden"}, 403)
        else:
            h.send_body("<h1>403</h1><p>Admins only.</p>", 403)
        return True

    if path == "/tunnel":
        nav = _main_attr("nav")
        base_css = _main_attr("CSS", "")
        page = PAGE.replace("__CSS__", base_css + CSS)
        page = page.replace("__NAV__", nav("/tunnel", h.current_user(), True) if nav else "")
        page = page.replace("__JS__", JS.replace("__CT_JS__", json.dumps(ct_label())))
        # Placeholders in the copy and the form hints, so the page describes
        # this host rather than the one it was written on. The examples are
        # taken from routes that already exist where there are any.
        t = site.tunnel_info()
        hosts = t.get("hostnames") or []
        origin = next((s2["url"] for s2 in site.services_list() if s2.get("url")), "")
        page = page.replace("__CT__", ct_label())
        page = page.replace("__HOSTEG__",
                            (hosts[0].split(".")[0] if hosts else "myservice"))
        page = page.replace("__ORIGINEG__",
                            origin.split("//")[-1].split(":")[0] or site.host_ip())
        h.send_body(page)
        return True

    from urllib.parse import parse_qs
    tok = _token_for((parse_qs(qs).get("token") or [""])[0])
    _json(h, state(tok))
    return True


def handle_post(h, path):
    """Handle a routing POST. Returns True when it took the request."""
    if path not in ("/api/tunnel/route", "/api/tunnel/route/delete",
                    "/api/tunnel/restart"):
        return False
    if not h.session_ok():
        _json(h, {"error": "unauthenticated"}, 401)
        return True
    if not h.is_admin():
        _json(h, {"error": "forbidden"}, 403)
        return True

    body, err = _body(h)
    if err:
        _json(h, {"error": err}, 400)
        return True
    user = h.current_user() or "?"

    if path == "/api/tunnel/restart":
        jid, err = restart_connector(user)
        if err:
            _json(h, {"error": err}, 400)
            return True
        _json(h, {"ok": True, "job": jid})
        return True

    tok = _token_for(body.get("token"))
    local = mode() == "local"
    want_dns = body.get("dns", True) is not False
    # In local mode the ingress edit happens in the connector's container and
    # needs no token; only the DNS half still does, so a missing token degrades
    # rather than blocks.
    if not tok and not local:
        _json(h, {"error": "no API token - store one at /etc/media-dashboard/"
                           "cf-token or paste one above"}, 400)
        return True

    if path == "/api/tunnel/route":
        if local:
            res, err = apply_route_local(
                user, body.get("hostname"), body.get("service"),
                no_tls_verify=bool(body.get("no_tls_verify")),
                old_hostname=(body.get("old_hostname") or None))
            if not err:
                if want_dns and tok:
                    ok, derr = upsert_dns(tok, conf(), res["hostname"],
                                          force=bool(body.get("force")))
                    res["dns"] = "ok" if ok else "failed"
                    if not ok:
                        _json(h, {"ok": True, "result": res, "error": derr}, 400)
                        return True
                else:
                    res["dns"] = "not attempted - needs an API token" if want_dns \
                        else "skipped"
        else:
            res, err = apply_route(
                user, tok, body.get("hostname"), body.get("service"),
                no_tls_verify=bool(body.get("no_tls_verify")),
                want_dns=want_dns, force=bool(body.get("force")),
                old_hostname=(body.get("old_hostname") or None))
        if err:
            _json(h, {"error": err, "result": res}, 400)
            return True
        _json(h, {"ok": True, "result": res})
        return True

    # /api/tunnel/route/delete
    if local:
        res, err = delete_route_local(user, body.get("hostname"))
        if not err and want_dns and tok:
            ok, derr = delete_dns(tok, conf(), res["hostname"])
            res["dns"] = "deleted" if ok else "failed"
            if not ok:
                _json(h, {"ok": True, "result": res, "error": derr}, 400)
                return True
    else:
        res, err = delete_route(user, tok, body.get("hostname"), drop_dns=want_dns)
    if err:
        _json(h, {"error": err, "result": res}, 400)
        return True
    _json(h, {"ok": True, "result": res})
    return True
