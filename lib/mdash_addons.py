"""Dashboard add-ons: other web UIs, plugged into this one.

An add-on is a registered web dashboard - Grafana, Jellyfin, the Proxmox UI,
anything with a browser interface - that gets a tile on /addons and opens
inside this dashboard's chrome rather than in a bare tab. Managing them is
admin-only and lives in the app store's Dashboards tab; viewing them is open to
any signed-in user the add-on is marked visible to.

Wiring (in media-dashboard-web.py):

    import mdash_addons

    # in do_GET, after the session check:
    if mdash_addons.handle_get(self, path, qs):
        return

    # at the top of do_POST (it checks the session itself):
    if mdash_addons.handle_post(self, p):
        return

    # in nav():
    if mdash_addons.has_visible(admin):
        out += a("/addons", "Dashboards")

    # in the app store page: mdash_addons.PANEL as a tab panel.

Three things about this box shape the design.

*The iframe is loaded by the browser, not by us.* So the URL has to be one the
client can actually reach. LAN clients cannot route the internal bridge -
they reach services through the host's uplink address on a forwarded port -
and that address is DHCP and changes, so add-on URLs hold a {host} placeholder
the browser fills in from the page it is already on. Off the LAN there is no such port, so an add-on can also
carry a public hostname, and the browser picks between them.

*Plenty of dashboards refuse to be framed.* X-Frame-Options: DENY and CSP
frame-ancestors are common (on this host: Grafana, Threadfin and Gameyfin deny
it outright; RomM and qBittorrent allow same-origin only, which we are not).
There is no way to override that from our side - it is the browser enforcing
it - so each add-on is probed from the host, the answer is cached, and one that
cannot be framed gets a tile that opens a tab instead of an empty white box.

*Mixed content.* Reached over the Cloudflare tunnel this dashboard is https,
and an https page may not frame an http one. That is detected in the browser,
where the page's own scheme is known, rather than guessed here.
"""
import json
import os
import re
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.request

CONF_FILE = "/etc/media-dashboard/addons.json"
TOPO_FILE = "/var/lib/media-dashboard/topology.json"
NAT_SCRIPT = "/usr/local/bin/media-stack-nat.sh"

MAX_ADDONS = 40
MAX_BODY = 64 * 1024
PROBE_TIMEOUT = 6
PROBE_TTL = 12 * 3600           # re-probe roughly twice a day

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
ICON_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# {host} is substituted in the browser; it is the only brace form accepted.
URL_RE = re.compile(r"^https?://(\{host\}|[A-Za-z0-9._-]+)(:[0-9]{1,5})?"
                    r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]*)?$")
ROLES = ("all", "admin")
EMBEDS = ("auto", "iframe", "newtab")


def _main_attr(name, default=None):
    """Borrow nav()/audit()/CSS from the dashboard without importing it."""
    return getattr(sys.modules.get("__main__"), name, default)


def _audit(user, msg):
    fn = _main_attr("audit")
    if fn:
        try:
            fn(user, msg)
        except Exception:
            pass


# ---------------------------------------------------------------- storage

def load():
    try:
        with open(CONF_FILE) as f:
            d = json.load(f)
    except Exception:
        d = {}
    rows = [r for r in (d.get("addons") or []) if isinstance(r, dict)
            and ID_RE.match(str(r.get("id") or ""))]
    rows.sort(key=lambda r: (int(r.get("order") or 0), str(r.get("name") or "")))
    return rows


def save(rows, user, what):
    os.makedirs(os.path.dirname(CONF_FILE), exist_ok=True)
    tmp = CONF_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"addons": rows}, f, indent=2)
    shutil.move(tmp, CONF_FILE)
    _audit(user, f"ADDON {what}")


def visible_to(rows, admin):
    return [r for r in rows if r.get("enabled", True)
            and (admin or r.get("roles", "admin") == "all")]


def has_visible(admin):
    """Whether to offer the Dashboards link in the nav at all."""
    try:
        return bool(visible_to(load(), admin))
    except Exception:
        return False


# ---------------------------------------------------------------- validation

def clean(row, existing_ids=(), user="?"):
    """Normalise a submitted add-on. Returns (row, error)."""
    out = {}
    aid = str(row.get("id") or "").strip().lower()
    if not ID_RE.match(aid):
        return None, "the id must be lowercase letters, digits and dashes"
    out["id"] = aid

    name = re.sub(r"[\x00-\x1f\x7f]", "", str(row.get("name") or "")).strip()
    if not 1 <= len(name) <= 60:
        return None, "give it a name of 1-60 characters"
    out["name"] = name

    url = str(row.get("url") or "").strip()
    if not URL_RE.match(url) or len(url) > 300:
        return None, ("the URL must be http:// or https:// followed by a host "
                      "name, an address, or {host} for whatever address this "
                      "dashboard is reached on")
    out["url"] = url

    remote = str(row.get("url_remote") or "").strip()
    if remote:
        if not URL_RE.match(remote) or len(remote) > 300:
            return None, "the off-LAN URL is not a valid http(s) URL"
        if "{host}" in remote:
            return None, ("the off-LAN URL is used when {host} would be wrong, "
                          "so it has to be a real hostname")
    out["url_remote"] = remote

    icon = str(row.get("icon") or "").strip().lower()
    if icon and not ICON_RE.match(icon):
        return None, "that is not an icon name"
    out["icon"] = icon

    out["roles"] = row.get("roles") if row.get("roles") in ROLES else "admin"
    out["embed"] = row.get("embed") if row.get("embed") in EMBEDS else "auto"
    out["enabled"] = bool(row.get("enabled", True))
    note = re.sub(r"[\x00-\x1f\x7f]", "", str(row.get("note") or "")).strip()
    out["note"] = note[:200]
    try:
        out["order"] = max(0, min(999, int(row.get("order") or 0)))
    except (TypeError, ValueError):
        out["order"] = 0
    # A probe URL only exists for add-ons discovered from the topology, where
    # we know the service's internal address. It is never taken from a request.
    out["probe_url"] = str(row.get("probe_url") or "")
    if not URL_RE.match(out["probe_url"] or "http://x"):
        out["probe_url"] = ""
    out["frame"] = row.get("frame") if isinstance(row.get("frame"), dict) else {}
    return out, None


# ---------------------------------------------------------------- probing

def _probe_url_for(row):
    """The address to ask about framing.

    {host} means "whatever the browser is on", which from here would resolve to
    the host's own uplink address - and traffic originating on the host skips
    the DNAT chain entirely, so that probe would fail for reasons that say
    nothing about the add-on. Discovery therefore records the service's internal
    address separately, and that is what gets probed.
    """
    if row.get("probe_url"):
        return row["probe_url"]
    for u in (row.get("url") or "", row.get("url_remote") or ""):
        if u and "{host}" not in u:
            return u
    return ""


def probe(row):
    """Ask a dashboard whether it will let itself be framed."""
    url = _probe_url_for(row)
    if not url:
        return {"state": "unknown", "why": "nothing to probe - this add-on is "
                                           "only addressable from your browser",
                "at": int(time.time())}
    ctx = ssl.create_default_context()
    # The Proxmox UI and anything else on this box uses a self-signed
    # certificate. We are reading response headers, not trusting content.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "media-dashboard/addons"})
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT, context=ctx) as r:
            hdrs, code = r.headers, r.status
    except urllib.error.HTTPError as e:
        hdrs, code = e.headers, e.code           # 401/403 still carry the headers
    except Exception as e:
        return {"state": "unreachable", "why": str(e)[:160], "at": int(time.time())}

    xfo = (hdrs.get("X-Frame-Options") or "").strip().lower()
    csp = " ".join(hdrs.get_all("Content-Security-Policy") or []).lower()
    anc = re.search(r"frame-ancestors([^;]*)", csp)
    ancestors = (anc.group(1).strip() if anc else "")

    if xfo.startswith("deny"):
        return {"state": "no", "why": "it answers X-Frame-Options: DENY",
                "code": code, "at": int(time.time())}
    if xfo.startswith("sameorigin"):
        return {"state": "no", "why": "it answers X-Frame-Options: SAMEORIGIN, "
                                      "and this dashboard is a different origin",
                "code": code, "at": int(time.time())}
    if ancestors:
        allowed = ancestors.split()
        if allowed and allowed[0] in ("'none'", "'self'"):
            return {"state": "no",
                    "why": f"its Content-Security-Policy sets frame-ancestors "
                           f"{allowed[0]}", "code": code, "at": int(time.time())}
        return {"state": "maybe",
                "why": f"it allows framing only by {ancestors[:80]}",
                "code": code, "at": int(time.time())}
    return {"state": "yes", "why": "it sends no framing restrictions",
            "code": code, "at": int(time.time())}


# What can be done about a refusal, for the dashboards we ship. Shown next to
# the probe result so the answer is not just "no".
FRAME_FIXES = {
    "grafana": "Grafana can allow it: set allow_embedding = true in the "
               "[security] section of /etc/grafana/grafana.ini in its container "
               "and restart grafana-server.",
    "qbittorrent": "qBittorrent hard-codes frame-ancestors 'self' in its Web UI "
                   "headers; there is no setting for this, so it opens in a tab.",
    "gameyfin": "Gameyfin sends X-Frame-Options: DENY with no setting to relax "
                "it, so it opens in a tab.",
    "threadfin": "Threadfin sends X-Frame-Options: DENY with no setting to relax "
                 "it, so it opens in a tab.",
}


def refresh_probes(rows, force=False):
    """Re-probe anything whose answer is missing or stale. Returns True if any
    row changed, so the caller knows whether to write the file back."""
    now, changed = time.time(), False
    for r in rows:
        f = r.get("frame") or {}
        if force or not f.get("at") or now - f["at"] > PROBE_TTL:
            r["frame"] = probe(r)
            changed = True
    return changed


# ---------------------------------------------------------------- discovery

def nat_forwards():
    """internal ip:port -> host port, read from the one script that owns NAT.

    Parsed rather than read back from iptables because the web process runs
    under ProtectSystem=strict and cannot take the netfilter locks, and because
    this file is the thing that would be edited if a forward changed.
    """
    out = {}
    try:
        with open(NAT_SCRIPT) as f:
            for line in f:
                m = re.match(r"^\s*fwd\s+([0-9]{1,5})\s+([0-9.]+)\s+([0-9]{1,5})",
                             line)
                if m:
                    out[f"{m.group(2)}:{m.group(3)}"] = m.group(1)
    except OSError:
        pass
    return out


def _topology_services():
    try:
        with open(TOPO_FILE) as f:
            return [n for n in json.load(f).get("nodes", [])
                    if n.get("kind") == "service"]
    except Exception:
        return []


def discover():
    """Add-on candidates built from what the collector already found.

    Every service the topology knows about that answers HTTP becomes a
    suggestion, with its LAN URL taken from the NAT table and its off-LAN URL
    from the public hostname the tunnel serves it on.
    """
    fwd = nat_forwards()
    found = []
    for n in _topology_services():
        link = n.get("link") or ""
        m = re.match(r"^https?://([0-9.]+):([0-9]+)$", link)
        if not m or n.get("discovered"):
            continue                       # port-scan finds, not real dashboards
        meta = {k: v for k, v in (n.get("meta") or [])}
        if meta.get("HTTP") in ("000", None):
            continue                       # never answered HTTP
        internal = f"{m.group(1)}:{m.group(2)}"
        host_port = fwd.get(internal)
        public = (meta.get("Public") or "").strip()
        if public in ("-", "internal only", "tunnel", ""):
            public = ""
        if not host_port and not public:
            continue                       # nothing a browser could reach
        label = n.get("label") or ""
        found.append({
            "id": re.sub(r"[^a-z0-9-]+", "-", label.lower()).strip("-")[:40],
            "name": label,
            "url": f"http://{{host}}:{host_port}" if host_port
                   else f"https://{public}",
            "url_remote": f"https://{public}" if public and host_port else "",
            "icon": n.get("icon") if n.get("icon") != "generic" else "",
            "probe_url": link,
            "roles": "admin",
            "embed": "auto",
            "enabled": True,
            "note": "",
            "where": ("LAN: port %s on this host" % host_port) if host_port
                     else "through the Cloudflare tunnel only",
        })

    # The hypervisor's own UI is not a "service" in the collector's sense, but
    # it is the dashboard people most want one click away.
    found.append({
        "id": "proxmox", "name": "Proxmox VE", "url": "https://{host}:8006",
        "url_remote": "", "icon": "proxmox", "probe_url": "https://127.0.0.1:8006",
        "roles": "admin", "embed": "auto", "enabled": True, "note": "",
        "where": "LAN: port 8006 on this host",
    })
    seen, uniq = set(), []
    for r in found:
        if r["id"] and r["id"] not in seen:
            seen.add(r["id"])
            uniq.append(r)
    return uniq


# ---------------------------------------------------------------- pages

CSS = """
.agrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.acard{background:var(--card);border:1px solid var(--line);border-radius:11px;
padding:14px;display:flex;gap:12px;align-items:flex-start;text-decoration:none;
color:var(--fg);transition:border-color .12s}
.acard:hover{border-color:var(--accent)}
.acard .ai{width:40px;height:40px;flex:0 0 40px;border-radius:9px;background:var(--bg);
border:1px solid var(--line);position:relative;display:flex;align-items:center;
justify-content:center;font-weight:700;color:var(--muted);overflow:hidden}
.acard .ai img{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;padding:7px}
.acard .an{font-size:14px;font-weight:600;margin-bottom:3px}
.acard .aw{font-size:12px;color:var(--muted);word-break:break-all}
.acard .at{font-size:10px;padding:1px 7px;border-radius:20px;border:1px solid var(--line);
color:var(--muted);display:inline-block;margin-top:6px}
.aframe{position:fixed;inset:0;display:flex;flex-direction:column;background:var(--bg)}
.aframe .abar{display:flex;gap:8px;align-items:center;padding:7px 12px;
border-bottom:1px solid var(--line);background:var(--card);flex-wrap:wrap}
.aframe .abar a,.aframe .abar button{font-size:12px;padding:5px 11px;border-radius:7px;
border:1px solid var(--line);background:var(--bg);color:var(--fg);text-decoration:none;
cursor:pointer;white-space:nowrap}
.aframe .abar a.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.aframe .abar .sp{flex:1}
.aframe iframe{flex:1;width:100%;border:0;background:var(--card)}
.aframe.full .abar{display:none}
.anote{background:var(--card);border:1px solid var(--line);border-radius:11px;
padding:22px;margin:40px auto;max-width:560px;text-align:center}
.anote h2{margin:0 0 8px;font-size:16px}
.anote p{color:var(--muted);font-size:13px;line-height:1.6;margin:0 0 16px}
.anote a.go{display:inline-block;background:var(--accent);color:#fff;padding:9px 18px;
border-radius:8px;text-decoration:none;font-size:13px;font-weight:600}
"""

PAGE = """<!doctype html><meta charset="utf-8"><title>Dashboards</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
__NAV__
<h1>Dashboards</h1>
<div class="sub" id="sub">Loading...</div>
<div class="agrid" id="grid"></div>
<script>
var ONLAN=true;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function hostOf(u){return String(u).replace(/^https?:\\/\\//,'').split('/')[0];}

// Which of an add-on's URLs this browser should use, or '' when none of them
// would work from here. {host} is the address this dashboard was reached on,
// which is only a useful address for the add-on when the reader is on the LAN -
// over the tunnel that hostname serves this dashboard and nothing else.
function pick(a){
  var tpl=a.url||'', rem=a.url_remote||'';
  if(tpl.indexOf('{host}')>=0&&!ONLAN)return rem;
  var lan=tpl.replace('{host}',location.hostname);
  if(!rem)return lan;
  if(location.hostname===hostOf(rem))return rem;
  // An https page cannot frame or even silently open an http one.
  if(location.protocol==='https:'&&lan.indexOf('http://')===0)return rem;
  return lan;
}
function framed(a){
  var u=pick(a);
  if(!u)return false;
  if(a.embed==='newtab')return false;
  if(a.embed==='iframe')return true;
  if((a.frame||{}).state==='no')return false;
  if(location.protocol==='https:'&&u.indexOf('http://')===0)return false;
  return true;
}
function tile(a){
  var u=pick(a), inline=framed(a);
  var body='<div class="ai">'+esc((a.name||'?').charAt(0).toUpperCase())
    +(a.icon?'<img alt="" src="/api/svcicon?name='+encodeURIComponent(a.icon)
      +'" onerror="this.remove()">':'')
    +'</div><div style="min-width:0"><div class="an">'+esc(a.name)+'</div>';
  if(!u){
    // Only addressable as {host}:port, and we are not on the LAN.
    return '<div class="acard" style="opacity:.6">'+body
      +'<div class="aw">only reachable on the local network</div>'
      +'<span class="at">not available from here</span></div></div>';
  }
  var href=inline?('/addons/view?id='+encodeURIComponent(a.id)):u;
  var s='<a class="acard" href="'+esc(href)+'"'+(inline?'':' target="_blank" '
    +'rel="noopener"')+'>'+body
    +'<div class="aw">'+esc(hostOf(u))+'</div>';
  if(!inline)s+='<span class="at">opens in a new tab</span>';
  if(a.note)s+='<div class="aw" style="margin-top:5px">'+esc(a.note)+'</div>';
  return s+'</div></a>';
}
fetch('/api/addons',{cache:'no-store'}).then(function(r){return r.json();})
.then(function(d){
  var a=d.addons||[];
  ONLAN=d.lan!==false;
  document.getElementById('sub').textContent = a.length
    ? a.length+' dashboard'+(a.length>1?'s':'')+' plugged in'
    : 'Nothing plugged in yet.';
  document.getElementById('grid').innerHTML = a.length ? a.map(tile).join('')
    : '<div class="acard" style="grid-column:1/-1;display:block">'
      +'No dashboards have been added yet.'+(d.admin
        ?' Add them from the <a href="/appstore">app store</a>, under Dashboards.'
        :' An admin can add them from the app store.')+'</div>';
});
</script>
"""

VIEW = """<!doctype html><meta charset="utf-8"><title>__TITLE__</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__
body{margin:0;padding:0;max-width:none}
</style>
<div class="aframe" id="wrap">
  <div class="abar" id="bar"></div>
  <iframe id="fr" referrerpolicy="no-referrer"
          allow="fullscreen; clipboard-write; encrypted-media; picture-in-picture"></iframe>
</div>
<script>
var ID=__ID__, LIST=[], ONLAN=true;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function hostOf(u){return String(u).replace(/^https?:\\/\\//,'').split('/')[0];}
function pick(a){
  var tpl=a.url||'', rem=a.url_remote||'';
  if(tpl.indexOf('{host}')>=0&&!ONLAN)return rem;
  var lan=tpl.replace('{host}',location.hostname);
  if(!rem)return lan;
  if(location.hostname===hostOf(rem))return rem;
  if(location.protocol==='https:'&&lan.indexOf('http://')===0)return rem;
  return lan;
}
function bar(cur){
  var s='<a href="/">&larr; Dashboard</a>';
  LIST.forEach(function(a){
    s+='<a href="/addons/view?id='+encodeURIComponent(a.id)+'"'
      +(a.id===cur.id?' class="on"':'')+'>'+esc(a.name)+'</a>';
  });
  s+='<span class="sp"></span>'
    +'<button onclick="document.getElementById(\\'wrap\\').className='
    +'\\'aframe full\\'">Full screen</button>';
  var u=pick(cur);
  if(u)s+='<a href="'+esc(u)+'" target="_blank" rel="noopener">Open directly</a>';
  document.getElementById('bar').innerHTML=s;
}
function blocked(cur,why){
  var u=pick(cur);
  document.getElementById('wrap').innerHTML=
    '<div class="anote"><h2>'+esc(cur.name)+' will not open inside this page</h2>'
    +'<p>'+esc(why)+'</p>'
    +(u?'<a class="go" href="'+esc(u)+'" target="_blank" rel="noopener">Open '
       +esc(cur.name)+' in a new tab</a>':'')
    +'<p style="margin-top:16px"><a href="/addons">Back to dashboards</a></p></div>';
}
fetch('/api/addons',{cache:'no-store'}).then(function(r){return r.json();})
.then(function(d){
  LIST=d.addons||[];
  ONLAN=d.lan!==false;
  var cur=LIST.filter(function(a){return a.id===ID;})[0];
  if(!cur){location.href='/addons';return;}
  document.title=cur.name;
  bar(cur);
  var u=pick(cur);
  if(!u){
    return blocked(cur,'This add-on is only addressable on the local network - '
      +'it points at a port on the Proxmox host, and you are not reading this '
      +'over the LAN. Give it a public address as well if you want it from here.');
  }
  if(location.protocol==='https:'&&u.indexOf('http://')===0){
    return blocked(cur,'You are reading this dashboard over https, and a secure '
      +'page is not allowed to embed an insecure one. Give this add-on an '
      +'https address, or open it directly.');
  }
  if(cur.embed!=='iframe'&&(cur.frame||{}).state==='no'){
    return blocked(cur,(cur.frame.why||'it refuses to be framed')
      +(cur.fix?' '+cur.fix:''));
  }
  document.getElementById('fr').src=u;
});
// Escape leaves full screen, since the bar with the way out is hidden.
document.addEventListener('keydown',function(e){
  if(e.key==='Escape')document.getElementById('wrap').className='aframe';
});
</script>
"""

# ---- the app store's Dashboards tab. Self-contained: markup, styles and an
# IIFE that publishes only window.ADDONS, so it cannot collide with the app
# store's own globals.
PANEL = """
<style>
.adm table.resp td .btn{margin-right:6px}
.adm .fld{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:10px;margin:12px 0}
.adm .fld label{font-size:12px;color:var(--muted);display:block;margin-bottom:3px}
.adm .fld input,.adm .fld select{width:100%;padding:7px 10px;border-radius:7px;
border:1px solid var(--line);background:var(--bg);color:var(--fg);font-size:13px}
.adm .sug{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));
gap:10px;margin-top:10px}
.adm .sug .app{cursor:default}
.adm .fr{font-size:11px;padding:1px 8px;border-radius:20px;border:1px solid var(--line)}
.adm .fr.yes{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,transparent)}
.adm .fr.no{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,transparent)}
.adm .fr.unreachable{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
</style>
<div class="adm">
  <div class="warn-box"><b>Add-ons embed another site inside this page.</b><br>
  Whatever you point one at is loaded by your browser with its own login and its
  own cookies - this dashboard does not proxy it and cannot log you into it.
  Dashboards that send <code>X-Frame-Options</code> or a
  <code>frame-ancestors</code> policy cannot be embedded by anyone; those are
  detected and get a tile that opens a tab instead.</div>

  <div class="tablewrap" id="ad-list"></div>

  <h3 style="font-size:13px;margin:20px 0 4px">Found on this host</h3>
  <div class="sub" style="margin:0">Built from the topology the collector
  already writes, so the address and icon are filled in for you.</div>
  <div class="sug" id="ad-sug"></div>

  <h3 style="font-size:13px;margin:20px 0 8px">Add any other web dashboard</h3>
  <div class="fld">
    <div><label>Name</label><input id="ad-name" placeholder="Home Assistant"></div>
    <div style="grid-column:span 2"><label>URL</label>
      <input id="ad-url" placeholder="http://{host}:8123"></div>
    <div><label>Icon</label><input id="ad-icon" placeholder="home-assistant"></div>
    <div style="grid-column:span 2"><label>URL when off the LAN (optional)</label>
      <input id="ad-remote" placeholder="https://ha.example.com"></div>
    <div><label>Visible to</label><select id="ad-roles">
      <option value="admin">Admins only</option>
      <option value="all">Everyone signed in</option></select></div>
    <div><label>How to open</label><select id="ad-embed">
      <option value="auto">Embed if allowed</option>
      <option value="iframe">Always embed</option>
      <option value="newtab">Always a new tab</option></select></div>
    <div style="align-self:end"><button class="btn go" style="width:100%"
      onclick="ADDONS.add()">Add dashboard</button></div>
  </div>
  <div class="sub" style="margin:0">Use <code>{host}</code> where the address of
  this dashboard should go - it is filled in by the browser, so it keeps working
  when the uplink gets a different DHCP address.</div>
  <div id="ad-msg"></div>
</div>
<script>
(function(){
var ST={addons:[],suggest:[]};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function msg(h){document.getElementById('ad-msg').innerHTML=h;}
function jstr(v){return esc(JSON.stringify(v));}

function frameCell(a){
  var f=a.frame||{}, st=f.state||'unknown';
  var label={yes:'embeds',no:'blocked',maybe:'partial',
             unreachable:'unreachable',unknown:'not probed'}[st]||st;
  return '<span class="fr '+esc(st)+'" title="'+esc(f.why||'')+'">'
    +esc(label)+'</span>';
}

function list(){
  var el=document.getElementById('ad-list');
  if(!ST.addons.length){
    el.innerHTML='<div class="empty">No dashboards plugged in yet.</div>';
    return;
  }
  var s='<table class="resp"><tr class="hd"><th>Dashboard</th><th>Address</th>'
    +'<th>Visible to</th><th>Framing</th><th>State</th><th></th></tr>';
  ST.addons.forEach(function(a){
    s+='<tr><td><b>'+esc(a.name)+'</b></td>'
      +'<td class="ver" data-label="Address">'+esc(a.url)
      +(a.url_remote?'<br><span class="who">off-LAN: '+esc(a.url_remote)
        +'</span>':'')+'</td>'
      +'<td data-label="Visible to">'+(a.roles==='all'?'everyone':'admins')+'</td>'
      +'<td data-label="Framing">'+frameCell(a)
      +(a.fix?'<br><span class="who">'+esc(a.fix)+'</span>':'')+'</td>'
      +'<td data-label="State">'+(a.enabled
        ?'<span class="st done">on</span>':'<span class="st queued">off</span>')+'</td>'
      +'<td class="srcacts">'
      +'<button class="btn" onclick="ADDONS.op(\\'toggle\\','+jstr(a.id)+')">'
      +(a.enabled?'Disable':'Enable')+'</button>'
      +'<button class="btn" onclick="ADDONS.op(\\'probe\\','+jstr(a.id)+')">Re-probe</button>'
      +'<button class="btn" onclick="ADDONS.op(\\'remove\\','+jstr(a.id)+')">Remove</button>'
      +'</td></tr>';
  });
  document.getElementById('ad-list').innerHTML=s+'</table>';
}

function suggestions(){
  var have={};
  ST.addons.forEach(function(a){have[a.id]=1;});
  var out=ST.suggest.filter(function(s){return !have[s.id];});
  document.getElementById('ad-sug').innerHTML = out.length ? out.map(function(s){
    return '<div class="app"><div class="ico">'+esc(s.name.charAt(0))
      +(s.icon?'<img alt="" src="/api/svcicon?name='+encodeURIComponent(s.icon)
        +'" onload="this.parentNode.className=\\'ico has\\'" onerror="this.remove()">':'')
      +'</div><div class="txt"><h3>'+esc(s.name)+'</h3>'
      +'<div class="res">'+esc(s.url)+'</div>'
      +'<div class="bl">'+esc(s.where||'')+'</div>'
      +'<div style="margin-top:8px"><button class="btn go" '
      +'onclick="ADDONS.plug('+jstr(s.id)+')">Plug in</button></div></div></div>';
  }).join('') : '<div class="empty">Everything the collector found is already '
    +'plugged in.</div>';
}

function post(body,ok){
  msg('<div class="more">Working...</div>');
  return fetch('/api/addons',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(function(r){return r.json();}).then(function(d){
      if(d.error){msg('<div class="warn-box"><b>Refused.</b><br>'+esc(d.error)
        +'</div>');return false;}
      msg('<div class="more">'+esc(ok)+'</div>');
      ST.addons=d.addons||[];ST.suggest=d.suggest||[];list();suggestions();
      return true;
    }).catch(function(e){msg('<div class="warn-box">Request failed: '+esc(e)
      +'</div>');return false;});
}

window.ADDONS={
  show:function(){
    fetch('/api/addons/catalog',{cache:'no-store'})
      .then(function(r){return r.json();}).then(function(d){
        ST.addons=d.addons||[];ST.suggest=d.suggest||[];list();suggestions();});
  },
  plug:function(id){
    var s=ST.suggest.filter(function(x){return x.id===id;})[0];
    if(s)post({action:'add',addon:s},'Plugged in. It is on the Dashboards page now.');
  },
  op:function(act,id){
    if(act==='remove'&&!confirm('Remove this dashboard from the UI? '
      +'The service itself is not touched.'))return;
    post({action:act,id:id},act==='remove'?'Removed.':'Updated.');
  },
  add:function(){
    var name=document.getElementById('ad-name').value.trim();
    var url=document.getElementById('ad-url').value.trim();
    if(!name||!url){msg('<div class="warn-box">A name and a URL, at least.</div>');
      return;}
    post({action:'add',addon:{
      id:name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,''),
      name:name,url:url,url_remote:document.getElementById('ad-remote').value.trim(),
      icon:document.getElementById('ad-icon').value.trim().toLowerCase(),
      roles:document.getElementById('ad-roles').value,
      embed:document.getElementById('ad-embed').value}},'Added.').then(function(ok){
        if(ok)['ad-name','ad-url','ad-remote','ad-icon'].forEach(function(i){
          document.getElementById(i).value='';});
      });
  }
};
})();
</script>
"""


# ---------------------------------------------------------------- routing

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


_PRIVATE_RE = re.compile(r"^(10\.|127\.|192\.168\.|169\.254\.|"
                         r"172\.(1[6-9]|2[0-9]|3[01])\.)")


def on_lan(h):
    """Whether this request came in over the local network.

    It matters because {host} means "the address you are reading this on", and
    that is only a useful address for an add-on when the reader is on the LAN.
    Over the Cloudflare tunnel the browser's idea of this host is a public
    hostname that serves exactly one origin, so {host}:8006 would point at
    nothing. Judged from the Host header rather than the client address,
    because that is what the browser would actually substitute.
    """
    host = (h.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
    if not host:
        return False
    if host == "localhost" or _PRIVATE_RE.match(host):
        return True
    if re.match(r"^[0-9.]+$", host):
        return False                       # a public address is not our LAN
    return "." not in host or host.endswith(".local")


def _decorate(rows):
    """Attach the known fix for a refusal, for the UI to show."""
    for r in rows:
        if (r.get("frame") or {}).get("state") == "no":
            key = re.sub(r"[^a-z0-9]+", "", (r.get("icon") or r.get("name") or "")
                         .lower())
            r["fix"] = FRAME_FIXES.get(key, "")
        else:
            r["fix"] = ""
    return rows


def handle_get(h, path, qs):
    """Handle an add-on route. Returns True when it took the request.

    The caller has already checked the session; the admin role is checked here
    per request, because viewing is open to everyone and managing is not.
    """
    if path not in ("/addons", "/addons/view", "/api/addons",
                    "/api/addons/catalog"):
        return False
    admin = h.is_admin()

    if path == "/api/addons/catalog":
        if not admin:
            _json(h, {"error": "forbidden"}, 403)
            return True
        rows = load()
        if refresh_probes(rows):
            save(rows, h.current_user() or "?", "probed")
        _json(h, {"addons": _decorate(rows), "suggest": discover()})
        return True

    if path == "/api/addons":
        _json(h, {"addons": _decorate(visible_to(load(), admin)),
                  "admin": admin, "lan": on_lan(h)})
        return True

    nav = _main_attr("nav")
    css = _main_attr("CSS", "") + CSS

    if path == "/addons":
        page = PAGE.replace("__CSS__", css)
        page = page.replace("__NAV__",
                            nav("/addons", h.current_user(), admin) if nav else "")
        h.send_body(page)
        return True

    # /addons/view - the embedded viewer. The id is only ever handed back to
    # the page as JSON, and the page matches it against the list it fetched, so
    # an unknown id lands back on /addons rather than in the markup.
    from urllib.parse import parse_qs
    aid = (parse_qs(qs).get("id") or [""])[0]
    if not ID_RE.match(aid):
        aid = ""
    page = VIEW.replace("__CSS__", css).replace("__ID__", json.dumps(aid))
    page = page.replace("__TITLE__", "Dashboard")
    h.send_body(page)
    return True


def handle_post(h, path):
    """Handle an add-on POST. Returns True when it took the request."""
    if path != "/api/addons":
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
    action = str(body.get("action") or "")
    rows = load()

    if action == "add":
        row, err = clean(body.get("addon") or {}, user=user)
        if err:
            _json(h, {"error": err}, 400)
            return True
        if len(rows) >= MAX_ADDONS:
            _json(h, {"error": f"that is {MAX_ADDONS} dashboards already"}, 400)
            return True
        if any(r["id"] == row["id"] for r in rows):
            _json(h, {"error": f"a dashboard called {row['id']} is already "
                               f"plugged in"}, 400)
            return True
        row["order"] = len(rows)
        row["frame"] = probe(row)
        rows.append(row)
        save(rows, user, f"add {row['id']} -> {row['url']}")
    elif action in ("toggle", "remove", "probe"):
        aid = str(body.get("id") or "")
        row = next((r for r in rows if r.get("id") == aid), None)
        if not row:
            _json(h, {"error": "no such dashboard"}, 404)
            return True
        if action == "remove":
            rows = [r for r in rows if r is not row]
        elif action == "toggle":
            row["enabled"] = not row.get("enabled", True)
        else:
            row["frame"] = probe(row)
        save(rows, user, f"{action} {aid}")
    else:
        _json(h, {"error": "unknown action"}, 400)
        return True

    _json(h, {"ok": True, "addons": _decorate(rows), "suggest": discover()})
    return True
