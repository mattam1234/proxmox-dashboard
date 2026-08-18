#!/usr/bin/env python3
"""The Fleet page: every Proxmox host this dashboard federates, on one screen.

Wired into the web service with the usual three lines - handle_get,
handle_post, and a nav entry. The polling, caching and peer registry all live
in mdash_fleet; this file is the view and the admin controls.

The page is built around one claim: if you run several hosts, the thing you
actually want is not ten dashboards but the union of what is wrong on any of
them. So the roll-up comes first - unreachable hosts, then issues, then
available updates, each labelled with which host it came from - and the
per-host cards are underneath for when you want the detail.

Viewing is open to any signed-in user, the same as the status page. Managing
peers is admin-only, because a peer URL is somewhere this host will send a
credential on a timer.
"""

import json
import sys

sys.path.insert(0, "/usr/local/lib/mdash")
import mdash_fleet as fleet                            # noqa: E402


def _main_attr(name, default=None):
    """Borrow nav()/audit() from the dashboard without importing it."""
    return getattr(sys.modules.get("__main__"), name, default)


def _audit(user, msg):
    fn = _main_attr("audit")
    if fn:
        try:
            fn(user, msg)
        except Exception:
            pass


def _json(h, obj, code=200):
    h.send_body(json.dumps(obj), code, "application/json")


def _body(h):
    n = int(h.headers.get("Content-Length") or 0)
    if n <= 0 or n > 64 * 1024:
        return {}
    try:
        return json.loads(h.rfile.read(n).decode("utf-8", "replace"))
    except Exception:
        return {}


CSS = """
.fl .roll{display:grid;gap:12px;margin-bottom:18px}
.fl .kpis{display:flex;gap:10px;flex-wrap:wrap}
.fl .kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;
  padding:11px 15px;min-width:104px;flex:1 1 104px}
.fl .kpi b{display:block;font-size:21px;line-height:1.15;font-weight:650}
.fl .kpi span{font-size:11px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.05em}
.fl .kpi.bad b{color:var(--bad)}
.fl .kpi.warn b{color:#d97706}
.fl .alerts{background:var(--card);border:1px solid var(--line);border-radius:10px;
  overflow:hidden}
.fl .alerts h2{margin:0;padding:10px 14px;font-size:12px;text-transform:uppercase;
  letter-spacing:.06em;color:var(--muted);border-bottom:1px solid var(--line)}
.fl .alerts .row{display:flex;gap:10px;align-items:baseline;padding:8px 14px;
  border-bottom:1px solid var(--line);font-size:13px}
.fl .alerts .row:last-child{border-bottom:0}
.fl .who{flex:0 0 auto;font-size:11px;font-weight:650;color:var(--muted);
  background:var(--bg);border:1px solid var(--line);border-radius:999px;
  padding:1px 8px}
.fl .alerts .row.dead{color:var(--bad)}
.fl .alerts a{color:var(--accent);text-decoration:none}
.fl .alerts a:hover{text-decoration:underline}

.fl .hosts{display:grid;gap:14px;
  grid-template-columns:repeat(auto-fill,minmax(340px,1fr))}
.fl .host{background:var(--card);border:1px solid var(--line);border-radius:11px;
  padding:14px;display:flex;flex-direction:column;gap:10px}
.fl .host.off{opacity:.62}
.fl .host.dead{border-color:color-mix(in srgb,var(--bad) 45%,var(--line))}
.fl .hhdr{display:flex;align-items:center;gap:9px}
.fl .hhdr h3{margin:0;font-size:15px;font-weight:650;flex:1;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fl .dot{width:9px;height:9px;border-radius:50%;flex:0 0 9px;background:#16a34a}
.fl .dot.stale{background:#d97706}
.fl .dot.dead{background:var(--bad)}
.fl .sub{font-size:12px;color:var(--muted)}
.fl .bars{display:grid;gap:6px}
.fl .bar{display:grid;grid-template-columns:46px minmax(0,1fr) auto;gap:8px;
  align-items:center;font-size:11px;color:var(--muted)}
.fl .track{height:6px;border-radius:999px;background:var(--bg);
  border:1px solid var(--line);overflow:hidden}
.fl .fill{height:100%;background:var(--accent)}
.fl .fill.warn{background:#d97706}
.fl .fill.bad{background:var(--bad)}
.fl .chips{display:flex;flex-wrap:wrap;gap:5px}
.fl .chip{display:inline-flex;align-items:center;gap:5px;font-size:11px;
  border:1px solid var(--line);border-radius:999px;padding:2px 8px;
  color:var(--muted);background:var(--bg)}
.fl .chip.down{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
.fl .chip img{width:13px;height:13px;object-fit:contain}
.fl .more{font-size:11px;color:var(--muted)}
.fl .hfoot{display:flex;gap:8px;align-items:center;margin-top:auto;
  padding-top:9px;border-top:1px solid var(--line);font-size:11px;color:var(--muted)}
.fl .hfoot a{color:var(--accent);text-decoration:none;margin-left:auto}
.fl .hfoot a:hover{text-decoration:underline}
.fl .err{color:var(--bad);font-size:12px}

.fl .peers{margin-top:22px}
.fl .peers table{width:100%;border-collapse:collapse;background:var(--card);
  border:1px solid var(--line);border-radius:9px;overflow:hidden}
.fl .peers th,.fl .peers td{text-align:left;padding:9px 11px;
  border-bottom:1px solid var(--line);font-size:13px}
.fl .peers th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted)}
.fl .peers tr:last-child td{border-bottom:0}
.fl .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.fl .card{background:var(--card);border:1px solid var(--line);border-radius:9px;
  padding:14px;margin-top:14px}
.fl .card h2{font-size:14px;margin:0 0 10px}
.fl .frow{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:9px}
.fl .frow label{font-size:12px;color:var(--muted);min-width:74px}
.fl .fi{padding:8px 10px;border:1px solid var(--line);border-radius:8px;
  background:var(--bg);color:var(--fg);font:inherit;font-size:13px}
.fl .fi:focus{outline:2px solid var(--accent);outline-offset:1px}
.fl .btn{padding:8px 15px;border:0;border-radius:8px;background:var(--accent);
  color:#fff;font:inherit;font-weight:600;cursor:pointer}
.fl .btn.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
.fl .btn:disabled{opacity:.5;cursor:default}
.fl .tb{padding:5px 10px;border:1px solid var(--line);border-radius:7px;
  background:var(--bg);color:var(--fg);font:inherit;font-size:12px;cursor:pointer}
.fl .tb:hover{border-color:var(--accent)}
.fl .tb.del:hover{border-color:var(--bad);color:var(--bad)}
.fl .note{font-size:12px;color:var(--muted)}
.fl .note.bad{color:var(--bad)}
.fl .note.good{color:#16a34a}
.fl .tok{word-break:break-all;background:var(--bg);border:1px solid var(--line);
  border-radius:7px;padding:8px 10px;font-family:ui-monospace,Menlo,monospace;
  font-size:12px;margin-top:6px}
.fl .empty{color:var(--muted);font-size:13px;padding:26px;text-align:center;
  background:var(--card);border:1px solid var(--line);border-radius:11px}

@media (max-width:760px){
.fl .hosts{grid-template-columns:1fr}
.fl .kpi{min-width:84px;flex:1 1 84px;padding:9px 11px}
.fl .kpi b{font-size:18px}
.fl .frow label{flex-basis:100%;min-width:0}
.fl .fi{width:100%;flex:1 1 100%}
.fl .btn{width:100%}
.fl .peers table{background:transparent;border:0}
.fl .peers table.resp tr{display:block;background:var(--card);
  border:1px solid var(--line);border-radius:9px;margin-bottom:8px;padding:11px 13px}
.fl .peers table.resp td{display:block;padding:2px 0;border:0}
.fl .peers table.resp thead{display:none}
}
@media (pointer:coarse){
.fl .tb{min-height:36px}
.fl .fi{font-size:16px}
.fl .btn{min-height:42px}
}
"""

PAGE = """<!doctype html>
<meta charset="utf-8"><title>Fleet</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
<div class="wrap">
__NAV__
<h1>Fleet</h1>
<div class="fl">
  <div class="roll" id="f-roll"></div>
  <div class="hosts" id="f-hosts"></div>
  <div class="peers" id="f-peers"></div>
</div>
<script>__JS__</script>
"""

JS = """
const ADMIN = __ADMIN__;
let DATA = null;

function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;',
  '<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function ago(s){
  if(s==null)return 'never';
  if(s<90)return Math.round(s)+'s ago';
  if(s<5400)return Math.round(s/60)+'m ago';
  if(s<172800)return Math.round(s/3600)+'h ago';
  return Math.round(s/86400)+'d ago';
}
function lvl(p){return p>=90?'bad':p>=75?'warn':'';}

function bar(label,pct,text){
  if(pct==null)return '';
  return '<div class="bar"><span>'+esc(label)+'</span>'
    +'<span class="track"><span class="fill '+lvl(pct)+'" style="width:'
    +Math.max(0,Math.min(100,pct))+'%"></span></span>'
    +'<span>'+esc(text||(pct+'%'))+'</span></div>';
}

/* Roll-up first: the point of a fleet page is the union of what is wrong. */
function renderRoll(r){
  let s='<div class="kpis">'
    +'<div class="kpi"><b>'+r.hosts+'</b><span>hosts</span></div>'
    +'<div class="kpi"><b>'+r.guests_running+'/'+r.guests+'</b><span>guests up</span></div>'
    +'<div class="kpi"><b>'+r.services_up+'/'+r.services+'</b><span>services up</span></div>'
    +'<div class="kpi'+(r.issues.length?' warn':'')+'"><b>'+r.issues.length
      +'</b><span>issues</span></div>'
    +'<div class="kpi'+(r.updates.length?' warn':'')+'"><b>'+r.updates.length
      +'</b><span>updates</span></div>'
    +'<div class="kpi'+(r.unreachable.length?' bad':'')+'"><b>'+r.unreachable.length
      +'</b><span>unreachable</span></div>'
    +'</div>';

  if(r.unreachable.length){
    s+='<div class="alerts"><h2>Not answering</h2>'
      +r.unreachable.map(u=>'<div class="row dead"><span class="who">'+esc(u.host)
        +'</span><span>'+esc(u.why)+'</span></div>').join('')+'</div>';
  }
  if(r.issues.length){
    s+='<div class="alerts"><h2>Issues</h2>'
      +r.issues.map(i=>'<div class="row"><span class="who">'+esc(i.host)
        +'</span><span>'+esc(i.text)+'</span></div>').join('')+'</div>';
  }
  if(r.updates.length){
    s+='<div class="alerts"><h2>Updates available</h2>'
      +r.updates.map(u=>'<div class="row"><span class="who">'+esc(u.host)+'</span>'
        +'<span>'+(u.url?'<a href="'+esc(u.url)+'" target="_blank" rel="noopener">'
          +esc(u.name)+'</a>':esc(u.name))
        +' &middot; '+esc(u.detail||'')+'</span></div>').join('')+'</div>';
  }
  if(!r.unreachable.length&&!r.issues.length&&!r.updates.length&&r.hosts){
    s+='<div class="alerts"><h2>Status</h2><div class="row">'
      +'<span>Nothing needs attention on any host.</span></div></div>';
  }
  $('f-roll').innerHTML=s;
}

function svcChip(sv){
  let s='<span class="chip'+(sv.up?'':' down')+'">';
  if(sv.icon&&sv.icon!=='generic')
    s+='<img loading="lazy" alt="" src="/api/svcicon?name='+encodeURIComponent(sv.icon)
      +'" onerror="this.remove()">';
  return s+esc(sv.name)+(sv.version?' <span style="opacity:.7">'+esc(sv.version)
    +'</span>':'')+'</span>';
}

function renderHosts(list){
  if(!list.length){
    $('f-hosts').innerHTML='<div class="empty">No hosts yet. '
      +(ADMIN?'Add a peer below.':'Ask an admin to add one.')+'</div>';
    return;
  }
  $('f-hosts').innerHTML=list.map(e=>{
    const d=e.data;
    const dead=!!e.error&&!d, stale=e.stale;
    let cls='host'+(dead?' dead':'')+(e.enabled===false?' off':'');
    let s='<div class="'+cls+'">';
    s+='<div class="hhdr"><span class="dot'+(dead?' dead':stale?' stale':'')+'"></span>'
      +'<h3>'+esc(e.name)+'</h3>'
      +(e.local?'<span class="chip">this host</span>':'')+'</div>';

    if(!d){
      s+='<div class="err">'+esc(e.error||'no data yet')+'</div>';
      if(e.url)s+='<div class="sub mono">'+esc(e.url)+'</div>';
      return s+'</div>';
    }
    const h=d.host||{};
    s+='<div class="sub">Proxmox '+esc(h.pve||'?')+' &middot; up '+esc(h.uptime||'?')
      +' &middot; load '+esc(h.load||'?')+'</div>';
    if(e.error)s+='<div class="err">'+esc(e.error)+' - showing last known</div>';

    s+='<div class="bars">'
      +bar('memory',h.mem_pct,h.mem)
      +bar('root',h.disk_pct,h.disk)
      +(d.disks||[]).map(x=>bar(x.mount,x.pct,x.avail+' free')).join('')
      +'</div>';

    const gs=d.guests||[], up=gs.filter(g=>g.status==='running').length;
    s+='<div class="sub">'+up+'/'+gs.length+' guests running'
      +(h.gpus&&h.gpus.length?' &middot; '+h.gpus.length+'&times; '+esc(h.gpus[0].name):'')
      +(h.reboot_required?' &middot; <b>reboot required</b>':'')
      +(h.pending_updates?' &middot; '+h.pending_updates+' apt updates':'')
      +'</div>';

    const sv=(d.services||[]).slice().sort((a,b)=>(a.up===b.up)?0:(a.up?1:-1));
    s+='<div class="chips">'+sv.slice(0,14).map(svcChip).join('')
      +(sv.length>14?'<span class="more">+'+(sv.length-14)+' more</span>':'')+'</div>';

    s+='<div class="hfoot"><span>checked '+ago(e.age)+'</span>'
      +(e.url?'<a href="'+esc(e.url)+'" target="_blank" rel="noopener">open &rsaquo;</a>':'')
      +'</div>';
    return s+'</div>';
  }).join('');
}

function renderPeers(d){
  if(!ADMIN){$('f-peers').innerHTML='';return;}
  let s='<h2 style="font-size:15px;margin:0 0 10px">Peers</h2>';
  s+='<table class="resp"><thead><tr><th>Name</th><th>URL</th><th>State</th>'
    +'<th></th></tr></thead><tbody>';
  if(!d.peers.length){
    s+='<tr><td colspan="4">No peers configured.</td></tr>';
  }else{
    d.peers.forEach(p=>{
      const e=(d.fleet||[]).find(x=>x.id===p.id)||{};
      s+='<tr><td>'+esc(p.name)+'</td><td class="mono">'+esc(p.url)+'</td>'
        +'<td>'+(p.enabled?(e.error?'<span style="color:var(--bad)">'+esc(e.error)
          +'</span>':'ok, '+ago(e.age)):'paused')+'</td>'
        +'<td style="white-space:nowrap">'
        +'<button class="tb" data-tog="'+esc(p.id)+'">'+(p.enabled?'Pause':'Resume')
        +'</button> <button class="tb del" data-del="'+esc(p.id)+'">Remove</button>'
        +'</td></tr>';
    });
  }
  s+='</tbody></table>';

  s+='<div class="card"><h2>Add a peer</h2>'
    +'<div class="frow"><label for="p-name">Name</label>'
    +'<input id="p-name" class="fi" placeholder="second-host" autocomplete="off"></div>'
    +'<div class="frow"><label for="p-url">URL</label>'
    +'<input id="p-url" class="fi" style="min-width:260px" '
    +'placeholder="http://10.20.0.1:8085" autocomplete="off"></div>'
    +'<div class="frow"><label for="p-token">Token</label>'
    +'<input id="p-token" class="fi" type="password" style="min-width:260px" '
    +'placeholder="that host\\'s fleet token" autocomplete="off"></div>'
    +'<div class="frow"><label><input type="checkbox" id="p-insecure"> '
    +'accept a self-signed certificate</label></div>'
    +'<div class="frow"><button class="btn" id="p-add">Add peer</button>'
    +'<button class="btn ghost" id="p-refresh">Poll now</button>'
    +'<span class="note" id="p-note"></span></div>'
    +'<div class="note">Run <span class="mono">media-dashboard-fleet-token</span> on '
    +'the other host to print its token. The token only ever reads that host\\'s '
    +'status export - it cannot run jobs, read credentials or open a terminal.</div>'
    +'</div>';

  s+='<div class="card"><h2>This host\\'s token</h2>'
    +'<div class="note">Give this to another dashboard so it can federate this '
    +'host. Anyone holding it can read this page\\'s worth of status about this '
    +'host, so treat it as a credential.</div>'
    +'<div class="frow" style="margin-top:9px">'
    +'<button class="btn ghost" id="t-show">Show token</button>'
    +'<button class="btn ghost" id="t-new">Generate a new one</button></div>'
    +'<div id="t-out"></div></div>';

  $('f-peers').innerHTML=s;

  $('f-peers').querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>{
    if(confirm('Remove peer "'+b.dataset.del+'"? Its cached status is dropped too.'))
      post('/api/fleet/peer/remove',{id:b.dataset.del});
  });
  $('f-peers').querySelectorAll('[data-tog]').forEach(b=>b.onclick=()=>
    post('/api/fleet/peer/toggle',{id:b.dataset.tog}));
  $('p-add').onclick=()=>post('/api/fleet/peer/add',{
    name:$('p-name').value.trim(), url:$('p-url').value.trim(),
    token:$('p-token').value, insecure_tls:$('p-insecure').checked});
  $('p-refresh').onclick=()=>post('/api/fleet/poll',{});
  $('t-show').onclick=()=>showToken(false);
  $('t-new').onclick=()=>{
    if(confirm('Generate a new token? Every dashboard currently federating this '
      +'host stops working until you give it the new one.')) showToken(true);
  };
}

function showToken(rotate){
  fetch('/api/fleet/token',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({rotate:!!rotate})})
    .then(r=>r.json()).then(d=>{
      $('t-out').innerHTML = d.token
        ? '<div class="tok">'+esc(d.token)+'</div>'
        : '<div class="note bad">'+esc(d.error||'could not read the token')+'</div>';
    });
}

function note(msg,bad){
  const n=$('p-note'); if(!n)return;
  n.textContent=msg; n.className='note'+(bad?' bad':' good');
  setTimeout(()=>{if(n.textContent===msg){n.textContent='';n.className='note';}},6000);
}

function post(url,body){
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)}).then(r=>r.json()).then(d=>{
      if(d.error){note(d.error,true);return;}
      note(d.message||'done');
      load();
    }).catch(e=>note(String(e),true));
}

function load(){
  fetch('/api/fleet').then(r=>r.json()).then(d=>{
    DATA=d;
    renderRoll(d.rollup);
    renderHosts(d.fleet);
    renderPeers(d);
  }).catch(e=>{
    $('f-roll').innerHTML='<div class="empty">'+esc(String(e))+'</div>';
  });
}

load();
setInterval(load, 30000);
"""


def handle_get(h, path, qs):
    """Fleet routes. Returns True when it took the request.

    The export route is handled by the web service *before* the session check,
    because peers authenticate with a bearer token rather than a cookie.
    """
    if path == "/fleet":
        nav = _main_attr("nav")
        base_css = _main_attr("CSS", "")
        page = PAGE.replace("__CSS__", base_css + CSS)
        page = page.replace("__NAV__",
                            nav("/fleet", h.current_user(), h.is_admin()) if nav else "")
        page = page.replace("__JS__",
                            JS.replace("__ADMIN__", "true" if h.is_admin() else "false"))
        h.send_body(page)
        return True

    if path == "/api/fleet":
        entries = fleet.fleet()
        out = {"fleet": entries, "rollup": fleet.rollup(entries),
               "peers": fleet.peers_public() if h.is_admin() else []}
        _json(h, out)
        return True

    return False


def handle_export(h, path):
    """GET /api/fleet/export - the one route a peer token may reach.

    Checked before the session check and answering only to a bearer token. It
    serves a file the collector already wrote: no computation, no privileged
    call, and nothing in it that is not already on this host's own status page.
    """
    if path != "/api/fleet/export":
        return False
    presented = ""
    hdr = h.headers.get("Authorization") or ""
    if hdr.lower().startswith("bearer "):
        presented = hdr[7:]
    if not fleet.token_ok(presented):
        # Deliberately identical whether the token is wrong or federation was
        # never turned on here - a prober learns nothing either way.
        h.send_body('{"error":"unauthorized"}', 401, "application/json")
        return True
    try:
        with open(fleet.EXPORT_FILE, "rb") as f:
            body = f.read()
    except OSError:
        h.send_body('{"error":"no export yet"}', 503, "application/json")
        return True
    h.send_body(body, 200, "application/json")
    return True


def handle_post(h, path):
    """Fleet POSTs. Returns True when it took the request. All admin-only."""
    routes = ("/api/fleet/peer/add", "/api/fleet/peer/remove",
              "/api/fleet/peer/toggle", "/api/fleet/poll", "/api/fleet/token")
    if path not in routes:
        return False
    if not h.is_admin():
        _json(h, {"error": "admins only"}, 403)
        return True

    me = h.current_user()
    b = _body(h)

    try:
        if path == "/api/fleet/peer/add":
            name = (b.get("name") or "").strip()
            url = (b.get("url") or "").strip()
            token = (b.get("token") or "").strip()
            if not name or not url or not token:
                return _json(h, {"error": "name, URL and token are all required"}, 400)
            if len(name) > 64 or len(url) > 300 or len(token) > 512:
                return _json(h, {"error": "one of those values is implausibly long"}, 400)
            pid = "".join(c if c.isalnum() or c in "-_" else "-"
                          for c in name.lower())[:48]
            if not pid:
                return _json(h, {"error": "that name has no usable characters"}, 400)
            fleet.add_peer(pid, name, url, token, bool(b.get("insecure_tls")))
            # Poll immediately so a typo in the URL or token is reported now
            # rather than silently on the next sweep.
            entry = fleet.poll_one(next(p for p in fleet.peers() if p["id"] == pid))
            _audit(me, f"FLEET add peer {pid} url={url}")
            if entry.get("error"):
                return _json(h, {"message": f"added, but it did not answer: "
                                            f"{entry['error']}"})
            return _json(h, {"message": f"added {name}"})

        if path == "/api/fleet/peer/remove":
            pid = (b.get("id") or "").strip()
            fleet.remove_peer(pid)
            _audit(me, f"FLEET remove peer {pid}")
            return _json(h, {"message": "removed"})

        if path == "/api/fleet/peer/toggle":
            pid = (b.get("id") or "").strip()
            cur = next((p for p in fleet.peers() if p["id"] == pid), None)
            if not cur:
                return _json(h, {"error": "no such peer"}, 404)
            fleet.set_enabled(pid, not cur["enabled"])
            _audit(me, f"FLEET {'pause' if cur['enabled'] else 'resume'} peer {pid}")
            return _json(h, {"message": "paused" if cur["enabled"] else "resumed"})

        if path == "/api/fleet/poll":
            n = len(fleet.poll_all())
            return _json(h, {"message": f"polled {n} peer{'' if n == 1 else 's'}"})

        if path == "/api/fleet/token":
            if b.get("rotate"):
                try:
                    os_remove = __import__("os").remove
                    os_remove(fleet.TOKEN_FILE)
                except OSError:
                    pass
                _audit(me, "FLEET rotated this host's federation token")
            tok = fleet.local_token(create=True)
            if not tok:
                return _json(h, {"error": "could not create a token"}, 500)
            return _json(h, {"token": tok})
    except ValueError as e:
        return _json(h, {"error": str(e)}, 400)
    except Exception as e:
        return _json(h, {"error": f"{type(e).__name__}: {e}"}, 500)

    return True
