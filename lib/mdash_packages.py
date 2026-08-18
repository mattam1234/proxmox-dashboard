"""Package catalogues in the app store: apt, and the Proxmox appliance list.

The app store already installs whole applications - a helper script that builds
a container, or a compose stack. This adds the layer underneath it: the package
catalogues of the machines themselves. apt on the Proxmox host and inside every
running container, plus the Proxmox appliance catalogue (the LXC templates
`pveam` offers), all searchable and installable from the same page.

Wiring (in media-dashboard-web.py):

    import mdash_packages

    # in do_GET, after the session check:
    if mdash_packages.handle_get(self, path, qs):
        return

    # at the top of do_POST (it checks the session itself):
    if mdash_packages.handle_post(self, p):
        return

    # in the app store page: mdash_packages.PANEL as a tab panel.

Everything here is admin-only, and nothing here runs a command. The web process
deliberately cannot reach pct - that is the whole point of it running under
ProtectSystem=strict - so this module only ever *describes* what it wants:

  * reads go out as queries, spooled to /var/lib/media-dashboard/queries and
    answered by the runner within a fraction of a second. The runner will only
    answer with apt-cache, apt list, dpkg-query, `apt-get -s` and pveam, so a
    query cannot change anything even if this process were compromised.

  * writes go out as jobs, on the same spool the rest of the dashboard uses,
    and are re-validated against the live host before a command is built.

Installing is a two-step: the plan comes back from `apt-get -s` and is shown
before anything happens, so an install that would drag in forty packages, or a
removal that would take systemd with it, is visible rather than a surprise.
Removals apt would cascade into anything essential are refused outright by the
runner - see PROTECTED_PKGS there.
"""
import json
import os
import re
import shutil
import sys
import threading
import time

QUERY_DIR = "/var/lib/media-dashboard/queries"
TOPO_FILE = "/var/lib/media-dashboard/topology.json"
HOSTS_FILE = "/var/lib/media-dashboard/hosts.json"

QUERY_WAIT = 60                 # apt on a cold cache; the UI shows a spinner
CACHE_TTL = 120                 # a search result is good enough for this long
MAX_BODY = 64 * 1024
MAX_PKGS = 20

PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,99}$")
SEARCH_RE = re.compile(r"^[A-Za-z0-9 +._:@/-]{2,80}$")
TARGET_RE = re.compile(r"^(host|[0-9]{3,5})$")
TEMPLATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.tar\.(gz|xz|zst)$")
STORAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,64}$")

_cache = {}
_cache_lock = threading.Lock()


def _main_attr(name, default=None):
    """Borrow audit()/enqueue()/CSS from the dashboard without importing it."""
    return getattr(sys.modules.get("__main__"), name, default)


# ---------------------------------------------------------------- query client

def ask(kind, params, timeout=QUERY_WAIT):
    """Put a read-only lookup on the runner's spool and wait for the answer.

    Returns (data, error). The id is generated here and shape-checked by the
    runner, so a query file can only ever be answered into the spool directory.
    """
    qid = f"{int(time.time())}-{os.urandom(4).hex()}"
    try:
        os.makedirs(QUERY_DIR, exist_ok=True)
        tmp = os.path.join(QUERY_DIR, qid + ".json.tmp")
        with open(tmp, "w") as f:
            json.dump({"id": qid, "kind": kind, "params": params}, f)
        # Moved into place only once complete, so the runner cannot pick up a
        # half-written query.
        shutil.move(tmp, os.path.join(QUERY_DIR, qid + ".json"))
    except OSError as e:
        return None, f"could not reach the runner: {e}"

    out = os.path.join(QUERY_DIR, qid + ".out")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(out) as f:
                ans = json.load(f)
        except (OSError, ValueError):
            time.sleep(0.1)
            continue
        try:
            os.unlink(out)
        except OSError:
            pass
        if ans.get("ok"):
            return ans.get("data"), None
        return None, ans.get("error") or "the lookup failed"
    return None, ("the runner did not answer in time - check that "
                  "media-dashboard-runner.service is running")


def cached(key, fn):
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_TTL:
            return hit[1]
    val = fn()
    with _cache_lock:
        if len(_cache) > 64:
            _cache.clear()
        _cache[key] = (now, val)
    return val


def drop_cache(target=None):
    with _cache_lock:
        for k in [k for k in _cache if target is None or k[1] == target]:
            _cache.pop(k, None)


# ---------------------------------------------------------------- targets

def targets():
    """The host, plus every container a package could be installed into."""
    out = [{"id": "host", "label": "pve (Proxmox host)", "running": True}]
    seen = set()
    try:
        with open(TOPO_FILE) as f:
            for n in json.load(f).get("nodes", []):
                if n.get("kind") != "ct":
                    continue
                cid = str(n.get("id", "")).split(":")[-1]
                if not cid.isdigit():
                    continue
                meta = {k: v for k, v in (n.get("meta") or [])}
                seen.add(cid)
                out.append({"id": cid, "label": n.get("label") or cid,
                            "running": meta.get("Status") == "running"})
    except Exception:
        pass
    if len(out) == 1:                       # topology not collected yet
        try:
            with open(HOSTS_FILE) as f:
                for hrow in json.load(f).get("hosts", []):
                    cid = str(hrow.get("cid"))
                    if cid.isdigit() and cid not in seen:
                        out.append({"id": cid,
                                    "label": f"{cid} {hrow.get('name', '')}".strip(),
                                    "running": True})
        except Exception:
            pass
    return out


def valid_target(t):
    t = str(t or "")
    if not TARGET_RE.match(t):
        return None
    if t != "host" and t not in [x["id"] for x in targets()]:
        return None
    return t


def valid_names(raw):
    if isinstance(raw, str):
        raw = [x for x in re.split(r"[\s,]+", raw) if x]
    if not isinstance(raw, list) or not raw:
        return None
    if len(raw) > MAX_PKGS:
        return None
    out = []
    for n in raw:
        n = str(n or "").strip()
        if not PKG_RE.match(n):
            return None
        if n not in out:
            out.append(n)
    return out


# ---------------------------------------------------------------- panel

PANEL = """
<style>
.pk .row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-bottom:12px}
.pk .row label{font-size:12px;color:var(--muted);display:block;margin-bottom:3px}
.pk select,.pk input{padding:7px 11px;border-radius:7px;border:1px solid var(--line);
background:var(--card);color:var(--fg);font-size:13px}
.pk input.q{flex:1;min-width:200px}
.pk table{width:100%;border-collapse:collapse}
.pk td,.pk th{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);
font-size:13px;vertical-align:top}
.pk th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.pk tr.p{cursor:pointer}
.pk tr.p:hover{background:var(--bg)}
.pk .nm{font-weight:600}
.pk .ver{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
color:var(--muted);white-space:nowrap}
.pk .d{color:var(--muted)}
.pk .in{font-size:10px;padding:1px 7px;border-radius:20px;
border:1px solid color-mix(in srgb,var(--ok) 45%,transparent);color:var(--ok)}
.pk .up{font-size:10px;padding:1px 7px;border-radius:20px;
border:1px solid color-mix(in srgb,var(--accent) 45%,transparent);color:var(--accent)}
.pk .spin{color:var(--muted);font-size:13px;padding:20px;text-align:center}
.pkmod{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;
align-items:center;justify-content:center;padding:20px;z-index:80}
.pkmod.on{display:flex}
.pkmod .b{background:var(--card);border:1px solid var(--line);border-radius:12px;
max-width:640px;width:100%;max-height:90vh;overflow:auto;padding:20px}
.pkmod h2{margin:0 0 4px;font-size:17px}
.pkmod pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:11px;
white-space:pre-wrap;word-break:break-word;max-height:40vh;overflow:auto}
@media (max-width:620px){.pkmod{padding:0;align-items:flex-end}
.pkmod .b{border-radius:16px 16px 0 0;border-width:1px 0 0;max-height:92vh;
padding:18px 16px calc(18px + env(safe-area-inset-bottom))}
.pk table td.hidesm{display:none}}
</style>
<div class="pk">
  <div class="row">
    <div><label>Catalogue</label>
      <select id="pk-cat" onchange="PKG.catalog()">
        <option value="apt">apt packages</option>
        <option value="pveam">Proxmox container templates</option>
      </select></div>
    <div id="pk-twrap"><label>On</label>
      <select id="pk-target" onchange="PKG.retarget()"></select></div>
    <div id="pk-mwrap"><label>Show</label>
      <select id="pk-mode" onchange="PKG.go()">
        <option value="search">Search the catalogue</option>
        <option value="upgradable">Upgradable</option>
        <option value="manual">Installed on purpose</option>
        <option value="installed">Everything installed</option>
      </select></div>
    <input class="q" id="pk-q" placeholder="Search packages..."
           onkeydown="if(event.key==='Enter')PKG.go()">
    <button class="btn go" onclick="PKG.go()">Search</button>
    <button class="btn" id="pk-refresh" onclick="PKG.refresh()">Refresh lists</button>
  </div>
  <div class="sub" id="pk-sub" style="margin:0 0 10px"></div>
  <div class="tablewrap"><div id="pk-out"></div></div>
  <div class="more" id="pk-more"></div>
</div>
<div class="pkmod" id="pk-mod" onclick="if(event.target===this)PKG.close()">
  <div class="b" id="pk-box"></div>
</div>
<script>
(function(){
var ST={cat:'apt',target:'host',rows:[],shown:0,pol:{},tpl:null,job:null};
var PAGE=80;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function jstr(v){return esc(JSON.stringify(v));}
function el(i){return document.getElementById(i);}
function sub(t){el('pk-sub').textContent=t;}
function spin(t){el('pk-out').innerHTML='<div class="spin">'+esc(t)+'</div>';
  el('pk-more').innerHTML='';}

function get(url){
  return fetch(url,{cache:'no-store'}).then(function(r){return r.json();});
}

// ---- apt

function rowsHtml(){
  var s='<table><tr><th>Package</th><th>Version</th>'
    +'<th class="hidesm">What it is</th><th></th></tr>';
  ST.rows.slice(0,ST.shown).forEach(function(r){
    var p=ST.pol[r.name]||{};
    var inst=p.installed||r.version||'';
    var cand=p.candidate||r.candidate||'';
    var tag=inst?(cand&&cand!==inst?'<span class="up">update</span>'
                                   :'<span class="in">installed</span>'):'';
    s+='<tr class="p" onclick="PKG.open('+jstr(r.name)+')">'
      +'<td><span class="nm">'+esc(r.name)+'</span> '+tag+'</td>'
      +'<td class="ver">'+esc(inst||cand||'')
      +(inst&&cand&&cand!==inst?' &rarr; '+esc(cand):'')+'</td>'
      +'<td class="d hidesm">'+esc(r.desc||'')+'</td>'
      +'<td style="text-align:right"><button class="btn" onclick="event.stopPropagation();'
      +'PKG.plan('+(inst?jstr('remove'):jstr('install'))+','+jstr(r.name)+')">'
      +(inst?(cand&&cand!==inst?'Upgrade':'Remove'):'Install')+'</button></td></tr>';
  });
  el('pk-out').innerHTML=s+'</table>';
  var left=ST.rows.length-ST.shown;
  el('pk-more').innerHTML = left>0
    ? '<button class="btn" onclick="PKG.more()">Show more ('+left+' left)</button>'
    : '';
}

// Versions are fetched only for the rows on screen: asking apt-cache about
// 600 packages costs the same as asking it about 80, but showing 600 rows
// costs the reader rather more.
function policy(){
  var want=ST.rows.slice(Math.max(0,ST.shown-PAGE),ST.shown)
    .map(function(r){return r.name;})
    .filter(function(n){return !(n in ST.pol);});
  if(!want.length)return;
  var q='/api/packages/policy?target='+encodeURIComponent(ST.target)
    +'&names='+encodeURIComponent(want.slice(0,20).join(','));
  get(q).then(function(d){
    if(d.policy){for(var k in d.policy)ST.pol[k]=d.policy[k];rowsHtml();}
    // Only 20 at a time, so keep going while rows remain unpriced.
    if(want.length>20)policy();
  });
}

function show(d,what){
  ST.rows=d.rows||[];ST.pol={};ST.shown=Math.min(PAGE,ST.rows.length);
  sub(ST.rows.length?(d.total>ST.rows.length
      ? d.total+' matches, showing the first '+ST.rows.length
      : ST.rows.length+' '+what)
    :'Nothing matched.');
  rowsHtml();
  if(ST.rows.length)policy();
}

// ---- templates

function tplHtml(){
  var d=ST.tpl||{}, rows=d.rows||[];
  var q=(el('pk-q').value||'').toLowerCase();
  var out=rows.filter(function(r){return !q||r.template.toLowerCase().indexOf(q)>=0;});
  var s='<table><tr><th>Template</th><th>Section</th><th></th></tr>';
  out.slice(0,300).forEach(function(r){
    s+='<tr><td><span class="nm">'+esc(r.template)+'</span></td>'
      +'<td class="d">'+esc(r.section)+'</td><td style="text-align:right">'
      +(r.downloaded?'<span class="in">downloaded</span>'
        :'<button class="btn" onclick="PKG.template('+jstr(r.template)+')">'
         +'Download</button>')+'</td></tr>';
  });
  el('pk-out').innerHTML=s+'</table>';
  el('pk-more').innerHTML='';
  var st=(d.storages||[]).map(function(x){
    return x.name+' ('+x.free_gb+' GB free)';}).join(', ');
  sub(out.length+' of '+rows.length+' templates'+(st?' - stored on '+st:''));
}

// ---- job watching, shared by installs, removals and downloads

function watch(jid,title){
  ST.job=jid;
  box('<h2>'+esc(title)+'</h2><div class="src">Job '+esc(jid)
    +' - closing this does not stop it.</div><pre id="pk-log">waiting for '
    +'output...</pre><div class="acts"><button class="btn" onclick="PKG.close();'
    +'PKG.go()">Close</button></div>');
  tick();
}
function tick(){
  if(!ST.job)return;
  get('/api/runner/joblog?id='+encodeURIComponent(ST.job)).then(function(d){
    var l=el('pk-log'); if(!l||!ST.job)return;
    var end=l.scrollTop+l.clientHeight>=l.scrollHeight-30;
    l.textContent=d.log||'waiting for output...';
    if(end)l.scrollTop=l.scrollHeight;
    setTimeout(tick,2000);
  }).catch(function(){setTimeout(tick,4000);});
}

function box(h){el('pk-box').innerHTML=h;el('pk-mod').className='pkmod on';}

function post(body){
  return fetch('/api/packages',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(function(r){return r.json();});
}

function planHtml(op,name,p){
  var s='<h2>'+esc(op==='install'?'Install ':'Remove ')+esc(name)+'</h2>'
    +'<div class="src">on '+esc(el('pk-target').selectedOptions[0].textContent)
    +'</div>';
  if(p.blocked&&p.blocked.length){
    s+='<div class="warn-box"><b>Refused.</b><br>'+p.blocked.map(esc).join('<br>')
      +'</div><div class="acts"><button class="btn" onclick="PKG.close()">Close'
      +'</button></div>';
    return s;
  }
  function lst(t,arr){
    if(!arr||!arr.length)return '';
    return '<div style="margin-top:10px"><b style="font-size:12px">'+t+'</b>'
      +'<div class="ver" style="margin-top:4px">'+arr.map(function(x){
        return esc(x.name)+(x.from?' '+esc(x.from)+' \\u2192 '+esc(x.to)
                                  :(x.to?' '+esc(x.to):''));}).join('<br>')
      +'</div></div>';
  }
  s+=lst('New packages',p.install)+lst('Upgraded',p.upgrade)
    +lst('Removed',p.remove);
  if(p.summary)s+='<div class="src" style="margin-top:12px">'+esc(p.summary)+'</div>';
  if(p.download)s+='<div class="src">'+esc(p.download)+'</div>';
  if(p.space)s+='<div class="src">'+esc(p.space)+'</div>';
  if(op!=='install'&&p.remove&&p.remove.length>1){
    s+='<div class="warn-box"><b>This takes other packages with it.</b><br>'
      +'apt wants to remove '+p.remove.length+' packages, not one. Read the '
      +'list above before you agree to it.</div>';
  }
  if(!p.install.length&&!p.remove.length&&!p.upgrade.length){
    s+='<div class="warn-box">apt says there is nothing to do here.</div>';
  }
  s+='<div class="acts"><button class="btn" onclick="PKG.close()">Cancel</button>'
    +'<button class="btn '+(op==='install'?'go':'danger')+'" id="pk-go" '
    +'onclick="PKG.run('+jstr(op)+','+jstr(name)+')">'
    +esc(op==='install'?'Install':'Remove')+'</button></div>';
  return s;
}

window.PKG={
  show:function(){
    if(el('pk-target').options.length)return;
    get('/api/packages/state').then(function(d){
      var sel=el('pk-target');
      (d.targets||[]).forEach(function(t){
        var o=document.createElement('option');
        o.value=t.id;o.textContent=t.label+(t.running?'':' (stopped)');
        o.disabled=!t.running;sel.appendChild(o);
      });
      sel.value='host';ST.target='host';
      sub('Pick a catalogue and search, or list what is already installed.');
    });
  },
  catalog:function(){
    ST.cat=el('pk-cat').value;
    var apt=ST.cat==='apt';
    el('pk-twrap').style.display=apt?'':'none';
    el('pk-mwrap').style.display=apt?'':'none';
    el('pk-refresh').style.display=apt?'':'none';
    el('pk-q').placeholder=apt?'Search packages...':'Filter templates...';
    if(apt){ST.rows=[];el('pk-out').innerHTML='';sub('');}
    else this.go();
  },
  retarget:function(){ST.target=el('pk-target').value;ST.rows=[];ST.pol={};
    el('pk-out').innerHTML='';sub('');},
  more:function(){ST.shown=Math.min(ST.shown+PAGE,ST.rows.length);rowsHtml();policy();},
  go:function(){
    if(ST.cat==='pveam'){
      if(ST.tpl)return tplHtml();
      spin('Reading the Proxmox appliance catalogue...');
      return get('/api/packages/templates').then(function(d){
        if(d.error){el('pk-out').innerHTML='<div class="empty">'+esc(d.error)
          +'</div>';return;}
        ST.tpl=d;tplHtml();
      });
    }
    var mode=el('pk-mode').value, q=(el('pk-q').value||'').trim();
    if(mode==='search'&&q.length<2){
      sub('Type at least two characters to search.');return;
    }
    spin(mode==='search'?'Asking apt on '+ST.target+'...'
                        :'Listing packages on '+ST.target+'...');
    var u=mode==='search'
      ? '/api/packages/search?target='+encodeURIComponent(ST.target)
        +'&q='+encodeURIComponent(q)
      : '/api/packages/list?target='+encodeURIComponent(ST.target)
        +'&mode='+encodeURIComponent(mode);
    get(u).then(function(d){
      if(d.error){el('pk-out').innerHTML='<div class="empty">'+esc(d.error)
        +'</div>';el('pk-more').innerHTML='';sub('');return;}
      show(d,mode==='search'?'matches':'packages');
    });
  },
  open:function(name){
    box('<div class="spin">Reading '+esc(name)+'...</div>');
    get('/api/packages/show?target='+encodeURIComponent(ST.target)
        +'&name='+encodeURIComponent(name)).then(function(d){
      if(d.error){box('<div class="warn-box">'+esc(d.error)+'</div>');return;}
      var s='<h2>'+esc(d.name)+'</h2><div class="src">'+esc(d.summary||'')+'</div>';
      s+='<div class="ver" style="margin:10px 0">'
        +(d.installed?'installed '+esc(d.installed)+'<br>':'not installed<br>')
        +(d.candidate?'available '+esc(d.candidate):'')+'</div>';
      if(d.description)s+='<pre>'+esc(d.description)+'</pre>';
      var meta=[['Section',d.section],['Priority',d.priority],
        ['Installed size',d.installed_size?d.installed_size+' kB':''],
        ['Homepage',d.homepage],['Depends',d.depends]];
      s+='<div class="src" style="margin-top:10px">'+meta.filter(function(m){
        return m[1];}).map(function(m){
          return '<b>'+m[0]+':</b> '+esc(m[1]);}).join('<br>')+'</div>';
      if(d.protected)s+='<div class="warn-box"><b>Protected.</b><br>This host or '
        +'one of its services is built on this package, so the dashboard will '
        +'not remove it.</div>';
      s+='<div class="acts"><button class="btn" onclick="PKG.close()">Close</button>';
      if(d.installed&&d.candidate&&d.candidate!==d.installed)
        s+='<button class="btn go" onclick="PKG.plan(\\'install\\','+jstr(d.name)
          +')">Upgrade</button>';
      if(!d.installed)
        s+='<button class="btn go" onclick="PKG.plan(\\'install\\','+jstr(d.name)
          +')">Install</button>';
      else if(!d.protected)
        s+='<button class="btn danger" onclick="PKG.plan(\\'remove\\','+jstr(d.name)
          +')">Remove</button>';
      box(s+'</div>');
    });
  },
  plan:function(op,name){
    box('<div class="spin">Asking apt what that would do...</div>');
    get('/api/packages/plan?target='+encodeURIComponent(ST.target)
        +'&op='+encodeURIComponent(op)+'&names='+encodeURIComponent(name))
      .then(function(d){
        if(d.error){box('<div class="warn-box"><b>Refused.</b><br>'+esc(d.error)
          +'</div><div class="acts"><button class="btn" onclick="PKG.close()">'
          +'Close</button></div>');return;}
        box(planHtml(op,name,d));
      });
  },
  run:function(op,name){
    var b=el('pk-go'); if(b){b.disabled=true;b.textContent='Starting...';}
    post({action:op,target:ST.target,names:[name]}).then(function(d){
      if(d.error){box('<div class="warn-box"><b>Refused.</b><br>'+esc(d.error)
        +'</div><div class="acts"><button class="btn" onclick="PKG.close()">'
        +'Close</button></div>');return;}
      ST.pol={};
      watch(d.job,(op==='install'?'Installing ':'Removing ')+name);
    });
  },
  refresh:function(){
    post({action:'refresh',target:ST.target}).then(function(d){
      if(d.error){box('<div class="warn-box">'+esc(d.error)+'</div>');return;}
      watch(d.job,'Refreshing package lists');
    });
  },
  template:function(tpl){
    if(!confirm('Download '+tpl+' to local storage?'))return;
    post({action:'template',template:tpl}).then(function(d){
      if(d.error){box('<div class="warn-box">'+esc(d.error)+'</div>');return;}
      ST.tpl=null;
      watch(d.job,'Downloading '+tpl);
    });
  },
  close:function(){el('pk-mod').className='pkmod';ST.job=null;}
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


ROUTES = ("/api/packages/state", "/api/packages/search", "/api/packages/list",
          "/api/packages/policy", "/api/packages/show", "/api/packages/plan",
          "/api/packages/templates")


def handle_get(h, path, qs):
    """Handle a package lookup. Returns True when it took the request."""
    if path not in ROUTES:
        return False
    # Browsing a package catalogue tells you what is installed where, and the
    # buttons next to it install things as root, so this is admin-only like the
    # rest of the app store.
    if not h.is_admin():
        _json(h, {"error": "admins only"}, 403)
        return True

    from urllib.parse import parse_qs
    p = parse_qs(qs)

    def arg(k, default=""):
        return (p.get(k) or [default])[0]

    if path == "/api/packages/state":
        _json(h, {"targets": targets()})
        return True

    if path == "/api/packages/templates":
        data, err = cached(("pveam", "host"),
                           lambda: ask("pveam.catalog", {}))
        if err:
            _json(h, {"error": err}, 200)
        else:
            _json(h, data)
        return True

    target = valid_target(arg("target"))
    if not target:
        _json(h, {"error": "that is not a machine on this host"}, 400)
        return True

    if path == "/api/packages/search":
        q = arg("q").strip()
        if not SEARCH_RE.match(q):
            _json(h, {"error": "search for 2-80 characters of plain text"}, 400)
            return True
        data, err = cached(("search", target, q.lower()),
                           lambda: ask("apt.search", {"target": target, "q": q}))
    elif path == "/api/packages/list":
        mode = arg("mode", "installed")
        if mode not in ("installed", "manual", "upgradable"):
            _json(h, {"error": "unknown listing"}, 400)
            return True
        data, err = cached(("list", target, mode),
                           lambda: ask("apt.list", {"target": target,
                                                    "mode": mode}))
    elif path == "/api/packages/policy":
        names = valid_names(arg("names"))
        if not names:
            _json(h, {"error": "bad package names"}, 400)
            return True
        data, err = ask("apt.policy", {"target": target, "names": names})
    elif path == "/api/packages/show":
        names = valid_names(arg("name"))
        if not names:
            _json(h, {"error": "that is not a package name"}, 400)
            return True
        data, err = cached(("show", target, names[0]),
                           lambda: ask("apt.show", {"target": target,
                                                    "names": names[:1]}))
    else:                                            # /api/packages/plan
        op = arg("op")
        if op not in ("install", "remove", "purge"):
            _json(h, {"error": "unknown operation"}, 400)
            return True
        names = valid_names(arg("names"))
        if not names:
            _json(h, {"error": "bad package names"}, 400)
            return True
        # Never cached: the plan is what the operator is about to approve.
        data, err = ask("apt.plan", {"target": target, "op": op, "names": names})

    if err:
        _json(h, {"error": err}, 200)
    else:
        _json(h, data)
    return True


def handle_post(h, path):
    """Handle a package install/removal. Returns True when it took the request."""
    if path != "/api/packages":
        return False
    if not h.session_ok():
        _json(h, {"error": "unauthenticated"}, 401)
        return True
    if not h.is_admin():
        _json(h, {"error": "admins only"}, 403)
        return True
    body, err = _body(h)
    if err:
        _json(h, {"error": err}, 400)
        return True

    enqueue = _main_attr("enqueue")
    audit = _main_attr("audit")
    if not enqueue:
        _json(h, {"error": "the job spool is not available"}, 500)
        return True
    user = h.current_user() or "?"
    action = str(body.get("action") or "")

    if action == "template":
        tpl = str(body.get("template") or "")
        store = str(body.get("storage") or "local")
        if not TEMPLATE_RE.match(tpl) or not STORAGE_RE.match(store):
            _json(h, {"error": "that is not a template on this host"}, 400)
            return True
        jid = enqueue("template.download", {"template": tpl, "storage": store},
                      user)
        if audit:
            audit(user, f"TEMPLATE download {tpl} -> {store} (job {jid})")
        _json(h, {"ok": True, "job": jid})
        return True

    target = valid_target(body.get("target"))
    if not target:
        _json(h, {"error": "that is not a machine on this host"}, 400)
        return True

    if action == "refresh":
        jid = enqueue("pkg.refresh", {"target": target}, user)
        if audit:
            audit(user, f"APT refresh on {target} (job {jid})")
        drop_cache()
        _json(h, {"ok": True, "job": jid})
        return True

    if action not in ("install", "remove", "purge"):
        _json(h, {"error": "unknown action"}, 400)
        return True
    names = valid_names(body.get("names"))
    if not names:
        _json(h, {"error": f"name 1-{MAX_PKGS} valid packages"}, 400)
        return True

    if action in ("remove", "purge"):
        # The runner refuses a removal that would take something essential with
        # it, but it does that as a failed job. Asking it the same question here
        # first turns that into an answer on the screen instead - and asking the
        # runner rather than keeping a second copy of the protected list means
        # the two cannot drift apart.
        plan, perr = ask("apt.plan", {"target": target, "op": action,
                                      "names": names})
        if not perr and (plan or {}).get("blocked"):
            _json(h, {"error": "; ".join(plan["blocked"])}, 400)
            return True

    act = "pkg.install" if action == "install" else "pkg.remove"
    params = {"target": target, "names": names}
    if action == "purge":
        params["purge"] = True
    jid = enqueue(act, params, user)
    if audit:
        audit(user, f"APT {action} {' '.join(names)} on {target} (job {jid})")
    # What is installed on that target is about to change, so nothing cached
    # about it is worth keeping.
    drop_cache(target)
    _json(h, {"ok": True, "job": jid})
    return True
