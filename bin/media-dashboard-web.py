#!/usr/bin/env python3
"""Serves the media stack dashboard behind a form login.

Stdlib only. Sessions are stateless signed cookies; the password is stored
as a scrypt hash in /etc/media-dashboard/auth.json (mode 600).

Pages (all require a session):
    /             status dashboard (static file from the collector) + live downloads
    /catalog      paged, searchable view of the Jellyfin film and series library
    /credentials  usernames/passwords, read live from the credentials file
    /files        read-only browser over the media volumes

Set/change the password:
    /usr/local/bin/media-dashboard-passwd.py
"""
import base64
import hashlib
import hmac
import html
import http.cookies
import io
import json
import os
import re
import secrets
import shutil
import sys
import threading
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, quote

# Admin-only tmux terminal. Kept in its own module so this file stays readable;
# see /usr/local/lib/mdash/mdash_tmux.py.
sys.path.insert(0, "/usr/local/lib/mdash")
# What this particular host is: containers, addresses, storage, what runs
# where. Detected by the collector and read from its cache here, so nothing in
# this file names a container or an address.
import mdash_site as site                              # noqa: E402
import mdash_tmux                                      # noqa: E402
import mdash_claude                                    # noqa: E402
import mdash_usage                                     # noqa: E402
import mdash_tunnel                                    # noqa: E402
import mdash_usersync                                  # noqa: E402
import mdash_addons                                    # noqa: E402
import mdash_packages                                  # noqa: E402
import mdash_fleet                                     # noqa: E402
import mdash_fleetui                                   # noqa: E402

# Listen on the internal bridge, whatever it turned out to be - never on the
# uplink, which is DHCP and faces the LAN.
BIND = site.bind_addr(8085)
DOC = "/var/www/dashboard/index.html"
AUTH_FILE = "/etc/media-dashboard/auth.json"
CRED_FILE = "/root/media-stack-credentials.txt"
COOKIE = "mdsession"
SESSION_SECONDS = 12 * 3600

JELLYFIN_KEY_FILE = "/root/.jellyfin-key"


def qbit_base():
    return site.base_url("qBittorrent")


def jellyfin_base():
    return site.base_url("Jellyfin")


# The file browser may only ever look inside these. Anything resolving outside
# is refused, which is what stops ../ traversal. The roots are the storage the
# host was found to have, so a box that keeps its media elsewhere still browses
# and one with no media shares browses nothing.
BROWSE_ROOTS = [r for r in ([site.shared_root()] + site.bulk_roots()) if r]

_fails = {}
# Requests arrive two ways: straight off the internal bridge, and proxied by the
# tunnel connector. Only that connector may claim a client IP on someone else's
# behalf. CF-Connecting-IP is just a header, so without this anything on the
# internal subnet could rotate it per request and never trip the login lockout
# below - unlimited password guessing against a login that fronts root shells.
# The connector's address is detected; override with one IP per line in
# /etc/media-dashboard/trusted-proxies.
TRUSTED_PROXIES = site.trusted_proxies()
try:
    with open("/etc/media-dashboard/trusted-proxies") as _tp:
        _loaded = {ln.strip() for ln in _tp
                   if ln.strip() and not ln.lstrip().startswith("#")}
    if _loaded:
        TRUSTED_PROXIES = _loaded
except Exception:
    pass

_LOCK_AFTER = 5
_LOCK_SECONDS = 300


# ------------------------------------------------------------------ auth
USERNAME_OK = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def hash_pw(password, salt=None):
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()


def load_auth():
    with open(AUTH_FILE) as f:
        a = json.load(f)
    # Migrate the original single-password format to the multi-user one.
    if "users" not in a:
        a = {"secret": a.get("secret") or secrets.token_hex(32),
             "users": {"admin": {"salt": a["salt"], "hash": a["hash"], "role": "admin"}}}
        save_auth(a)
    return a


def save_auth(a):
    os.makedirs(os.path.dirname(AUTH_FILE), mode=0o700, exist_ok=True)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(a, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)


def verify_user(auth, username, password):
    u = (auth.get("users") or {}).get(username)
    if not u:
        # Compare against a dummy so a bad username costs the same as a bad password.
        hash_pw(password)
        return False
    _s, expect = hash_pw(password, base64.b64decode(u["salt"]))
    return hmac.compare_digest(expect, u["hash"])


def make_session(auth, username):
    exp = str(int(time.time()) + SESSION_SECONDS)
    payload = f"{exp}:{username}"
    sig = hmac.new(auth["secret"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{username}.{sig}"


def valid_session(auth, token):
    """Return the username the token authenticates, or None."""
    if not token or token.count(".") != 2:
        return None
    exp, username, sig = token.split(".")
    good = hmac.new(auth["secret"].encode(), f"{exp}:{username}".encode(),
                    hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, good):
        return None
    try:
        if int(exp) <= time.time():
            return None
    except ValueError:
        return None
    if username not in (auth.get("users") or {}):
        return None
    return username


def role_of(auth, username):
    return ((auth.get("users") or {}).get(username) or {}).get("role", "user")


# ------------------------------------------------------------------ helpers
def human(n):
    n = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024 or u == "T":
            return f"{n:.1f}{u}"
        n /= 1024.0


def qbit_downloads():
    """Live torrent list. The host is subnet-whitelisted so no login is needed."""
    try:
        out = subprocess.run(
            ["curl", "-sf", "--max-time", "6",
             f"{qbit_base()}/api/v2/torrents/info"],
            capture_output=True, text=True, timeout=10)
        data = json.loads(out.stdout) if out.returncode == 0 else []
    except Exception:
        return None
    rows = []
    for t in data:
        eta = t.get("eta") or 0
        if eta and eta < 8640000:
            h, m = divmod(int(eta) // 60, 60)
            eta_s = f"{h}h {m}m" if h else f"{m}m"
        else:
            eta_s = "—"
        rows.append({
            "name": t.get("name", "?"),
            "state": t.get("state", ""),
            "progress": round((t.get("progress") or 0) * 100, 1),
            "size": human(t.get("size") or 0),
            "dlspeed": human(t.get("dlspeed") or 0) + "/s",
            "upspeed": human(t.get("upspeed") or 0) + "/s",
            "eta": eta_s,
        })
    rows.sort(key=lambda r: (r["state"] not in ("downloading", "stalledDL"), -r["progress"]))
    return rows


# ------------------------------------------------------------------ catalog
# Jellyfin already holds the library index, so the catalog is a thin paged view
# over its API rather than a second index of our own. Rich fields are asked for
# here and reduced to one compact record per item: it keeps the API key on the
# server and cuts the browser payload to roughly a quarter of Jellyfin's JSON.
CATALOG_KINDS = {"movies": "Movie", "series": "Series"}

# label -> (Jellyfin SortBy, SortOrder)
CATALOG_SORTS = {
    "name": ("SortName", "Ascending"),
    "added": ("DateCreated", "Descending"),
    "year": ("ProductionYear", "Descending"),
    "rating": ("CommunityRating", "Descending"),
    "runtime": ("Runtime", "Descending"),
}
CATALOG_PAGE_SIZE = 60
CATALOG_MAX_PAGE = 200

_jf_server = None


def _jf_get(path, timeout=20):
    """GET a Jellyfin API path with the server's key. None on any failure."""
    try:
        with open(JELLYFIN_KEY_FILE) as f:
            key = f.read().strip()
    except Exception:
        return None
    if not key:
        return None
    try:
        r = subprocess.run(
            ["curl", "-sf", "--max-time", str(max(4, timeout - 4)),
             "-H", f"X-Emby-Token: {key}", f"{jellyfin_base()}{path}"],
            capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 or not r.stdout:
            return None
        return json.loads(r.stdout)
    except Exception:
        return None


def jf_server_id():
    """Jellyfin's server id, needed to build /web/#/details deep links."""
    global _jf_server
    if not _jf_server:
        _jf_server = (_jf_get("/System/Info/Public", timeout=8) or {}).get("Id") or ""
    return _jf_server


def catalog_genres(kind):
    d = _jf_get(f"/Genres?Recursive=true&IncludeItemTypes={CATALOG_KINDS[kind]}"
                f"&Limit=300&SortBy=SortName", timeout=12) or {}
    return [g["Name"] for g in d.get("Items") or [] if g.get("Name")]


def catalog_query(kind, start=0, limit=CATALOG_PAGE_SIZE, search="", genre="",
                  sort="name"):
    """One page of the library. None if Jellyfin cannot be reached."""
    sort_by, order = CATALOG_SORTS.get(sort, CATALOG_SORTS["name"])
    q = ["Recursive=true",
         f"IncludeItemTypes={CATALOG_KINDS[kind]}",
         f"StartIndex={start}", f"Limit={limit}",
         f"SortBy={sort_by}", f"SortOrder={order}",
         "EnableTotalRecordCount=true", "ImageTypeLimit=1",
         "Fields=ProductionYear,RunTimeTicks,Genres,CommunityRating,"
         "OfficialRating,DateCreated,ChildCount,MediaSources"]
    if search:
        q.append("SearchTerm=" + quote(search))
    if genre:
        q.append("Genres=" + quote(genre))
    d = _jf_get("/Items?" + "&".join(q), timeout=25)
    if d is None:
        return None
    items = []
    for i in d.get("Items") or []:
        ticks = i.get("RunTimeTicks") or 0
        rating = i.get("CommunityRating")
        # A series has no media source of its own; only films report bytes.
        size = sum((ms.get("Size") or 0) for ms in i.get("MediaSources") or [])
        items.append({
            "id": i.get("Id") or "",
            "name": i.get("Name") or "?",
            "year": i.get("ProductionYear") or "",
            "runtime": int(ticks / 600000000) if ticks else 0,
            "genres": (i.get("Genres") or [])[:3],
            "rating": round(rating, 1) if isinstance(rating, (int, float)) else "",
            "cert": i.get("OfficialRating") or "",
            "added": (i.get("DateCreated") or "")[:10],
            "seasons": i.get("ChildCount") or 0,
            "size": human(size) if size else "",
        })
    return {"items": items, "total": d.get("TotalRecordCount") or 0,
            "start": start, "limit": limit, "server": jf_server_id()}


TODO_FILE = "/var/lib/media-dashboard/todo.json"


def load_todo():
    try:
        with open(TODO_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_todo(items):
    os.makedirs(os.path.dirname(TODO_FILE), exist_ok=True)
    tmp = TODO_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(items, f, indent=1)
    os.replace(tmp, TODO_FILE)


def todo_apply(action, payload):
    items = load_todo()
    if action == "add":
        text = (payload.get("text") or "").strip()[:300]
        if text:
            nid = max([i.get("id", 0) for i in items] or [0]) + 1
            items.append({"id": nid, "text": text, "done": False,
                          "added": time.strftime("%Y-%m-%d")})
    elif action == "toggle":
        for i in items:
            if i.get("id") == payload.get("id"):
                i["done"] = not i.get("done")
    elif action == "delete":
        items = [i for i in items if i.get("id") != payload.get("id")]
    elif action == "clear_done":
        items = [i for i in items if not i.get("done")]
    save_todo(items)
    return items


# ---------------------------------------------------------------- file ops
AUDIT_LOG = "/var/lib/media-dashboard/fileops.log"
TRASH_NAME = ".dashboard-trash"

# Only these are ever sent to a browser. Anything else is metadata-only.
IMAGE_EXT = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
             ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
             ".svg": "image/svg+xml", ".avif": "image/avif"}
TEXT_EXT = {".txt", ".log", ".nfo", ".srt", ".sub", ".vtt", ".json", ".xml",
            ".yml", ".yaml", ".conf", ".ini", ".md", ".sh", ".url", ".cfg", ".csv"}
PDF_EXT = {".pdf"}
# Camera RAW. Pillow cannot decode these, but they carry embedded JPEGs that
# exiftool can pull straight to stdout - far cheaper than demosaicing, and it
# never writes anything next to the original.
RAW_EXT = {".cr2", ".cr3", ".dng", ".nef", ".arw", ".orf", ".rw2", ".raf",
           ".pef", ".srw", ".raw", ".3fr", ".erf", ".mrw"}
# Deliberately NOT previewed: video and audio. Streaming them through the
# Cloudflare tunnel is what TOS 2.8 prohibits, and they are far too large.
MEDIA_EXT = {".mkv", ".mp4", ".avi", ".mov", ".m4v", ".wmv", ".flv", ".ts",
             ".mp3", ".flac", ".m4a", ".wav", ".ogg", ".opus"}

IMAGE_MAX = 25 * 1024 * 1024      # bytes served inline
TEXT_MAX = 256 * 1024             # bytes of text returned, then truncated


def audit(user, msg):
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{user}\t{msg}\n")
    except Exception:
        pass


def sync_note(results):
    """One line summarising what the user-sync did, for the /users banner."""
    if not results:
        return "No services are ticked for them yet - set that on User sync."
    ok = [r for r in results if r.get("ok")]
    bad = [r for r in results if not r.get("ok")]
    parts = []
    if ok:
        parts.append("Synced to " + ", ".join(sorted({r["label"] for r in ok})) + ".")
    if bad:
        parts.append("Failed: " + "; ".join(f"{r['label']} - {r['detail']}"
                                            for r in bad))
    return " ".join(parts)


def mount_of(path):
    """Walk up to the filesystem this path sits on, so trash stays on-device."""
    p = os.path.realpath(path)
    while not os.path.ismount(p) and p != "/":
        p = os.path.dirname(p)
    return p


def trash_dir_for(path):
    d = os.path.join(mount_of(path), TRASH_NAME)
    os.makedirs(d, exist_ok=True)
    return d


THUMB_DIR = "/var/lib/media-dashboard/thumbs"
THUMB_PX = 96
THUMB_SRC_MAX = 80 * 1024 * 1024   # skip absurdly large sources


def raw_embedded_jpeg(path, prefer_large=False):
    """Pull an embedded JPEG out of a camera RAW file, as bytes.

    ThumbnailImage is ~13KB and ideal for a 96px tile; PreviewImage is
    full-screen sized and used for the preview pane.
    """
    tags = (["-PreviewImage", "-JpgFromRaw", "-ThumbnailImage"] if prefer_large
            else ["-ThumbnailImage", "-PreviewImage", "-JpgFromRaw"])
    for tag in tags:
        try:
            r = subprocess.run(["exiftool", "-b", tag, path],
                               capture_output=True, timeout=20)
        except Exception:
            return None
        if r.returncode == 0 and len(r.stdout) > 1000:
            return r.stdout
    return None


def thumb_for(path):
    """Return a cached JPEG thumbnail for an image, or None.

    Cached under a hash of path+mtime+size so edits invalidate naturally.
    Uses JPEG draft mode, which lets libjpeg downscale while decoding - the
    difference between fast and unusable on a folder of 20MP photos.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    if st.st_size > THUMB_SRC_MAX:
        return None
    key = hashlib.sha256(f"{path}|{st.st_mtime_ns}|{st.st_size}".encode()).hexdigest()
    cached = os.path.join(THUMB_DIR, key + ".jpg")
    if os.path.exists(cached):
        try:
            with open(cached, "rb") as f:
                return f.read()
        except OSError:
            pass
    try:
        from PIL import Image
    except ImportError:
        return None
    src = path
    raw_bytes = None
    if preview_kind(path) == "raw":
        raw_bytes = raw_embedded_jpeg(path)
        if not raw_bytes:
            return None
        src = io.BytesIO(raw_bytes)
    try:
        with Image.open(src) as im:
            try:
                im.draft("RGB", (THUMB_PX * 2, THUMB_PX * 2))
            except Exception:
                pass
            im = im.convert("RGB")
            im.thumbnail((THUMB_PX, THUMB_PX), Image.LANCZOS)
            buf = io.BytesIO()
            im.save(buf, "JPEG", quality=78, optimize=True)
            data = buf.getvalue()
    except Exception:
        return None
    try:
        os.makedirs(THUMB_DIR, exist_ok=True)
        tmp = cached + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, cached)
    except OSError:
        pass
    return data


def preview_kind(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in IMAGE_EXT:
        return "image"
    if ext in TEXT_EXT:
        return "text"
    if ext in RAW_EXT:
        return "raw"
    if ext in PDF_EXT:
        return "pdf"
    if ext in MEDIA_EXT:
        return "media"
    return "other"


_jobs = {}          # id -> {"state","detail","src","dst"}
_job_seq = [0]
_jobs_lock = threading.Lock()


def start_copy(src, dst, user):
    with _jobs_lock:
        _job_seq[0] += 1
        jid = _job_seq[0]
        _jobs[jid] = {"id": jid, "state": "running", "detail": "",
                      "src": src, "dst": dst}

    def work():
        try:
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
            with _jobs_lock:
                _jobs[jid].update(state="done", detail="copied")
            audit(user, f"COPY OK {src} -> {dst}")
        except Exception as e:
            with _jobs_lock:
                _jobs[jid].update(state="error", detail=str(e)[:200])
            audit(user, f"COPY FAIL {src} -> {dst}: {e}")

    threading.Thread(target=work, daemon=True).start()
    return jid


def safe_path(p):
    """Resolve p and confirm it stays inside an allowed root."""
    if not p:
        return BROWSE_ROOTS[0]
    real = os.path.realpath(p)
    for root in BROWSE_ROOTS:
        if real == root or real.startswith(root + os.sep):
            return real
    return None


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

/* ===== pages served by this file only ===== */
.sec{margin:22px 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;
background:var(--bg);padding:1px 6px;border-radius:5px;border:1px solid var(--line)}
.fi{padding:7px 10px;border:1px solid var(--line);border-radius:7px;
background:var(--bg);color:var(--fg);font-size:14px;min-width:130px;max-width:100%}
.fi:focus{outline:2px solid var(--accent);outline-offset:1px}
.fb{padding:7px 13px;border:0;border-radius:7px;background:var(--accent);
color:#fff;font-weight:600;cursor:pointer;font-size:14px}
.fb.del{background:var(--card);border:1px solid var(--line);color:var(--bad)}
.warnbox{border-radius:var(--r);padding:10px 14px;margin-bottom:16px;font-size:13px;
background:color-mix(in srgb,var(--bad) 12%,transparent);
border:1px solid color-mix(in srgb,var(--bad) 40%,transparent)}
/* Inline row-forms (users page) stop overflowing once they can wrap. */
.rowform{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
@media (max-width:760px){.rowform,.rowform .fi{width:100%}.rowform .fb{flex:1}}
/* A cell whose content is a whole form needs its label above it, not beside. */
@media (max-width:760px){
table.resp td.stk{display:block}
table.resp td.stk::before{display:block;margin-bottom:4px}}
"""


FILES_CSS = """
.fm{display:grid;grid-template-columns:280px minmax(0,1fr) 0;gap:14px;align-items:start}
.fm.withprev{grid-template-columns:260px minmax(0,1fr) 380px}
@media (max-width:1100px){.fm,.fm.withprev{grid-template-columns:1fr}}
.pane{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.pane h2{margin:0;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);padding:10px 14px;border-bottom:1px solid var(--line)}
.tree{max-height:70vh;overflow:auto;padding:6px 0;font-size:14px}
.tree ul{list-style:none;margin:0;padding-left:14px}
.tree li{white-space:nowrap}
.tree .row{display:flex;align-items:center;gap:4px;padding:3px 8px;border-radius:6px;cursor:pointer}
.tree .row:hover{background:var(--bg)}
.tree .row.sel{background:var(--accent);color:#fff}
.tree .tw{width:14px;display:inline-block;text-align:center;color:var(--muted);flex:0 0 auto}
.tree .row.sel .tw{color:#fff}
.flist{max-height:70vh;overflow:auto}
.flist table{width:100%}
.flist tr.sel td{background:color-mix(in srgb,var(--accent) 14%,transparent)}
.flist tr{cursor:pointer}
.fname{display:flex;align-items:center;gap:9px;white-space:normal;overflow-wrap:anywhere}
.thumb{width:40px;height:40px;object-fit:cover;border-radius:5px;flex:0 0 auto;
background:var(--line);display:block}
.ficon{width:40px;text-align:center;flex:0 0 auto;font-size:17px;opacity:.85}
.flist td{padding-top:6px;padding-bottom:6px}
.tb{display:flex;gap:6px;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid var(--line);
align-items:center}
.tb button{padding:5px 11px;border:1px solid var(--line);border-radius:7px;background:var(--bg);
color:var(--fg);font-size:13px;cursor:pointer}
.tb button:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.tb button:disabled{opacity:.4;cursor:not-allowed}
.tb button.danger:hover:not(:disabled){border-color:var(--bad);color:var(--bad)}
.tb .crumb{font-size:13px;color:var(--muted);margin-left:auto;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:50%}
.prev{padding:12px}
.prev img{max-width:100%;border-radius:8px;display:block}
.prev pre{white-space:pre-wrap;word-break:break-word;font-size:12px;max-height:60vh;
overflow:auto;background:var(--bg);padding:10px;border-radius:8px;border:1px solid var(--line)}
.prev .meta{font-size:12px;color:var(--muted);margin-bottom:8px;word-break:break-all}
.clip{font-size:12px;color:var(--accent);padding:0 14px 10px}
.toast{position:fixed;right:18px;bottom:18px;background:var(--card);border:1px solid var(--line);
border-radius:9px;padding:10px 14px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.18);
max-width:420px;z-index:50}

/* ---- one column: the three panes stack, so the tree can no longer own 70vh
   of it. It gets a short scroller with a pinned heading, the toolbar's
   breadcrumb drops to its own line, and every row becomes tappable. ---- */
@media (max-width:760px){
/* Name + Size is all that fits; Modified goes. Targeted by position rather
   than class so the colspan status rows are not affected. */
.flist th:nth-child(3),.flist td:nth-child(3){display:none}
}
@media (max-width:1100px){
.pane h2{position:sticky;top:0;z-index:1;background:var(--card)}
.tree{max-height:min(38vh,300px)}
.flist{max-height:none}
.tb .crumb{margin-left:0;max-width:100%;flex-basis:100%;white-space:normal;
overflow-wrap:anywhere;order:-1;padding-bottom:2px}
}
/* Desktop opens folders by double-click; touch gets a real button instead. */
.opnb{display:none}
@media (pointer:coarse){
.opnb{display:grid;place-items:center;margin-left:auto;flex:0 0 auto;
width:38px;height:38px;border:1px solid var(--line);border-radius:8px;
background:var(--bg);color:var(--accent);font-size:20px;line-height:1;cursor:pointer}
.opnb:active{background:var(--accent);color:#fff;border-color:var(--accent)}
.tree{font-size:15px}
.tree .row{padding:9px 8px;gap:8px}
.tree .tw{width:34px;min-height:34px;display:inline-flex;align-items:center;
justify-content:center;margin:-9px 0 -9px -8px;font-size:15px}
.tb button{min-height:40px;padding:0 14px;font-size:14px}
.flist td{padding-top:10px;padding-bottom:10px}
.toast{left:12px;right:12px;bottom:12px;max-width:none}
}
.toast.err{border-color:var(--bad);color:var(--bad)}
"""

FILES_PAGE = """<!doctype html><meta charset="utf-8"><title>Files</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
__NAV__
<h1>Files</h1>
<div class="sub">Browse, preview and manage the media volumes.</div>
<div class="fm" id="fm">
  <div class="pane"><h2>Folders</h2><div class="tree" id="tree"></div></div>
  <div class="pane">
    <div class="tb">
      <button id="bNew"    onclick="opMkdir()">New folder</button>
      <button id="bRen"    onclick="opRename()" disabled>Rename</button>
      <button id="bCopy"   onclick="clipSet('copy')" disabled>Copy</button>
      <button id="bCut"    onclick="clipSet('cut')" disabled>Cut</button>
      <button id="bPaste"  onclick="opPaste()" disabled>Paste</button>
      <button id="bDl"     onclick="opDownload()" disabled>Download</button>
      <button id="bDel"    onclick="opDelete()" disabled class="danger">Delete</button>
      <span class="crumb" id="crumb"></span>
    </div>
    <div class="clip" id="clip"></div>
    <div class="flist" id="flist"></div>
  </div>
  <div class="pane" id="prevpane" style="display:none">
    <h2>Preview</h2><div class="prev" id="prev"></div>
  </div>
</div>
<script>
const ADMIN=__ADMIN__, ROOTS=__ROOTS__;
let CWD=__START__, SEL=null, CLIP=null;
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function toast(m,err){const t=document.createElement('div');t.className='toast'+(err?' err':'');
  t.textContent=m;document.body.appendChild(t);setTimeout(()=>t.remove(),5000);}
async function api(u){const r=await fetch(u,{cache:'no-store'});return r.json();}

/* ---------------- folder tree ---------------- */
async function treeChildren(path){
  const d=await api('/api/browse?path='+encodeURIComponent(path));
  return (d.entries||[]).filter(e=>e.dir);
}
function treeRow(name,path,open){
  return '<div class="row" data-p="'+esc(path)+'" onclick="treeClick(event,this)">'+
         '<span class="tw">'+(open?'&#9662;':'&#9656;')+'</span>'+
         '<span>&#128193; '+esc(name)+'</span></div><ul style="display:none"></ul>';
}
async function treeToggle(row){
  const li=row.parentElement, ul=li.querySelector(':scope > ul'), tw=row.querySelector('.tw');
  if(ul.style.display==='none'){
    if(!ul.dataset.loaded){
      const kids=await treeChildren(row.dataset.p);
      ul.innerHTML=kids.map(k=>'<li>'+treeRow(k.name,k.path,false)+'</li>').join('')
                  || '<li style="color:var(--muted);padding:3px 8px;font-size:12px">empty</li>';
      ul.dataset.loaded='1';
    }
    ul.style.display=''; tw.innerHTML='&#9662;';
  } else { ul.style.display='none'; tw.innerHTML='&#9656;'; }
}
function treeClick(ev,row){ treeToggle(row); go(row.dataset.p); }
async function treeInit(){
  const t=document.getElementById('tree');
  t.innerHTML='<ul>'+ROOTS.map(r=>'<li>'+treeRow(r,r,false)+'</li>').join('')+'</ul>';
}
function treeMark(){
  document.querySelectorAll('#tree .row').forEach(r=>
    r.classList.toggle('sel', r.dataset.p===CWD));
}

/* ---------------- listing ---------------- */
async function go(path){
  const d=await api('/api/browse?path='+encodeURIComponent(path));
  if(d.error){toast(d.error,true);return;}
  CWD=d.path; SEL=null; render(d); treeMark(); showPrev(null);
  history.replaceState(null,'','/files?path='+encodeURIComponent(CWD));
}
function thumbFail(img){
  const s=document.createElement('span');
  s.className='ficon'; s.innerHTML='&#128196;';
  img.replaceWith(s);
}
function render(d){
  document.getElementById('crumb').textContent=d.path;
  let h='<table><tr><th>Name</th><th style="width:100px">Size</th>'+
        '<th style="width:140px">Modified</th></tr>';
  if(d.parent) h+='<tr onclick="go('+esc(JSON.stringify(d.parent))+')"><td>&larr; up</td>'+
                  '<td></td><td></td></tr>';
  for(const e of d.entries){
    const ic = e.dir
      ? '<span class="ficon">&#128193;</span>'
      : (e.img
        ? '<img class="thumb" loading="lazy" onerror="thumbFail(this)" alt="" src="'+
          '/api/thumb?path='+encodeURIComponent(e.path)+'">'
        : '<span class="ficon">&#128196;</span>');
    const opnb = e.dir
      ? '<button class="opnb" aria-label="Open folder" onclick="event.stopPropagation();'+
        'go('+esc(JSON.stringify(e.path))+')">&#8250;</button>'
      : '';
    h+='<tr data-p="'+esc(e.path)+'" data-d="'+(e.dir?1:0)+'" data-n="'+esc(e.name)+'" '+
       'onclick="pick(this)" ondblclick="opn(this)"><td class="fname">'+
       ic+'<span>'+esc(e.name)+'</span>'+opnb+'</td>'+
       '<td class="ver">'+esc(e.size||'—')+'</td><td class="ver">'+esc(e.mtime)+'</td></tr>';
  }
  if(!d.entries.length) h+='<tr><td colspan="3" style="color:var(--muted)">empty</td></tr>';
  if(d.truncated) h+='<tr><td colspan="3" style="color:var(--muted)">truncated at 400</td></tr>';
  document.getElementById('flist').innerHTML=h+'</table>';
  buttons();
}
function pick(tr){
  document.querySelectorAll('#flist tr').forEach(r=>r.classList.remove('sel'));
  tr.classList.add('sel');
  SEL={path:tr.dataset.p,dir:tr.dataset.d==='1',name:tr.dataset.n};
  buttons();
  if(!SEL.dir) showPrev(SEL); else showPrev(null);
}
function opn(tr){ if(tr.dataset.d==='1') go(tr.dataset.p); }
function buttons(){
  const has=!!SEL;
  for(const [id,on] of [['bRen',has],['bCopy',has],['bCut',has],['bDel',has],
                        ['bPaste',!!CLIP],['bNew',true]])
    document.getElementById(id).disabled=!(on&&ADMIN);
  // Download is a read operation, so it is not admin-gated. Folders can't be downloaded.
  document.getElementById('bDl').disabled=!(has && !SEL.dir);
  document.getElementById('clip').textContent=
    CLIP?(CLIP.mode==='cut'?'Cut: ':'Copied: ')+CLIP.path+'  — open a folder and press Paste':'';
}

/* ---------------- preview ---------------- */
async function showPrev(sel){
  const pane=document.getElementById('prevpane'), box=document.getElementById('prev');
  if(!sel){pane.style.display='none';document.getElementById('fm').classList.remove('withprev');return;}
  pane.style.display=''; document.getElementById('fm').classList.add('withprev');
  box.innerHTML='<div class="meta">'+esc(sel.name)+'</div>loading…';
  const url='/api/file?path='+encodeURIComponent(sel.path);
  const r=await fetch(url,{cache:'no-store'});
  const ct=(r.headers.get('content-type')||'');
  let h='<div class="meta">'+esc(sel.path)+'</div>'+
        '<p><a href="/api/download?path='+encodeURIComponent(sel.path)+'" '+
        'download="'+esc(sel.name)+'">&#11015; Download this file</a></p>';
  if(ct.startsWith('image/')){ h+='<img src="'+url+'" alt="">'; }
  else if(ct.startsWith('text/plain')){ h+='<pre>'+esc(await r.text())+'</pre>'; }
  else if(ct.startsWith('application/pdf')){
    h+='<iframe src="'+url+'" style="width:100%;height:60vh;border:0;border-radius:8px"></iframe>'; }
  else { const j=await r.json().catch(()=>({}));
    h+='<p style="font-size:13px">'+esc(j.note||j.error||'No preview.')+'</p>'+
       (j.size?'<div class="meta">'+esc(j.size)+'</div>':''); }
  box.innerHTML=h;
}

/* ---------------- operations ---------------- */
async function post(body){
  const r=await fetch('/api/fileop',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json().catch(()=>({error:'bad response'}));
  if(j.error){toast(j.error,true);return null;}
  return j;
}
function opDownload(){
  if(!SEL||SEL.dir)return;
  const a=document.createElement('a');
  a.href='/api/download?path='+encodeURIComponent(SEL.path);
  a.download=SEL.name; document.body.appendChild(a); a.click(); a.remove();
}
function clipSet(mode){ if(!SEL)return; CLIP={mode:mode,path:SEL.path}; buttons(); }
async function opPaste(){
  if(!CLIP)return;
  const j=await post({action:CLIP.mode==='cut'?'move':'copy',src:CLIP.path,dst:CWD});
  if(!j)return;
  if(j.job){toast('Copy started in the background.');pollJobs();}
  else toast('Moved.');
  CLIP=null; go(CWD);
}
async function opRename(){
  if(!SEL)return;
  const n=prompt('New name:',SEL.name); if(!n||n===SEL.name)return;
  if(await post({action:'rename',src:SEL.path,name:n})){toast('Renamed.');go(CWD);}
}
async function opMkdir(){
  const n=prompt('New folder name:'); if(!n)return;
  if(await post({action:'mkdir',src:CWD,name:n})){toast('Folder created.');go(CWD);}
}
async function opDelete(){
  if(!SEL)return;
  if(!confirm('Move to trash?\\n\\n'+SEL.path+
              '\\n\\nIt is moved to a .dashboard-trash folder on the same disk, not erased.'))return;
  const j=await post({action:'delete',src:SEL.path});
  if(j){toast('Moved to trash.');go(CWD);}
}
async function pollJobs(){
  const d=await api('/api/jobs');
  const run=(d.jobs||[]).filter(j=>j.state==='running');
  for(const j of (d.jobs||[]).filter(j=>j.state==='error')) toast('Copy failed: '+j.detail,true);
  if(run.length){ setTimeout(pollJobs,3000); } else { go(CWD); }
}

treeInit(); go(CWD);
</script>
"""

CATALOG_CSS = """
.cbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.cbar .grow{flex:1}
.seg{display:flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.seg button{padding:6px 14px;border:0;border-right:1px solid var(--line);
background:var(--card);color:var(--fg);font:inherit;font-size:13px;font-weight:500;
cursor:pointer}
.seg button:last-child{border-right:0}
.seg button.on{background:var(--accent);color:#fff}
.csum{color:var(--muted);font-size:13px;margin:0 0 14px}
.cgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
overflow:hidden;display:flex;flex-direction:column}
.ph{position:relative;aspect-ratio:2/3;background:var(--bg);display:grid;place-items:center}
.ph .noart{font-size:26px;opacity:.35}
.ph img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:block}
.ph img.miss{display:none}
.badge{position:absolute;right:6px;top:6px;z-index:2;background:rgba(0,0,0,.72);
color:#fff;font-size:11px;font-weight:600;padding:2px 6px;border-radius:20px}
.ci{padding:8px 10px 10px;display:flex;flex-direction:column;gap:2px;min-width:0}
.cn{font-size:13px;font-weight:600;line-height:1.3;color:var(--fg);overflow-wrap:anywhere;
display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.cn:hover{color:var(--accent);text-decoration:none}
.cm{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.gpill{display:inline-block;font-size:11px;color:var(--muted);border:1px solid var(--line);
border-radius:20px;padding:0 7px;margin-right:3px}
.ctab td{white-space:nowrap}
.ctab td.t{white-space:normal;overflow-wrap:anywhere;font-weight:600}
.ctab .mini{width:32px;height:48px;object-fit:cover;border-radius:4px;background:var(--line);
display:block}
.cpg{display:flex;gap:8px;align-items:center;justify-content:center;margin:20px 0 6px;
flex-wrap:wrap}
.cpg button{padding:6px 13px;border:1px solid var(--line);border-radius:7px;
background:var(--card);color:var(--fg);font-size:13px;cursor:pointer}
.cpg button:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.cpg button:disabled{opacity:.4;cursor:not-allowed}
.cpg .pi{font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums}
.cpg input{width:66px;text-align:center}
.empty{padding:40px 22px;text-align:center;color:var(--muted);font-size:14px;
background:var(--card);border:1px solid var(--line);border-radius:10px}
.empty b{color:var(--fg)}
.spin{padding:34px;text-align:center;color:var(--muted);font-size:13px}

/* ---- phones: the filter bar goes full-width instead of squeezing six
   controls onto one line, and the list view stacks like the other tables. ---- */
@media (max-width:760px){
.cbar{gap:6px}
.cbar .grow{display:none}
#q{order:1;flex:1 1 100%;min-width:0}
#kind{order:2;flex:1 1 auto}
#view{order:3;flex:1 1 auto}
#genre{order:4;flex:1 1 46%;min-width:0}
#sort{order:5;flex:1 1 46%;min-width:0}
.seg button{flex:1}
.cgrid{grid-template-columns:repeat(auto-fill,minmax(min(132px,46%),1fr));gap:10px}
.ctab td{white-space:normal}
/* Nine columns will not fit a phone. Genres, added, rating and cert drop out;
   poster, title, year, runtime and size remain. Header cells carry the same
   classes so the columns stay aligned. */
.ctab td.g,.ctab th.g,.ctab td.a,.ctab th.a,
.ctab td.r,.ctab th.r,.ctab td.c,.ctab th.c{display:none}
.cpg button{flex:1}
}
@media (pointer:coarse){
.seg button,.cpg button{min-height:40px}
.cpg input{min-height:40px}
}
"""

CATALOG_JS = """
const PAGE = __PAGE__;
const JF = __JF__;
let ST = {kind:'movies', q:'', genre:'', sort:'name', view:'grid', page:0};
let SERVER = '', SEQ = 0, TIMER = null;

function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;',
  '>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function nf(n){return Number(n).toLocaleString();}
function hhmm(m){if(!m)return '';const h=Math.floor(m/60),r=m%60;
  return h?(h+'h '+(r?r+'m':'')).trim():r+'m';}
function link(id){return JF+'/web/#/details?id='+id+(SERVER?'&serverId='+SERVER:'');}
function posterFail(img){img.classList.add('miss');}

/* State lives in the hash so reload and the back button keep your place. */
function writeHash(){
  const p=new URLSearchParams();
  p.set('k',ST.kind);
  if(ST.q)p.set('q',ST.q);
  if(ST.genre)p.set('g',ST.genre);
  if(ST.sort!=='name')p.set('s',ST.sort);
  if(ST.view!=='grid')p.set('v',ST.view);
  if(ST.page)p.set('p',ST.page+1);
  history.replaceState(null,'','#'+p.toString());
}
const SORTS=['name','added','year','rating','runtime'];
function readHash(){
  const p=new URLSearchParams(location.hash.replace(/^#/,''));
  if(p.get('k')==='series'||p.get('k')==='movies')ST.kind=p.get('k');
  ST.q=p.get('q')||''; ST.genre=p.get('g')||'';
  ST.sort=SORTS.includes(p.get('s'))?p.get('s'):'name';
  ST.view=p.get('v')==='list'?'list':'grid';
  ST.page=Math.max(0,(parseInt(p.get('p'),10)||1)-1);
}

function syncControls(){
  document.querySelectorAll('#kind button').forEach(b=>
    b.classList.toggle('on',b.dataset.k===ST.kind));
  document.querySelectorAll('#view button').forEach(b=>
    b.classList.toggle('on',b.dataset.v===ST.view));
  document.getElementById('q').value=ST.q;
  document.getElementById('sort').value=ST.sort;
}

function setKind(k){
  if(k===ST.kind)return;
  ST.kind=k; ST.page=0; ST.genre='';
  syncControls(); loadGenres(); load();
}
function setView(v){ST.view=v; syncControls(); writeHash(); render();}
function setSort(v){ST.sort=v; ST.page=0; load();}
function setGenre(v){ST.genre=v; ST.page=0; load();}
function onSearch(v){
  ST.q=v; ST.page=0;
  clearTimeout(TIMER); TIMER=setTimeout(load,300);
}
function goto(p){
  const last=Math.max(0,Math.ceil(DATA.total/PAGE)-1);
  ST.page=Math.min(Math.max(0,p),last);
  load(); window.scrollTo({top:0,behavior:'smooth'});
}
function jump(v){const n=parseInt(v,10); if(n>0)goto(n-1);}

async function loadGenres(){
  const sel=document.getElementById('genre');
  sel.innerHTML='<option value="">All genres</option>';
  try{
    const r=await fetch('/api/catalog/genres?kind='+ST.kind,{cache:'no-store'});
    const d=await r.json();
    for(const g of d.genres||[]){
      const o=document.createElement('option');
      o.value=g; o.textContent=g;
      if(g===ST.genre)o.selected=true;
      sel.appendChild(o);
    }
  }catch(e){}
}

let DATA={items:[],total:0,start:0};

async function load(){
  const out=document.getElementById('out');
  const mine=++SEQ;
  out.innerHTML='<div class="spin">Loading\\u2026</div>';
  document.getElementById('pg').innerHTML='';
  writeHash();
  const p=new URLSearchParams({kind:ST.kind,start:ST.page*PAGE,limit:PAGE,sort:ST.sort});
  if(ST.q)p.set('search',ST.q);
  if(ST.genre)p.set('genre',ST.genre);
  let d;
  try{
    const r=await fetch('/api/catalog?'+p.toString(),{cache:'no-store'});
    d=await r.json();
  }catch(e){ d={error:'request failed'}; }
  if(mine!==SEQ)return;                       /* a newer query already won */
  if(d.error){
    document.getElementById('sum').textContent='';
    out.innerHTML='<div class="empty"><b>Jellyfin is not reachable.</b><br>'+
      esc(d.error)+'</div>';
    return;
  }
  SERVER=d.server||SERVER; DATA=d;
  render(); renderPager();
}

function render(){
  const out=document.getElementById('out');
  const noun=ST.kind==='series'?'series':'films';
  if(!DATA.items.length){
    document.getElementById('sum').textContent='';
    let why;
    if(ST.q||ST.genre){
      why='<b>Nothing matches that filter.</b><br>Try a different title or genre.';
    }else if(ST.kind==='series'){
      why='<b>No series indexed yet.</b><br>The Series library points at '+
          '<code>/srv/disks/series/TV</code> and <code>/srv/media/tv</code>, '+
          'which are both empty. Shows appear here automatically once Sonarr '+
          'imports them and Jellyfin scans.';
    }else{
      why='<b>Nothing indexed yet.</b>';
    }
    out.innerHTML='<div class="empty">'+why+'</div>';
    return;
  }
  const from=DATA.start+1, to=DATA.start+DATA.items.length;
  document.getElementById('sum').textContent =
    nf(DATA.total)+' '+noun+(ST.q||ST.genre?' matching':'')+
    '  \\u00b7  showing '+nf(from)+'\\u2013'+nf(to);
  out.innerHTML = ST.view==='grid'?grid():list();
}

function meta(it){
  const bits=[];
  if(it.year)bits.push(it.year);
  if(ST.kind==='series'){
    if(it.seasons)bits.push(it.seasons+(it.seasons>1?' seasons':' season'));
  }else if(it.runtime)bits.push(hhmm(it.runtime));
  return bits.join(' \\u00b7 ');
}

function grid(){
  let h='<div class="cgrid">';
  for(const it of DATA.items){
    const l=link(it.id);
    h+='<div class="card">'+
       '<a class="ph" href="'+l+'" target="_blank" rel="noopener" '+
         'title="Open '+esc(it.name)+' in Jellyfin">'+
         '<span class="noart">\\ud83c\\udfac</span>'+
         '<img loading="lazy" decoding="async" alt="" onerror="posterFail(this)" '+
           'src="/api/poster?id='+it.id+'">'+
         (it.rating?'<span class="badge">\\u2605 '+it.rating+'</span>':'')+
       '</a>'+
       '<div class="ci">'+
         '<a class="cn" href="'+l+'" target="_blank" rel="noopener">'+esc(it.name)+'</a>'+
         '<span class="cm">'+esc(meta(it))+'</span>'+
         (it.size?'<span class="cm">'+esc(it.size)+'</span>':'')+
       '</div></div>';
  }
  return h+'</div>';
}

function list(){
  const isS=ST.kind==='series';
  let h='<div class="tablewrap"><table class="ctab"><tr>'+
        '<th></th><th>Title</th><th>Year</th>'+
        '<th>'+(isS?'Seasons':'Runtime')+'</th>'+
        '<th class="r">Rating</th><th class="c">Cert</th><th class="g">Genres</th>'+
        (isS?'':'<th>Size</th>')+'<th class="a">Added</th></tr>';
  for(const it of DATA.items){
    const l=link(it.id);
    h+='<tr>'+
       '<td><a href="'+l+'" target="_blank" rel="noopener">'+
         '<img class="mini" loading="lazy" alt="" onerror="posterFail(this)" '+
         'src="/api/poster?id='+it.id+'"></a></td>'+
       '<td class="t"><a href="'+l+'" target="_blank" rel="noopener">'+
         esc(it.name)+'</a></td>'+
       '<td>'+esc(it.year||'\\u2014')+'</td>'+
       '<td>'+(isS?(it.seasons||'\\u2014'):(it.runtime?hhmm(it.runtime):'\\u2014'))+'</td>'+
       '<td class="r">'+(it.rating?'\\u2605 '+it.rating:'\\u2014')+'</td>'+
       '<td class="c">'+esc(it.cert||'\\u2014')+'</td>'+
       '<td class="g">'+(it.genres.length?it.genres.map(g=>
         '<span class="gpill">'+esc(g)+'</span>').join(''):'\\u2014')+'</td>'+
       (isS?'':'<td>'+esc(it.size||'\\u2014')+'</td>')+
       '<td class="a">'+esc(it.added||'\\u2014')+'</td></tr>';
  }
  return h+'</table></div>';
}

function renderPager(){
  const pages=Math.max(1,Math.ceil(DATA.total/PAGE));
  const el=document.getElementById('pg');
  if(pages<2){el.innerHTML='';return;}
  const cur=ST.page;
  el.innerHTML=
    '<button onclick="goto(0)"'+(cur?'':' disabled')+'>\\u00ab First</button>'+
    '<button onclick="goto('+(cur-1)+')"'+(cur?'':' disabled')+'>\\u2039 Prev</button>'+
    '<span class="pi">Page '+nf(cur+1)+' of '+nf(pages)+'</span>'+
    '<button onclick="goto('+(cur+1)+')"'+(cur<pages-1?'':' disabled')+'>Next \\u203a</button>'+
    '<button onclick="goto('+(pages-1)+')"'+(cur<pages-1?'':' disabled')+'>Last \\u00bb</button>'+
    '<input class="fi" type="number" min="1" max="'+pages+'" placeholder="go to" '+
      'onchange="jump(this.value)">';
}

readHash(); syncControls(); loadGenres(); load();
"""

CATALOG_PAGE = """<!doctype html><meta charset="utf-8"><title>Catalog</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
__NAV__
<h1>Catalog</h1>
<div class="sub">Everything Jellyfin has indexed &mdash; films and series.
Click any title to open it in Jellyfin.</div>
<div class="cbar">
  <div class="seg" id="kind">
    <button data-k="movies" onclick="setKind('movies')">Films</button>
    <button data-k="series" onclick="setKind('series')">Series</button>
  </div>
  <input class="fi" id="q" type="search" placeholder="Search title\u2026"
         autocomplete="off" oninput="onSearch(this.value)">
  <select class="fi" id="genre" onchange="setGenre(this.value)">
    <option value="">All genres</option>
  </select>
  <select class="fi" id="sort" onchange="setSort(this.value)">
    <option value="name">Title A&ndash;Z</option>
    <option value="added">Recently added</option>
    <option value="year">Newest first</option>
    <option value="rating">Highest rated</option>
    <option value="runtime">Longest</option>
  </select>
  <span class="grow"></span>
  <div class="seg" id="view">
    <button data-v="grid" onclick="setView('grid')">Grid</button>
    <button data-v="list" onclick="setView('list')">List</button>
  </div>
</div>
<div class="csum" id="sum"></div>
<div id="out"></div>
<div class="cpg" id="pg"></div>
<script>__JS__</script>
"""

TOPO_FILE = "/var/lib/media-dashboard/topology.json"

# ------------------------------------------------------------------ jobs
#
# This process cannot touch pct - ProtectSystem=strict leaves /run/lxc
# read-only and lxc-attach cannot take its lock. That is deliberate. Privileged
# work is only ever *described* here and carried out by media-dashboard-runner,
# which re-validates every parameter against the live host before it builds a
# command. Nothing below becomes a shell word in this process.
JOB_DIR = "/var/lib/media-dashboard/jobs"
CATALOG_APPS = "/var/lib/media-dashboard/catalog.json"

# Actions the UI may ask for. The runner enforces this list too; keeping a copy
# here just means an unknown action is refused before it is ever spooled.
JOB_ACTIONS = {"update.docker", "update.apt", "update.arr", "update.host",
               "deploy.script", "deploy.compose", "catalog.refresh",
               "service.systemd", "service.docker", "service.ct",
               "tunnel.ingress", "pkg.install", "pkg.remove", "pkg.refresh",
               "template.download"}

SOURCES_FILE = "/etc/media-dashboard/sources.json"

# A source names a GitHub repository the catalogue is built from. Adding one
# widens what an admin can deploy as root, so the shapes are checked here and
# again in the runner, and the app store shows which source an entry came from.
SRC_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,100}$")
SRC_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
SRC_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]{0,120}$")
SRC_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


def load_sources_file():
    try:
        with open(SOURCES_FILE) as f:
            d = json.load(f)
    except Exception:
        d = {}
    return {"helpers": list(d.get("helpers") or []),
            "compose": list(d.get("compose") or [])}


def save_sources_file(d):
    os.makedirs(os.path.dirname(SOURCES_FILE), exist_ok=True)
    tmp = SOURCES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2)
    shutil.move(tmp, SOURCES_FILE)

JOB_ID_OK = re.compile(r"^[0-9]{10}-[0-9a-f]{8}$")

# How each service is installed, and therefore how it is updated and how it is
# started and stopped. These used to be two hand-written tables naming every
# container, directory and unit on this host. They are now derived from what
# detection found: a compose stack updates by pulling in its own working
# directory, an *arr through its own API, anything else through apt in the
# container it lives in.
#
# The security property is unchanged and is the reason these stay lookups
# rather than becoming parameters. The browser only ever posts a service name;
# the recipe is resolved here from detected facts, so a client can never choose
# a container, a package or a directory. The runner re-validates all of it
# against the live host regardless.
#
# "note" is shown in the confirm dialog when an update is not the routine kind;
# "warn" when the blast radius of a stop is wider than the name suggests. Both
# come from the portable app table in mdash_site.
def update_recipes():
    """service name -> update recipe, for every updatable service found."""
    out = {}
    for s in site.services_list():
        r = site.update_recipe(s["name"])
        if r:
            out[s["name"]] = r
    # The host itself is not a service, but it updates like one.
    out["pve"] = {"action": "update.host", "params": {},
                  "note": "This upgrades the Proxmox host itself. It can pull in "
                          "a new kernel, and nothing here reboots for you."}
    return out


def service_control():
    """topology node id -> start/stop recipe, for every controllable service."""
    out = {}
    for s in site.services_list():
        r = site.control_recipe(s["name"])
        if r:
            out[f"svc:{s['name']}"] = r
    return out


def ct_warns():
    """Containers whose loss is worse than the name suggests."""
    out = {}
    for g in site.guests_list():
        w = site.ct_warn(g["id"])
        if w:
            out[g["id"]] = w
    return out


def enqueue(action, params, user):
    """Spool a job for the runner. Returns the new job id."""
    if action not in JOB_ACTIONS:
        raise ValueError("unknown action")
    os.makedirs(JOB_DIR, exist_ok=True)
    jid = f"{int(time.time())}-{os.urandom(4).hex()}"
    job = {"id": jid, "action": action, "params": params, "user": user,
           "created": int(time.time()), "status": "queued"}
    tmp = os.path.join(JOB_DIR, jid + ".json.tmp")
    with open(tmp, "w") as f:
        json.dump(job, f)
    # Move into place only once complete, so the runner cannot pick up a
    # half-written spool file.
    shutil.move(tmp, os.path.join(JOB_DIR, jid + ".json"))
    return jid


def job_list(limit=40):
    out = []
    try:
        names = [n for n in os.listdir(JOB_DIR) if n.endswith(".json")]
    except OSError:
        return out
    for n in sorted(names, reverse=True)[:limit]:
        try:
            with open(os.path.join(JOB_DIR, n)) as f:
                j = json.load(f)
        except Exception:
            continue
        out.append({k: j.get(k) for k in
                    ("id", "action", "params", "user", "created", "status",
                     "rc", "started", "finished", "error")})
    return out


def job_log(jid, tail=64000):
    """Last slice of a job's output. Ids are generated here and shape-checked
    on the way back in, so a well-formed id cannot escape the spool directory."""
    if not JOB_ID_OK.match(jid or ""):
        return None
    p = os.path.join(JOB_DIR, jid + ".log")
    try:
        size = os.path.getsize(p)
        with open(p, errors="replace") as f:
            if size > tail:
                f.seek(size - tail)
            return f.read()
    except OSError:
        return ""


def app_catalog():
    try:
        with open(CATALOG_APPS) as f:
            return json.load(f)
    except Exception:
        return {"fetched": 0, "apps": [], "compose": []}


STATUS_ICON_CSS = """
<style>
.ic16{width:16px;height:16px;vertical-align:-3px;margin-right:8px}
.icw{display:inline-block;position:relative;width:16px;height:16px;
vertical-align:-3px;margin-right:8px}
.icw .ic16{margin:0;position:absolute;inset:0}
.icw img{width:16px;height:16px;object-fit:contain;position:absolute;inset:0}
h2 .ic16{width:15px;height:15px;vertical-align:-2px;margin-right:7px;opacity:.9}
td .ic16{opacity:.95}
</style>
"""


def service_icon_map():
    """Service name to sprite symbol, read from the topology the collector
    already writes - so the status page and the graph cannot drift apart about
    which logo belongs to what."""
    out = {}
    try:
        with open(TOPO_FILE) as f:
            for n in json.load(f).get("nodes", []):
                nid = n.get("id") or ""
                if n.get("kind") == "service" and nid.startswith("svc:"):
                    out[nid[4:]] = n.get("icon") or "generic"
    except Exception:
        pass
    return out


def decorate_status(page):
    """Graft icons onto the generated status page.

    The collector writes plain tables with no ids, and it has no notion of the
    icon sprite the graph draws from. Rather than duplicate that sprite into
    the collector, the markup is decorated here at serve time: tables are
    matched by their first header cell, so a column being added or reordered
    upstream degrades to no icons rather than to mangled HTML.
    """
    icons = service_icon_map()

    def ico(name):
        return (f'<svg class="ic16" aria-hidden="true">'
                f'<use href="#i-{name}"></use></svg>')

    def svc_ico(label):
        """Sprite symbol if we drew one, otherwise let the wider icon set try.

        The fallback image is layered over the generic glyph and hides it only
        once it has actually loaded, so a service with no icon anywhere still
        shows a placeholder rather than a broken image.
        """
        name = icons.get(label, "generic")
        if name != "generic":
            return ico(name)
        return ('<span class="icw">' + ico("generic")
                + '<img alt="" src="/api/svcicon?name=' + quote(label)
                + '" onload="this.previousElementSibling.style.visibility=\'hidden\'"'
                  ' onerror="this.remove()"></span>')

    def fix_table(m):
        t = m.group(0)
        h = re.search(r"<th[^>]*>(.*?)</th>", t, re.S)
        first = re.sub(r"<[^>]*>", "", h.group(1)).strip() if h else ""
        if first == "Service":
            return re.sub(
                r"<tr><td><b>(.*?)</b>",
                lambda r: "<tr><td><b>"
                          + svc_ico(re.sub(r"<[^>]*>", "", r.group(1)).strip())
                          + r.group(1) + "</b>", t)
        if first == "Container":
            return re.sub(r"<tr><td>([0-9]+ )",
                          lambda r: "<tr><td>" + ico("lxc") + r.group(1), t)
        if "disk" in first.lower():
            return re.sub(r"<tr><td><b>",
                          "<tr><td><b>" + ico("disk"), t)
        return t

    page = re.sub(r"<table[^>]*>.*?</table>", fix_table, page, flags=re.S)
    page = page.replace("<h2>Host</h2>", "<h2>" + ico("proxmox") + "Host</h2>")
    page = re.sub(r"<h2>(GPU [0-9]+)</h2>",
                  lambda m: "<h2>" + ico("nvidia") + m.group(1) + "</h2>", page)
    return page


STATUS_CTL_JS = """
<style>
.sctl{display:flex;gap:5px;flex-wrap:wrap}
.sctl button{padding:4px 11px;border-radius:6px;border:1px solid var(--line);
background:var(--card);color:var(--fg);font-size:11px;font-weight:600;cursor:pointer}
.sctl button:hover{border-color:var(--accent)}
.sctl button.stop{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
@media (pointer:coarse){.sctl button{min-height:38px;padding:0 14px;font-size:13px;flex:1}}
@media (max-width:760px){table.resp td.sctlcell{display:block;margin-top:8px}
table.resp td.sctlcell::before{display:none}
/* Rows the collector offers no control for get an empty cell - collapse it,
   which the core's td:empty rule can no longer do at this specificity. */
table.resp td.sctlcell:empty{display:none}}
.smod{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;
align-items:center;justify-content:center;padding:20px;z-index:70}
.smod.on{display:flex}
.smod .b{background:var(--card);border:1px solid var(--line);border-radius:12px;
max-width:580px;width:100%;max-height:88vh;overflow:auto;padding:20px}
/* On a phone a centred dialog fights the keyboard, so it becomes a sheet
   anchored to the bottom of the screen, within thumb reach. */
@media (max-width:620px){
.smod{padding:0;align-items:flex-end}
.smod .b{border-radius:16px 16px 0 0;border-width:1px 0 0;max-height:92vh;
padding:18px 16px calc(18px + env(safe-area-inset-bottom))}
.smod .a{flex-direction:column-reverse}
.smod .a button{width:100%;min-height:44px}}
.smod h2{margin:0 0 10px;font-size:17px}
.smod .w{background:color-mix(in srgb,var(--warn) 12%,transparent);
border:1px solid color-mix(in srgb,var(--warn) 45%,transparent);border-radius:8px;
padding:11px 13px;font-size:13px;margin:12px 0;line-height:1.5}
.smod .w b{color:var(--warn)}
.smod .l{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:11px;
white-space:pre-wrap;word-break:break-word;max-height:46vh;overflow:auto;margin-top:12px}
.smod .a{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.smod .a button{padding:8px 16px;border-radius:7px;border:1px solid var(--line);
background:var(--card);color:var(--fg);font-size:13px;font-weight:500;cursor:pointer}
.smod .a button.go{background:var(--accent);color:#fff;border-color:var(--accent)}
.smod .a button.danger{background:var(--bad);color:#fff;border-color:var(--bad)}
</style>
<div class="smod" id="smod" onclick="if(event.target===this)sclose()">
  <div class="b" id="sbox"></div>
</div>
<script>
(function(){
var S=__SCTL__, SJOB=null;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

// The collector writes plain tables with no ids, so rows are matched by their
// header row instead. Anything unrecognised is simply left alone.
function tableFor(first){
  var ts=document.querySelectorAll('table');
  for(var i=0;i<ts.length;i++){
    var th=ts[i].querySelectorAll('tr th');
    if(th.length&&th[0].textContent.trim()===first)return ts[i];
  }
  return null;
}
function addCol(tbl,pick){
  if(!tbl)return;
  var rows=tbl.querySelectorAll('tr');
  for(var i=0;i<rows.length;i++){
    var r=rows[i];
    if(i===0){var h=document.createElement('th');h.textContent='';r.appendChild(h);continue;}
    var cells=r.querySelectorAll('td'); if(!cells.length)continue;
    var info=pick(cells[0].textContent.trim(),r);
    var td=document.createElement('td');
    td.className='sctlcell';
    if(info){
      var running=(r.textContent.indexOf('running')>=0)||
        (r.querySelector('.pill.ok')!==null);
      td.innerHTML='<div class="sctl">'
        +'<button onclick="__sop(\\''+info.id+'\\',\\'restart\\')">Restart</button>'
        +(running?'<button class="stop" onclick="__sop(\\''+info.id+'\\',\\'stop\\')">Stop</button>'
                 :'<button onclick="__sop(\\''+info.id+'\\',\\'start\\')">Start</button>')
        +'</div>';
    }
    r.appendChild(td);
  }
}
addCol(tableFor('Service'),function(name){
  var id='svc:'+name; return S.ctl[id]?{id:id}:null;
});
addCol(tableFor('Container'),function(name){
  var m=name.match(/^([0-9]+)/); return m?{id:'ct:'+m[1]}:null;
});

function sbox(h){document.getElementById('sbox').innerHTML=h;
  document.getElementById('smod').className='smod on';}
window.sclose=function(){document.getElementById('smod').className='smod';SJOB=null;};
window.__sop=function(id,op){
  var meta=S.ctl[id]||{};
  if(id.indexOf('ct:')===0&&S.ctwarn[id.slice(3)])meta={warn:S.ctwarn[id.slice(3)]};
  var verb=op.charAt(0).toUpperCase()+op.slice(1);
  var label=id.indexOf('ct:')===0?('container '+id.slice(3)):id.slice(4);
  var h='<h2>'+esc(verb)+' '+esc(label)+'</h2>';
  if(id.indexOf('ct:')===0)h+='<div style="font-size:13px;color:var(--muted)">'
    +'This is the whole container, so everything inside it goes with it.</div>';
  if(meta.warn)h+='<div class="w"><b>Careful.</b><br>'+esc(meta.warn)+'</div>';
  h+='<div class="a"><button onclick="sclose()">Cancel</button>'
    +'<button class="'+(op==='stop'?'danger':'go')+'" id="s-go" '
    +'onclick="__sgo(\\''+id+'\\',\\''+op+'\\')">'+esc(verb)+'</button></div>';
  sbox(h);
};
window.__sgo=function(id,op){
  var b=document.getElementById('s-go'); if(b){b.disabled=true;b.textContent='Working...';}
  fetch('/api/service',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:id,op:op})}).then(function(r){return r.json();})
    .then(function(d){
      if(d.error){document.getElementById('sbox').insertAdjacentHTML('beforeend',
        '<div class="w"><b>Refused.</b><br>'+esc(d.error)+'</div>');
        if(b){b.disabled=false;b.textContent=op;} return;}
      SJOB=d.job;
      sbox('<h2>Running</h2><div style="font-size:13px;color:var(--muted)">Job '
        +esc(d.job)+'</div><div class="l" id="sl">waiting for output...</div>'
        +'<div class="a"><button onclick="sclose();location.reload()">Close</button></div>');
      stick();
    }).catch(function(e){alert('Request failed: '+e);});
};
function stick(){
  if(!SJOB)return;
  fetch('/api/runner/joblog?id='+encodeURIComponent(SJOB))
    .then(function(r){return r.json();}).then(function(d){
      var el=document.getElementById('sl'); if(!el||!SJOB)return;
      el.textContent=d.log||'waiting for output...';
      el.scrollTop=el.scrollHeight;
      setTimeout(stick,2000);
    }).catch(function(){setTimeout(stick,4000);});
}
})();
</script>
"""

ICON_DIR = "/var/lib/media-dashboard/icons"
ICON_CDN = "https://cdn.jsdelivr.net/gh/selfhst/icons/svg"


def icon_bytes(slug):
    """SVG for a catalogue entry, fetched once and then served from disk.

    The slug is mapped to an icon name through the catalogue rather than being
    used in the URL directly, so a request can only ever reach an icon the
    runner already indexed - there is no way to point this at an arbitrary
    host. Fetching lazily keeps the catalogue refresh cheap: of 672 entries
    only the handful actually scrolled into view are ever downloaded, and they
    are then served from our own origin rather than hotlinked.
    """
    if not re.match(r"^[a-z0-9][a-z0-9._-]{0,63}$", slug or ""):
        return None
    cat = app_catalog()
    ent = next((a for a in list(cat.get("apps", [])) + list(cat.get("compose", []))
                if a.get("slug") == slug), None)
    name = (ent or {}).get("icon")
    if not name or not re.match(r"^[a-z0-9][a-z0-9._-]{0,63}$", name):
        return None
    return _icon_fetch(name)


def _icon_fetch(name):
    """Read one icon from the on-disk cache, fetching it once if absent."""
    path = os.path.join(ICON_DIR, name + ".svg")
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        pass
    try:
        os.makedirs(ICON_DIR, exist_ok=True)
        r = subprocess.run(["curl", "-sfL", "--max-time", "15",
                            f"{ICON_CDN}/{name}.svg"],
                           capture_output=True, timeout=20)
        body = r.stdout or b""
        # Guard against caching an error page as though it were artwork.
        if r.returncode != 0 or not body.lstrip()[:5].lower().startswith(b"<"):
            return None
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(body)
        shutil.move(tmp, path)
        return body
    except Exception:
        return None


def svc_icon_bytes(name):
    """Icon for a service the hand-drawn sprite does not cover.

    Services are discovered rather than declared, so new ones keep appearing
    and hand-drawing a symbol for each does not scale. The name is normalised
    and then checked against the indexed icon set before anything is fetched,
    so this can only ever resolve to an icon that was already known to exist.
    """
    n = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    if not n or len(n) > 64:
        return None
    try:
        with open("/var/lib/media-dashboard/icons.json") as f:
            have = set(json.load(f).get("icons", []))
    except Exception:
        return None
    for cand in (n, n.replace("-", ""), n + "-home"):
        if cand in have:
            return _icon_fetch(cand)
    return None


def deploy_targets():
    """Containers that can take a compose stack, as published by the runner."""
    try:
        with open("/var/lib/media-dashboard/hosts.json") as f:
            return json.load(f).get("hosts", [])
    except Exception:
        return []


def host_capacity():
    """Free RAM and per-storage free space, as measured by the runner.

    Deliberately not measured here: pvesh/pvesm shell out to the LVM tools,
    which cannot take their locks under ProtectSystem=strict, so asking this
    process silently dropped every lvmthin pool from the answer and made the
    app store think there was 52GB free instead of 158GB. Memory is read
    locally because /proc is always legible.
    """
    free_mb, store = 0, {}
    try:
        with open("/var/lib/media-dashboard/hosts.json") as f:
            cap = json.load(f).get("capacity") or {}
        free_mb = cap.get("ram_mb", 0)
        store = cap.get("storage", {})
    except Exception:
        pass
    try:
        r = subprocess.run(["free", "-m"], capture_output=True, text=True,
                           timeout=10)
        for line in r.stdout.splitlines():
            if line.startswith("Mem:"):
                free_mb = int(line.split()[6])   # fresher than the hourly sweep
    except Exception:
        pass
    return {"ram_mb": free_mb, "storage": store}


APPSTORE_CSS = """
.tabs{display:flex;gap:6px;margin:0 0 14px;flex-wrap:wrap}
.tabs button{padding:6px 14px;border-radius:7px;border:1px solid var(--line);
background:var(--card);color:var(--fg);font-size:13px;font-weight:500;cursor:pointer}
.tabs button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.cap{display:flex;gap:16px;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:12px 14px;margin-bottom:14px;font-size:13px}
.cap b{font-weight:600}
.cap .low{color:var(--warn)}
.tools{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.tools input,.tools select{padding:7px 11px;border-radius:7px;border:1px solid var(--line);
background:var(--card);color:var(--fg);font-size:13px}
.tools input{flex:1;min-width:220px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px}
.app{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;
cursor:pointer;transition:border-color .12s;display:flex;gap:11px;align-items:flex-start}
.app:hover{border-color:var(--accent)}
.app .txt{min-width:0;flex:1}
/* The initial sits behind the image and is hidden once it loads, so an app
   with no published icon still gets a tile instead of a broken-image box. */
.ico{width:38px;height:38px;border-radius:9px;background:var(--bg);
border:1px solid var(--line);flex:0 0 38px;position:relative;overflow:hidden;
display:flex;align-items:center;justify-content:center;
font-weight:700;font-size:15px;color:var(--muted)}
.ico.has{color:transparent}
.ico img{width:100%;height:100%;object-fit:contain;padding:6px;position:absolute;inset:0}
.obig{display:flex;gap:13px;align-items:center;margin-bottom:4px}
.obig .ico{width:46px;height:46px;flex:0 0 46px;font-size:18px}
.app h3{margin:0 0 3px;font-size:14px;font-weight:600;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.app .res{color:var(--muted);font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.app .bl{color:var(--muted);font-size:12px;margin-top:6px;
display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.app .tg{margin-top:7px;display:flex;gap:4px;flex-wrap:wrap}
.app .tg span{font-size:10px;padding:1px 7px;border-radius:20px;background:var(--bg);
border:1px solid var(--line);color:var(--muted)}
.app.no{opacity:.5}
.more{text-align:center;color:var(--muted);font-size:13px;padding:14px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;
align-items:center;justify-content:center;padding:20px;z-index:50}
.modal.on{display:flex}
.box{background:var(--card);border:1px solid var(--line);border-radius:12px;
max-width:620px;width:100%;max-height:90vh;overflow:auto;padding:20px}
.box h2{margin:0 0 4px;font-size:17px}
.box .src{color:var(--muted);font-size:12px;margin-bottom:14px;word-break:break-all}
.warn-box{background:color-mix(in srgb,var(--warn) 12%,transparent);
border:1px solid color-mix(in srgb,var(--warn) 45%,transparent);
border-radius:8px;padding:11px 13px;font-size:13px;margin:14px 0;line-height:1.5}
.warn-box b{color:var(--warn)}
.flds{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:14px 0}
.flds label{font-size:12px;color:var(--muted);display:block;margin-bottom:3px}
.flds input,.flds select{width:100%;padding:7px 10px;border-radius:7px;
border:1px solid var(--line);background:var(--bg);color:var(--fg);font-size:13px}
.acts{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.btn{padding:8px 16px;border-radius:7px;border:1px solid var(--line);background:var(--card);
color:var(--fg);font-size:13px;font-weight:500;cursor:pointer}
.btn.go{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn.danger{background:var(--bad);color:#fff;border-color:var(--bad)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.jl{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:11px;
white-space:pre-wrap;word-break:break-word;max-height:52vh;overflow:auto;margin-top:12px}
.jrow{display:flex;gap:10px;align-items:center;padding:9px 13px;border-bottom:1px solid var(--line);
font-size:13px;cursor:pointer}
.jrow:last-child{border-bottom:none}
.jrow:hover{background:var(--bg)}
.jrow .who{color:var(--muted);font-size:12px}
.jrow .sp{flex:1}
.st{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600}
.st.queued{background:var(--bg);color:var(--muted);border:1px solid var(--line)}
.st.running{background:color-mix(in srgb,var(--accent) 16%,transparent);color:var(--accent)}
.st.done{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
.st.failed{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}
.empty{color:var(--muted);font-size:13px;padding:22px;text-align:center}

/* ---- phones: the deploy dialog becomes a bottom sheet, its actions stack
   full-width, and the search box stops forcing a 220px minimum. ---- */
@media (max-width:760px){
/* Stacked Sources rows: the buttons get their own full-width row underneath,
   and built-in sources (which have no buttons) collapse the cell away. */
table.resp td.srcacts{display:flex;gap:8px;margin-top:9px}
table.resp td.srcacts::before{display:none}
table.resp td.srcacts:empty{display:none}
table.resp td.srcacts .btn{flex:1}
.tabs{flex-wrap:nowrap;overflow-x:auto;overscroll-behavior-x:contain;
scrollbar-width:none;-ms-overflow-style:none;padding-bottom:2px}
.tabs::-webkit-scrollbar{display:none}
.tabs button{flex:0 0 auto;white-space:nowrap}
.cap{gap:8px 14px;font-size:12px;padding:10px 12px}
}
@media (max-width:620px){
.modal{padding:0;align-items:flex-end}
.box{border-radius:16px 16px 0 0;border-width:1px 0 0;max-height:92vh;
padding:18px 16px calc(18px + env(safe-area-inset-bottom))}
.acts{flex-direction:column-reverse}
.acts .btn{width:100%;min-height:44px}
.tools input{min-width:0;flex-basis:100%}
.tools select{flex:1}
.grid{grid-template-columns:1fr}
.flds{grid-template-columns:1fr 1fr}
}
@media (pointer:coarse){
.tabs button{min-height:40px}
.jrow{padding:13px}
}
"""

APPSTORE_PAGE = """<!doctype html><meta charset="utf-8"><title>App store</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
__NAV__
<h1>App store</h1>
<div class="sub" id="sub">Loading catalogue...</div>
<div class="cap" id="cap"></div>
<div class="tabs">
  <button id="t-ct" class="on" onclick="tab('ct')">LXC containers</button>
  <button id="t-vm" onclick="tab('vm')">Virtual machines</button>
  <button id="t-host" onclick="tab('host')">Host tools</button>
  <button id="t-compose" onclick="tab('compose')">Docker stacks</button>
  <button id="t-pkg" onclick="tab('pkg')">Packages</button>
  <button id="t-addons" onclick="tab('addons')">Dashboards</button>
  <button id="t-jobs" onclick="tab('jobs')">Activity</button>
  <button id="t-src" onclick="tab('src')">Sources</button>
</div>
<div id="browse">
  <div class="tools">
    <input id="q" placeholder="Search applications..." oninput="render()">
    <select id="tag" onchange="render()"><option value="">All categories</option></select>
    <select id="fit" onchange="render()">
      <option value="">Show all</option>
      <option value="1">Only what fits</option>
    </select>
  </div>
  <div class="grid" id="grid"></div>
  <div class="more" id="more"></div>
</div>
<div id="pkg" style="display:none">__PKG_PANEL__</div>
<div id="addons" style="display:none">__ADDON_PANEL__</div>
<div id="jobs" style="display:none">
  <div class="tablewrap" id="jobwrap"></div>
</div>
<div id="src" style="display:none">
  <div class="tablewrap" id="srcwrap"></div>
  <div class="warn-box" style="margin-top:14px"><b>Anything you add here can be
  installed as root.</b><br>A helper-script source is a GitHub repository whose
  shell scripts this dashboard will download and execute with full privileges on
  the Proxmox host. Add repositories you would be willing to pipe into a root
  shell yourself, because that is what deploying from one does.</div>
  <h3 style="font-size:13px;margin:16px 0 8px">Add a source</h3>
  <div class="tools" style="align-items:flex-end">
    <div><label style="font-size:12px;color:var(--muted);display:block">Type</label>
      <select id="s-kind" onchange="srcKind()">
        <option value="compose">Docker stacks</option>
        <option value="helpers">Helper scripts</option>
      </select></div>
    <div style="flex:1;min-width:200px">
      <label style="font-size:12px;color:var(--muted);display:block">Repository</label>
      <input id="s-repo" placeholder="owner/name or a GitHub URL" style="width:100%"></div>
    <div><label style="font-size:12px;color:var(--muted);display:block">Branch</label>
      <input id="s-ref" placeholder="main" style="width:110px"></div>
    <div id="s-pathwrap"><label style="font-size:12px;color:var(--muted);display:block">
      Sub-folder</label>
      <input id="s-path" placeholder="(repo root)" style="width:140px"></div>
    <div id="s-dirswrap" style="display:none">
      <label style="font-size:12px;color:var(--muted);display:block">Script folders</label>
      <input id="s-dirs" placeholder="ct,vm" style="width:140px"></div>
    <button class="btn go" onclick="srcAdd()">Add source</button>
  </div>
  <div id="s-msg"></div>
</div>
<div class="modal" id="modal" onclick="if(event.target===this)close_()">
  <div class="box" id="box"></div>
</div>
<script>
var CAT={apps:[],compose:[],hosts:[],capacity:{ram_mb:0,storage:{}}};
var TAB='ct', SHOWN=90, CUR=null, POLL=null, LOGJOB=null;
var TABS=['ct','vm','host','compose','pkg','addons','jobs','src'];
// Tabs that are a panel of their own rather than a view of the catalogue grid.
var PANELS={pkg:1,addons:1,jobs:1,src:1};

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

function fits(a){
  var c=CAT.capacity||{}, st=c.storage||{};
  var best=0; for(var k in st){if(st[k]>best)best=st[k];}
  return (a.ram||0)<=(c.ram_mb||0) && (a.disk||0)<=best;
}

function tab(t){
  TAB=t; SHOWN=90;
  TABS.forEach(function(x){
    document.getElementById('t-'+x).className = (x===t?'on':'');
  });
  document.getElementById('browse').style.display = (PANELS[t]?'none':'');
  for(var p in PANELS){
    document.getElementById(p).style.display = (p===t?'':'none');
  }
  if(t==='jobs')loadJobs();
  else if(t==='src')renderSrc();
  else if(t==='pkg')PKG.show();
  else if(t==='addons')ADDONS.show();
  else render();
}

function srcKind(){
  var h=document.getElementById('s-kind').value==='helpers';
  document.getElementById('s-dirswrap').style.display = h?'':'none';
  document.getElementById('s-pathwrap').style.display = h?'none':'';
}

function renderSrc(){
  var rows=CAT.sources||[], s='';
  if(!rows.length){
    document.getElementById('srcwrap').innerHTML=
      '<div class="empty">No catalogue sources reported yet.</div>';
    return;
  }
  s='<table class="resp"><tr class="hd"><th>Source</th><th>Kind</th>'
   +'<th>Repository</th><th>Entries</th><th>State</th><th></th></tr>';
  rows.forEach(function(r){
    var st = !r.enabled ? '<span class="st queued">disabled</span>'
      : (r.ok===false ? '<span class="st failed">fetch failed</span>'
                      : '<span class="st done">ok</span>');
    s+='<tr><td>'+esc(r.name||r.id)+(r.builtin?' <span class="who" '
      +'style="color:var(--muted);font-size:11px">built in</span>':'')+'</td>'
      +'<td data-label="Kind">'+(r.kind==='helpers'?'Helper scripts':'Docker stacks')+'</td>'
      +'<td class="ver" data-label="Repository">'+esc(r.repo||'-')
      +(r.ref?'@'+esc(r.ref):'')+'</td>'
      +'<td data-label="Entries">'+(r.count||0)+'</td>'
      +'<td data-label="State">'+st+'</td><td class="srcacts">';
    if(!r.builtin){
      s+='<button class="btn" onclick="srcOp(\\'toggle\\','+esc(JSON.stringify(r.id))
        +')">'+(r.enabled?'Disable':'Enable')+'</button> '
        +'<button class="btn" onclick="srcOp(\\'remove\\','+esc(JSON.stringify(r.id))
        +')">Remove</button>';
    }
    s+='</td></tr>';
  });
  s+='</table>';
  document.getElementById('srcwrap').innerHTML=s;
}

function srcMsg(html){document.getElementById('s-msg').innerHTML=html;}

function srcPost(body,okmsg){
  srcMsg('<div class="more">Working...</div>');
  fetch('/api/sources',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)}).then(function(r){return r.json();}).then(function(d){
      if(d.error){srcMsg('<div class="warn-box"><b>Refused.</b><br>'
        +esc(d.error)+'</div>');return;}
      srcMsg('<div class="more">'+esc(okmsg)+' Rebuilding the catalogue...</div>');
      // The rebuild runs as a job; watch it, then reload so counts are real.
      LOGJOB=d.job; showLog(d.job);
      var poll=setInterval(function(){
        fetch('/api/runner/jobs').then(function(r){return r.json();}).then(function(j){
          var me=(j.jobs||[]).filter(function(x){return x.id===d.job;})[0];
          if(me&&(me.status==='done'||me.status==='failed')){
            clearInterval(poll); load();
          }
        });
      },2500);
    }).catch(function(e){srcMsg('<div class="warn-box">Request failed: '
      +esc(e)+'</div>');});
}

function srcAdd(){
  var kind=document.getElementById('s-kind').value;
  var body={action:'add',kind:kind,
            repo:document.getElementById('s-repo').value,
            ref:document.getElementById('s-ref').value};
  if(kind==='helpers')body.dirs=document.getElementById('s-dirs').value||'ct';
  else body.path=document.getElementById('s-path').value;
  if(!body.repo){srcMsg('<div class="warn-box">Enter a repository first.</div>');return;}
  srcPost(body,'Source added.');
}

function srcOp(act,id){
  if(act==='remove'&&!confirm('Remove this source? Anything it contributed '
    +'disappears from the catalogue.'))return;
  srcPost({action:act,id:id},act==='remove'?'Source removed.':'Source updated.');
}

// Icon tile: the initial shows immediately, the real artwork covers it if the
// project publishes one. 429 of the 672 catalogue entries have an icon.
function tile(a,big){
  var init=(a.name||a.slug||'?').replace(/[^A-Za-z0-9]/g,'').charAt(0).toUpperCase()||'?';
  var s='<div class="ico">'+esc(init);
  if(a.icon)s+='<img loading="lazy" alt="" src="/api/appicon?slug='
    +encodeURIComponent(a.slug)+'" onload="this.parentNode.className=\\'ico has\\'"'
    +' onerror="this.remove()">';
  return s+'</div>';
}

function curList(){
  if(TAB==='compose')return CAT.compose||[];
  return (CAT.apps||[]).filter(function(a){return a.target===TAB;});
}

function render(){
  var q=(document.getElementById('q').value||'').toLowerCase();
  var tg=document.getElementById('tag').value;
  var onlyfit=document.getElementById('fit').value==='1';
  var list = curList();
  var out=list.filter(function(a){
    if(q && (a.name||'').toLowerCase().indexOf(q)<0 &&
            (a.slug||'').toLowerCase().indexOf(q)<0 &&
            (a.blurb||'').toLowerCase().indexOf(q)<0) return false;
    if(tg && (a.tags||[]).indexOf(tg)<0) return false;
    if(onlyfit && TAB==='ct' && !fits(a)) return false;
    return true;
  });
  var g=document.getElementById('grid'), s='';
  out.slice(0,SHOWN).forEach(function(a,i){
    var ok = TAB!=='ct' || fits(a);
    s+='<div class="app'+(ok?'':' no')+'" onclick="open_('+esc(JSON.stringify(a.slug))+')">';
    s+=tile(a);
    s+='<div class="txt"><h3>'+esc(a.name)+'</h3>';
    if(TAB==='ct'){
      s+='<div class="res">'+a.cpu+' vCPU &middot; '+a.ram+' MB &middot; '+a.disk+' GB &middot; '
        +esc(a.os)+' '+esc(a.os_version||'')+'</div>';
      if(!ok)s+='<div class="bl">Not enough free memory or disk for this right now.</div>';
    }else if(TAB==='compose'){
      s+='<div class="res">port '+esc(a.port)+'</div>';
      s+='<div class="bl">'+esc(a.blurb||'')+'</div>';
    }else{
      s+='<div class="res">'+esc(a.kindlabel||'')+'</div>';
      s+='<div class="bl">Runs interactively - opens with the command to paste.</div>';
    }
    if((a.tags||[]).length){
      s+='<div class="tg">'+a.tags.slice(0,3).map(function(t){
        return '<span>'+esc(t)+'</span>';}).join('')+'</div>';
    }
    s+='</div></div>';
  });
  g.innerHTML = s || '<div class="empty">Nothing matches that search.</div>';
  document.getElementById('more').innerHTML =
    out.length>SHOWN ? '<button class="btn" onclick="SHOWN+=90;render()">Show more ('
      +(out.length-SHOWN)+' left)</button>' : '';
}

function open_(slug){
  var list = curList();
  var a=null; for(var i=0;i<list.length;i++){if(list[i].slug===slug){a=list[i];break;}}
  if(!a)return;
  CUR=a;
  var s='<div class="obig">'+tile(a)+'<h2 style="margin:0">'+esc(a.name)+'</h2></div>';

  // vm/ and tools/ scripts are whiptail wizards with no unattended mode, so
  // there is no honest one-click here. Hand over the exact command instead of
  // starting a job that would sit on a menu until it timed out.
  if(TAB==='vm'||TAB==='host'){
    var cmd='bash -c "$(curl -fsSL https://raw.githubusercontent.com/'
      +'community-scripts/ProxmoxVE/'+(CAT.commit||'main')+'/'+(a.path||'')+')"';
    s+='<div class="src">'+esc(a.kindlabel||'')
      +(a.source?' &middot; <a href="'+esc(a.source)+'" target="_blank" rel="noopener">'
      +esc(a.source)+'</a>':'')+'</div>';
    s+='<div class="warn-box"><b>This one has to be run by hand.</b><br>'
      +'Unlike the LXC scripts, '+esc(a.name)+' asks questions through an '
      +'interactive menu and has no unattended mode. Deploying it from here would '
      +'just hang waiting for an answer, so the dashboard will not pretend to do it. '
      +'Run this on the Proxmox host instead:</div>';
    s+='<div class="jl" style="max-height:none">'+esc(cmd)+'</div>';
    s+='<div class="acts"><button class="btn" onclick="close_()">Close</button>'
      +'<button class="btn go" onclick="copyCmd('+esc(JSON.stringify(cmd))
      +',this)">Copy command</button></div>';
    document.getElementById('box').innerHTML=s;
    document.getElementById('modal').className='modal on';
    return;
  }

  if(TAB==='ct'){
    s+='<div class="src">'+(a.source?'<a href="'+esc(a.source)+'" target="_blank" rel="noopener">'
      +esc(a.source)+'</a>':'')+'</div>';
    s+='<div class="warn-box"><b>This runs a script from the internet as root '
      +'on your Proxmox host.</b><br>The dashboard downloads <code>'+esc(a.path||'')
      +'</code> from <code>'+esc(a.repo||'')+'</code>'
      +(a.ref?' at commit <code>'+esc(String(a.ref).slice(0,12))+'</code>':'')
      +' and executes it with full privileges. It will create a container, install '
      +'packages and change host state. Only continue if you trust '
      +esc(a.srcname||'that source')+'.</div>';
    if(!fits(a)){
      s+='<div class="warn-box"><b>Not enough free capacity.</b><br>This asks for '
        +a.ram+' MB RAM and '+a.disk+' GB disk. The deploy will be refused before '
        +'anything is created.</div>';
    }
    s+='<div class="flds">'
      +'<div><label>Container ID</label><input id="f-ctid" placeholder="next free"></div>'
      +'<div><label>Hostname</label><input id="f-host" placeholder="'+esc(a.slug)+'"></div>'
      +'<div><label>vCPU</label><input id="f-cpu" value="'+a.cpu+'"></div>'
      +'<div><label>RAM (MB)</label><input id="f-ram" value="'+a.ram+'"></div>'
      +'<div><label>Disk (GB)</label><input id="f-disk" value="'+a.disk+'"></div>'
      +'</div>';
  }else{
    s+='<div class="src">Deploys a docker compose stack into an existing container.</div>';
    s+='<div class="bl" style="font-size:13px;color:var(--muted)">'+esc(a.blurb||'')+'</div>';
    var hosts=(CAT.hosts||[]).filter(function(h){return h.docker;});
    if(!hosts.length){
      s+='<div class="warn-box">No container on this host has docker installed, '
        +'so there is nowhere to put this stack.</div>';
    }else{
      s+='<div class="flds"><div style="grid-column:1/-1"><label>Deploy into</label>'
        +'<select id="f-cid">'+hosts.map(function(h){
          return '<option value="'+h.cid+'">'+h.cid+' &mdash; '+esc(h.name)+'</option>';
        }).join('')+'</select></div></div>';
      s+='<div class="warn-box">The stack is written to <code>/opt/'+esc(a.slug)
        +'</code> inside that container and started with '
        +'<code>docker compose up -d</code>. Port '+esc(a.port)
        +' must be free there.</div>';
    }
  }
  s+='<div class="acts"><button class="btn" onclick="close_()">Cancel</button>'
    +'<button class="btn go" id="f-go" onclick="go()">Deploy</button></div>';
  document.getElementById('box').innerHTML=s;
  document.getElementById('modal').className='modal on';
}

function close_(){document.getElementById('modal').className='modal';CUR=null;LOGJOB=null;}

// clipboard.writeText needs a secure context. Reached over the tunnel that is
// fine, but on plain http across the LAN it is not, hence the textarea path.
function copyCmd(cmd,btn){
  function done(){btn.textContent='Copied';setTimeout(function(){
    btn.textContent='Copy command';},1600);}
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(cmd).then(done).catch(function(){fallback();});
  }else{fallback();}
  function fallback(){
    var t=document.createElement('textarea');
    t.value=cmd; t.style.position='fixed'; t.style.opacity='0';
    document.body.appendChild(t); t.select();
    try{document.execCommand('copy');done();}catch(e){btn.textContent='Copy failed';}
    document.body.removeChild(t);
  }
}

function go(){
  if(!CUR)return;
  var btn=document.getElementById('f-go'); btn.disabled=true; btn.textContent='Starting...';
  var body;
  if(TAB==='ct'){
    body={kind:'script',slug:CUR.slug};
    var m={ctid:'f-ctid',cpu:'f-cpu',ram:'f-ram',disk:'f-disk'};
    for(var k in m){var v=(document.getElementById(m[k]).value||'').trim(); if(v)body[k]=v;}
    var h=(document.getElementById('f-host').value||'').trim(); if(h)body.hostname=h;
  }else{
    var sel=document.getElementById('f-cid');
    if(!sel){btn.disabled=false;btn.textContent='Deploy';return;}
    body={kind:'compose',slug:CUR.slug,cid:sel.value};
  }
  fetch('/api/deploy',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)}).then(function(r){return r.json();}).then(function(d){
      if(d.error){
        btn.disabled=false; btn.textContent='Deploy';
        document.getElementById('box').insertAdjacentHTML('beforeend',
          '<div class="warn-box"><b>Refused.</b><br>'+esc(d.error)+'</div>');
        return;
      }
      watch(d.job);
    }).catch(function(e){
      btn.disabled=false; btn.textContent='Deploy';
      alert('Request failed: '+e);
    });
}

function watch(jid){
  LOGJOB=jid;
  document.getElementById('box').innerHTML='<h2>Running</h2>'
    +'<div class="src">Job '+esc(jid)+' &mdash; this can take several minutes. '
    +'Closing this window does not stop it.</div>'
    +'<div class="jl" id="jl">waiting for output...</div>'
    +'<div class="acts"><button class="btn" onclick="close_();loadJobs();tab(\\'jobs\\')">'
    +'Close</button></div>';
  document.getElementById('modal').className='modal on';
  tick();
}

function tick(){
  if(!LOGJOB)return;
  fetch('/api/runner/joblog?id='+encodeURIComponent(LOGJOB))
    .then(function(r){return r.json();}).then(function(d){
      var el=document.getElementById('jl'); if(!el||!LOGJOB)return;
      var atEnd = el.scrollTop+el.clientHeight >= el.scrollHeight-30;
      el.textContent = d.log || 'waiting for output...';
      if(atEnd) el.scrollTop = el.scrollHeight;
      setTimeout(tick,2000);
    }).catch(function(){setTimeout(tick,4000);});
}

function loadJobs(){
  fetch('/api/runner/jobs').then(function(r){return r.json();}).then(function(d){
    var s='', js=d.jobs||[];
    if(!js.length){
      document.getElementById('jobwrap').innerHTML =
        '<div class="empty">Nothing has been run yet.</div>';
      return;
    }
    js.forEach(function(j){
      var when = j.created ? new Date(j.created*1000).toLocaleString() : '';
      var what = (j.params&&(j.params.slug||j.params.pkg||j.params.app||j.params.dir))||'';
      s+='<div class="jrow" onclick="showLog('+esc(JSON.stringify(j.id))+')">'
        +'<span class="st '+esc(j.status)+'">'+esc(j.status)+'</span>'
        +'<span>'+esc(j.action)+(what?' <span class="who">'+esc(what)+'</span>':'')+'</span>'
        +'<span class="sp"></span>'
        +'<span class="who">'+esc(j.user||'')+' &middot; '+esc(when)+'</span></div>';
    });
    document.getElementById('jobwrap').innerHTML=s;
  });
}

function showLog(jid){
  LOGJOB=jid;
  document.getElementById('box').innerHTML='<h2>Job output</h2>'
    +'<div class="src">'+esc(jid)+'</div><div class="jl" id="jl">loading...</div>'
    +'<div class="acts"><button class="btn" onclick="close_()">Close</button></div>';
  document.getElementById('modal').className='modal on';
  tick();
}

function load(){
  fetch('/api/appstore').then(function(r){return r.json();}).then(function(d){
    if(d.error){document.getElementById('sub').textContent=d.error;return;}
    CAT=d;
    var when = d.fetched ? new Date(d.fetched*1000).toLocaleString() : 'never';
    document.getElementById('sub').textContent =
      d.apps.length+' container templates, '+d.compose.length+' docker stacks'
      +' - catalogue refreshed '+when
      +(d.commit?' at '+d.commit.slice(0,7):'');
    var c=d.capacity||{}, st=c.storage||{}, parts=[];
    var lowmem = (c.ram_mb||0) < 2048;
    parts.push('<span'+(lowmem?' class="low"':'')+'>Free memory <b>'
      +Math.round((c.ram_mb||0)/1024*10)/10+' GB</b></span>');
    for(var k in st){
      parts.push('<span>'+esc(k)+' <b>'+st[k]+' GB</b> free</span>');
    }
    var dh=(d.hosts||[]).filter(function(h){return h.docker;}).length;
    parts.push('<span>'+dh+' docker-capable containers</span>');
    document.getElementById('cap').innerHTML=parts.join('');
    var tags={};
    d.apps.forEach(function(a){(a.tags||[]).forEach(function(t){tags[t]=1;});});
    var sel=document.getElementById('tag');
    Object.keys(tags).sort().forEach(function(t){
      var o=document.createElement('option'); o.value=t; o.textContent=t; sel.appendChild(o);
    });
    render();
  });
}
load();
</script>
"""

TOPO_CSS = """
.ops{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0 2px}
.ops button{padding:5px 12px;border-radius:7px;border:1px solid var(--line);
background:var(--card);color:var(--fg);font-size:12px;font-weight:600;cursor:pointer}
.ops button:hover{border-color:var(--accent)}
.ops button.go{background:var(--accent);color:#fff;border-color:var(--accent)}
.ops button.stop{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
.ops button:disabled{opacity:.45;cursor:not-allowed}
.omodal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;
align-items:center;justify-content:center;padding:20px;z-index:60}
.omodal.on{display:flex}
.obox{background:var(--card);border:1px solid var(--line);border-radius:12px;
max-width:600px;width:100%;max-height:88vh;overflow:auto;padding:20px}
.obox h2{margin:0 0 10px;font-size:17px}
.obox .wb{background:color-mix(in srgb,var(--warn) 12%,transparent);
border:1px solid color-mix(in srgb,var(--warn) 45%,transparent);border-radius:8px;
padding:11px 13px;font-size:13px;margin:12px 0;line-height:1.5}
.obox .wb b{color:var(--warn)}
.obox .ol{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:11px;
white-space:pre-wrap;word-break:break-word;max-height:46vh;overflow:auto;margin-top:12px}
.obox .oa{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.obox .oa button{padding:8px 16px;border-radius:7px;border:1px solid var(--line);
background:var(--card);color:var(--fg);font-size:13px;font-weight:500;cursor:pointer}
.obox .oa button.go{background:var(--accent);color:#fff;border-color:var(--accent)}
.obox .oa button.danger{background:var(--bad);color:#fff;border-color:var(--bad)}
.obox .oa button:disabled{opacity:.5;cursor:not-allowed}
.tp{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:14px;align-items:start}
@media (max-width:1100px){.tp{grid-template-columns:1fr}}
.pane{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.pane h2{margin:0;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);padding:10px 14px;border-bottom:1px solid var(--line)}
.tb{display:flex;gap:6px;flex-wrap:wrap;padding:9px 14px;border-bottom:1px solid var(--line);
align-items:center}
.tb button{padding:5px 11px;border:1px solid var(--line);border-radius:7px;background:var(--bg);
color:var(--fg);font-size:13px;cursor:pointer}
.tb button:hover{border-color:var(--accent);color:var(--accent)}
.tb label{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);
cursor:pointer;padding:3px 8px;border:1px solid var(--line);border-radius:20px}
.tb label:hover{border-color:var(--accent)}
.tb label input{margin:0;accent-color:var(--accent)}
.tb .sp{flex:1}
#svgwrap{height:72vh;min-height:460px;background:var(--bg);overflow:hidden;position:relative}
#g{width:100%;height:100%;display:block;cursor:grab;touch-action:none}
#g.drag{cursor:grabbing}
.nlabel{font:600 12.5px ui-sans-serif,system-ui,sans-serif;fill:var(--fg)}
.nsub{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;fill:var(--muted)}
.nsub.upd{fill:var(--warn);font-weight:600}
.blabel{font:700 12.5px ui-sans-serif,system-ui,sans-serif;fill:var(--fg)}
.elabel{font:10px ui-sans-serif,system-ui,sans-serif;fill:var(--muted)}
.zlabel{font:600 10.5px ui-sans-serif,system-ui,sans-serif;fill:var(--muted);
letter-spacing:.09em;text-transform:uppercase}
.hit{cursor:pointer}
.dim{opacity:.14}
.det{padding:12px 14px;font-size:13px;max-height:34vh;overflow:auto}
.det .kv{display:flex;justify-content:space-between;gap:10px;padding:4px 0;
border-bottom:1px solid var(--line)}
.det .kv:last-child{border-bottom:none}
.det .kv b{color:var(--muted);font-weight:500;flex:0 0 auto}
.det .kv span{text-align:right;overflow-wrap:anywhere;
font-family:ui-monospace,Menlo,monospace;font-size:12px}
.det .empty{color:var(--muted);font-size:12.5px}
.det h3{margin:0 0 10px;font-size:14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.iss{padding:10px 14px;font-size:12.5px;max-height:28vh;overflow:auto}
.iss div{padding:6px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.iss div:last-child{border-bottom:none}
.iss .none{color:var(--ok);border:none}
.upd{padding:10px 14px;font-size:12.5px;max-height:28vh;overflow:auto}
.upd .row{display:flex;justify-content:space-between;align-items:baseline;gap:10px;
padding:7px 0;border-bottom:1px solid var(--line);cursor:pointer}
.upd .row:last-child{border-bottom:none}
.upd .row:hover b{color:var(--accent)}
.upd .row b{font-weight:600}
/* The toolbar is one flat flex row on desktop; the wrappers only become real
   boxes on phones, where the actions and the filter chips split into two rows. */
.tbacts,.tbfilters{display:contents}
.hintcoarse{display:none}
@media (pointer:coarse){.hintfine{display:none}.hintcoarse{display:inline-flex}}

/* ---- phones: the diagram keeps a workable height without eating the whole
   screen, the run dialog becomes a bottom sheet, filters get finger-sized. ---- */
@media (max-width:760px){
#svgwrap{height:58vh;height:58dvh;min-height:320px}
.det,.iss,.upd{max-height:none}
.tb{display:block;padding:8px 10px}
.tbacts{display:flex;gap:6px;align-items:center;margin-bottom:7px}
.tbacts button{flex:1;min-width:0}
.tbacts .sp{display:none}
/* Seven filter toggles wrapped to three rows; one swipeable row instead. */
.tbfilters{display:flex;gap:6px;overflow-x:auto;overscroll-behavior-x:contain;
padding-bottom:2px;scrollbar-width:none;-ms-overflow-style:none}
.tbfilters::-webkit-scrollbar{display:none}
.tbfilters label{flex:0 0 auto;white-space:nowrap}
.lg{font-size:11.5px;padding:9px 12px;gap:5px 12px}
}
@media (max-width:620px){
.omodal{padding:0;align-items:flex-end}
.obox{border-radius:16px 16px 0 0;border-width:1px 0 0;max-height:92vh;
padding:18px 16px calc(18px + env(safe-area-inset-bottom))}
.obox .oa{flex-direction:column-reverse}
.obox .oa button{width:100%;min-height:44px}
.ops button{flex:1 1 auto}
}
@media (pointer:coarse){
.tb button,.ops button{min-height:38px;padding:0 13px}
.tb label{padding:7px 11px;font-size:13px}
.tb label input{width:17px;height:17px}
}
.upd .row span{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--warn);
white-space:nowrap}
.upd .row a{font-size:11px;margin-left:6px}
.upd .none{color:var(--ok)}
.lg{padding:10px 14px;font-size:12px;color:var(--muted);display:flex;flex-wrap:wrap;gap:6px 14px}
.lg span{display:inline-flex;align-items:center;gap:6px}
.lg i{width:16px;height:3px;border-radius:2px;display:inline-block}
.lg .tri{width:0;height:0;border-left:5px solid transparent;border-right:5px solid transparent;
border-bottom:8px solid var(--warn);border-radius:0}
.chip{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;font-weight:600}
.chip.ok{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
.chip.warn{background:color-mix(in srgb,var(--warn) 18%,transparent);color:var(--warn)}
.chip.bad{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}
.chip.idle{background:color-mix(in srgb,var(--muted) 18%,transparent);color:var(--muted)}
"""

# Symbols and arrowheads live in a hidden SVG so redrawing the graph does not
# have to re-emit them; <use href="#id"> resolves document-wide.
TOPO_DEFS = """
<svg style="position:absolute;width:0;height:0;overflow:hidden" aria-hidden="true"><defs>
<symbol id="i-jellyfin" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#aa5cc3"/><path d="M10 8l6 4-6 4z" fill="#fff"/></symbol>
<symbol id="i-jellyseerr" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#6366f1"/><path d="M12 7v10M7 12h10" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/></symbol>
<symbol id="i-gameyfin" viewBox="0 0 24 24"><rect x="2" y="8" width="20" height="10" rx="5" fill="#10b981"/><path d="M7 11v4M5 13h4" stroke="#fff" stroke-width="1.7" stroke-linecap="round"/><circle cx="16.5" cy="12.3" r="1.2" fill="#fff"/><circle cx="18.6" cy="15" r="1.2" fill="#fff"/></symbol>
<symbol id="i-prowlarr" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6" fill="none" stroke="#e66000" stroke-width="2.4"/><path d="M15 15l5 5" stroke="#e66000" stroke-width="2.6" stroke-linecap="round"/></symbol>
<symbol id="i-radarr" viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="2" fill="#ffc230"/><g fill="#7c4a03"><rect x="5" y="8" width="2.5" height="2.5"/><rect x="5" y="13.5" width="2.5" height="2.5"/><rect x="16.5" y="8" width="2.5" height="2.5"/><rect x="16.5" y="13.5" width="2.5" height="2.5"/></g></symbol>
<symbol id="i-sonarr" viewBox="0 0 24 24"><rect x="3" y="8" width="18" height="11" rx="2" fill="#35c5f4"/><path d="M8 4.5l4 3 4-3" stroke="#35c5f4" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-qbittorrent" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#2f67ba"/><path d="M12 6v9M8 11.5l4 4 4-4" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-dispatcharr" viewBox="0 0 24 24"><circle cx="12" cy="12" r="2.5" fill="#06b6d4"/><path d="M7.8 7.8a6 6 0 000 8.4M16.2 7.8a6 6 0 010 8.4M4.8 4.8a10 10 0 000 14.4M19.2 4.8a10 10 0 010 14.4" stroke="#06b6d4" stroke-width="1.8" fill="none" stroke-linecap="round"/></symbol>
<symbol id="i-threadfin" viewBox="0 0 24 24"><path d="M12 3.2c4.1 2.6 6.3 6 6.5 10.3-2.2-1.4-4.4-2.1-6.5-2.1s-4.3.7-6.5 2.1C5.7 9.2 7.9 5.8 12 3.2z" fill="#14b8a6"/><path d="M4.2 18.4c2.7-1.3 5.3-1.9 7.8-1.9s5.1.6 7.8 1.9" stroke="#14b8a6" stroke-width="2" fill="none" stroke-linecap="round"/></symbol>
<symbol id="i-grafana" viewBox="0 0 24 24"><rect x="3" y="13" width="4.5" height="7" rx="1" fill="#f46800"/><rect x="9.8" y="8" width="4.5" height="12" rx="1" fill="#f46800"/><rect x="16.5" y="4" width="4.5" height="16" rx="1" fill="#f46800"/></symbol>
<symbol id="i-influxdb" viewBox="0 0 24 24"><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6z" fill="#22adf6" opacity=".55"/><ellipse cx="12" cy="6" rx="7" ry="3" fill="#22adf6"/></symbol>
<symbol id="i-immich" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9.5" fill="#4250af"/><circle cx="12" cy="12" r="4" fill="#fff"/></symbol>
<symbol id="i-cloudflare" viewBox="0 0 24 24"><path d="M7 17.5h10.2a3.6 3.6 0 00.3-7.2 5.2 5.2 0 00-9.8-1.3A3.7 3.7 0 007 17.5z" fill="#f38020"/></symbol>
<symbol id="i-proxmox" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="6" rx="1.5" fill="#e57000"/><rect x="3" y="14" width="18" height="6" rx="1.5" fill="#e57000"/><circle cx="6.8" cy="7" r="1" fill="#fff"/><circle cx="6.8" cy="17" r="1" fill="#fff"/></symbol>
<symbol id="i-nvidia" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2.5" fill="#76b900"/><path d="M9.5 2.5v3.5M14.5 2.5v3.5M9.5 18v3.5M14.5 18v3.5M2.5 9.5h3.5M2.5 14.5h3.5M18 9.5h3.5M18 14.5h3.5" stroke="#76b900" stroke-width="1.8" stroke-linecap="round"/></symbol>
<symbol id="i-lxc" viewBox="0 0 24 24"><path d="M12 2.6l8.4 4.7v9.4L12 21.4 3.6 16.7V7.3z" fill="#4f46e5"/><path d="M12 12v9.4M3.6 7.3L12 12l8.4-4.7" stroke="#fff" stroke-width="1.2" fill="none" opacity=".5"/></symbol>
<symbol id="i-vm" viewBox="0 0 24 24"><rect x="2.5" y="4" width="19" height="12.5" rx="2" fill="#8b5cf6"/><path d="M9 20.5h6M12 16.5v4" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round"/></symbol>
<symbol id="i-folder" viewBox="0 0 24 24"><path d="M3 7a2 2 0 012-2h4.2l2 2H19a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" fill="#f59e0b"/></symbol>
<symbol id="i-disk" viewBox="0 0 24 24"><path d="M4 6.5v11c0 1.8 3.6 3.2 8 3.2s8-1.4 8-3.2v-11z" fill="#64748b"/><ellipse cx="12" cy="6.5" rx="8" ry="3.2" fill="#94a3b8"/><circle cx="12" cy="6.5" r="1.5" fill="#475569"/></symbol>
<symbol id="i-generic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5" fill="#94a3b8"/><circle cx="12" cy="12" r="3" fill="#e2e8f0"/></symbol>
<marker id="a-net" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#6366f1"/></marker>
<marker id="a-tunnel" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#f38020"/></marker>
<marker id="a-storage" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#0ea5e9"/></marker>
<marker id="a-host" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#94a3b8"/></marker>
<marker id="a-gpu" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#76b900"/></marker>
</defs></svg>
"""

TOPO_PAGE = """<!doctype html><meta charset="utf-8"><title>Topology</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
__NAV__
__DEFS__
<h1>Topology</h1>
<div class="sub" id="stamp">Live map of guests, services, volumes and disks.</div>
<div class="tp">
  <div class="pane">
    <div class="tb">
      <div class="tbacts">
      <button onclick="fit()">Fit</button>
      <button onclick="zoom(0.8)">Zoom in</button>
      <button onclick="zoom(1.25)">Zoom out</button>
      <span class="sp"></span>
      <button onclick="load()">Refresh</button>
      </div>
      <div class="tbfilters">
      <label><input type="checkbox" id="f-net" checked onchange="toggle('net')">Data flow</label>
      <label><input type="checkbox" id="f-tunnel" checked onchange="toggle('tunnel')">Tunnel</label>
      <label><input type="checkbox" id="f-storage" checked onchange="toggle('storage')">Storage</label>
      <label><input type="checkbox" id="f-host" checked onchange="toggle('host')">Hosting</label>
      <label><input type="checkbox" id="f-gpu" checked onchange="toggle('gpu')">GPU</label>
      <label><input type="checkbox" id="f-lbl" onchange="toggleLabels()">Link labels</label>
      <label><input type="checkbox" id="f-upd" onchange="toggleUpd()">Updates only</label>
      </div>
    </div>
    <div id="svgwrap"><svg id="g" xmlns="http://www.w3.org/2000/svg"></svg></div>
    <div class="lg">
      <span><i style="background:#6366f1"></i>data flow</span>
      <span><i style="background:#f38020"></i>tunnel</span>
      <span><i style="background:#0ea5e9"></i>storage</span>
      <span><i style="background:#94a3b8"></i>hosting</span>
      <span><i style="background:#76b900"></i>GPU</span>
      <span><i class="tri"></i>update available</span>
      <span class="hintfine">click a node for detail &middot; drag to pan &middot; scroll to zoom</span>
      <span class="hintcoarse">tap a node for detail &middot; drag to pan &middot; pinch to zoom</span>
    </div>
  </div>
  <div>
    <div class="pane" style="margin-bottom:14px">
      <h2>Detail</h2>
      <div class="det" id="det"><div class="empty">Select a node in the graph.</div></div>
    </div>
    <div class="pane" style="margin-bottom:14px">
      <h2>Updates</h2>
      <div class="upd" id="upd"></div>
    </div>
    <div class="pane">
      <h2>Findings</h2>
      <div class="iss" id="iss"></div>
    </div>
  </div>
</div>
<div class="omodal" id="omodal" onclick="if(event.target===this)oclose()">
  <div class="obox" id="obox"></div>
</div>
<script>
var CTL=__CTL__;
var DATA=null, LAY=null, VB={x:0,y:0,w:1600,h:900}, SEL=null, LABELS=false;
var UPDONLY=false;
var OJOB=null;
var SHOW={net:true,tunnel:true,storage:true,host:true,gpu:true};
var HDR=48, ROW=38, BW=250, NW=214, NH=60, GAP=26, COLGAP=96, TOP=54;
var EC={net:'#6366f1',tunnel:'#f38020',storage:'#0ea5e9',host:'#94a3b8',gpu:'#76b900'};

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

function toggle(k){SHOW[k]=document.getElementById('f-'+k).checked;draw();}
function toggleLabels(){LABELS=document.getElementById('f-lbl').checked;draw();}
function toggleUpd(){UPDONLY=document.getElementById('f-upd').checked;draw();}

// True for a node with a newer release upstream - and for a guest box, true if
// anything inside it has one, so the box stays visible in "Updates only".
function hasUpd(id){
  var n=LAY.byId[id];
  if(n&&n.update==='update')return true;
  var b=LAY.bybox[id];
  if(b)return b.members.some(function(m){return m.update==='update';});
  return false;
}

// A solid amber triangle: still readable at row size, where a glyph would not be.
function updTri(cx,cy,r){
  return '<path d="M'+cx+','+(cy-r)+' L'+(cx+r*0.95)+','+(cy+r*0.75)+' L'+
         (cx-r*0.95)+','+(cy+r*0.75)+' Z" fill="var(--warn)"/>';
}

function layout(d){
  var byId={},members={},i;
  d.nodes.forEach(function(n){byId[n.id]=n;});
  d.nodes.forEach(function(n){
    if(n.kind==='service'){(members[n.group]=members[n.group]||[]).push(n);}
  });
  // Within a guest, the services it is actually there to run come first and
  // anything the port scan merely stumbled on is parked at the bottom, so each
  // box reads top-down from "what this guest is for" to "what else listens".
  Object.keys(members).forEach(function(k){
    members[k].forEach(function(m,ix){m._ord=ix;});
    members[k].sort(function(a,b){
      return (a.discovered?1:0)-(b.discovered?1:0)||a._ord-b._ord;
    });
  });
  var cts=d.nodes.filter(function(n){return n.kind==='ct';});
  var edgeZ=d.nodes.filter(function(n){return n.zone==='edge';});
  var mounts=d.nodes.filter(function(n){return n.zone==='storage';});
  var disks=d.nodes.filter(function(n){return n.zone==='device';});

  // The column of each guest is derived from the data flow itself, so a guest
  // added later lands where its links say it belongs - nothing is hardcoded.
  var ctOf={},succ={};
  d.nodes.forEach(function(n){if(n.kind==='service')ctOf[n.id]=n.group;});
  cts.forEach(function(c){succ[c.id]={};});
  d.edges.forEach(function(e){
    if(e.kind!=='net'&&e.kind!=='tunnel')return;
    var a=ctOf[e.from],b=ctOf[e.to];
    if(a&&b&&a!==b&&succ[a])succ[a][b]=1;
  });
  // Mutual links are normal here - Jellyseerr asks Radarr for a movie, Radarr
  // tells Jellyfin to rescan - so break cycles with a DFS before layering.
  // Without this the relaxation below chases its own tail to the loop cap.
  var indeg={};
  cts.forEach(function(c){indeg[c.id]=0;});
  cts.forEach(function(c){
    Object.keys(succ[c.id]).forEach(function(t){
      if(indeg[t]!==undefined)indeg[t]++;
    });
  });
  // Start from the natural sources so the flow direction survives, and the
  // dropped edges are the genuine back-references.
  var roots=cts.filter(function(c){return indeg[c.id]===0;})
               .concat(cts.filter(function(c){return indeg[c.id]>0;}));
  var mark={};
  function dfs(u){
    mark[u]=1;
    Object.keys(succ[u]).forEach(function(v){
      if(mark[v]===1)delete succ[u][v];
      else if(!mark[v]&&succ[v])dfs(v);
    });
    mark[u]=2;
  }
  roots.forEach(function(c){if(!mark[c.id])dfs(c.id);});

  var layer={};
  cts.forEach(function(c){layer[c.id]=0;});
  for(i=0;i<cts.length+2;i++){
    var ch=false;
    cts.forEach(function(c){
      Object.keys(succ[c.id]).forEach(function(t){
        if(layer[t]!==undefined&&layer[t]<layer[c.id]+1){layer[t]=layer[c.id]+1;ch=true;}
      });
    });
    if(!ch)break;
  }
  var boxes=cts.map(function(c){
    var ms=members[c.id]||[];
    return {node:c,members:ms,w:BW,h:HDR+ms.length*ROW+12,col:1+layer[c.id]};
  });
  var maxCol=1;
  boxes.forEach(function(b){if(b.col>maxCol)maxCol=b.col;});
  boxes.forEach(function(b){
    var m=/([0-9]+)/.exec(b.node.label||'');
    b.seed=m?+m[1]:0;
  });

  var singles=[];
  function byLabel(a,b){return String(a.label).localeCompare(String(b.label));}
  // The internet is where the story starts, so it leads the edge column and the
  // hardware follows; everything else seeds alphabetically.
  var ER={internet:0,host:1,gpu:2};
  edgeZ.slice().sort(function(a,b){
    return (ER[a.kind]==null?9:ER[a.kind])-(ER[b.kind]==null?9:ER[b.kind]);
  }).forEach(function(n,ix){singles.push({node:n,w:NW,h:NH,col:0,seed:ix});});
  mounts.slice().sort(byLabel).forEach(function(n,ix){
    singles.push({node:n,w:NW,h:NH,col:maxCol+1,seed:ix});});
  disks.slice().sort(byLabel).forEach(function(n,ix){
    singles.push({node:n,w:NW,h:NH,col:maxCol+2,seed:ix});});

  var items=boxes.concat(singles),cols={};
  items.forEach(function(it,ix){it.i=ix;});
  items.forEach(function(it){(cols[it.col]=cols[it.col]||[]).push(it);});
  var keys=Object.keys(cols).map(Number).sort(function(a,b){return a-b;});

  // --- horizontal: one x per column, widest member sets the width --------
  var x=40,colX={},colW={};
  keys.forEach(function(k){
    var w=0;
    cols[k].forEach(function(it){if(it.w>w)w=it.w;});
    colX[k]=x;colW[k]=w;x+=w+COLGAP;
  });
  items.forEach(function(it){it.x=colX[it.col];});

  // --- who links to whom, and at what height on each side ----------------
  // A link leaves a service *row*, not the middle of the guest that holds it.
  // Carrying that offset around is what lets the alignment pass line a row up
  // with the volume it actually touches instead of with its container.
  var owner={},port={};
  items.forEach(function(it){
    owner[it.node.id]=it;
    port[it.node.id]=it.h/2;
    (it.members||[]).forEach(function(m,ix){
      owner[m.id]=it;
      port[m.id]=HDR+ix*ROW+ROW/2;
    });
  });
  items.forEach(function(it){it.adj=[];});
  d.edges.forEach(function(e){
    var a=owner[e.from],b=owner[e.to];
    if(!a||!b||a===b)return;   // links inside one box bow out on their own
    a.adj.push({o:b,mine:port[e.from],theirs:port[e.to]});
    b.adj.push({o:a,mine:port[e.to],theirs:port[e.from]});
  });

  keys.forEach(function(k){cols[k].sort(function(a,b){return a.seed-b.seed;});});

  // --- fewer crossings: order each column by where its neighbours sit -----
  // Barycentre sweeps, forwards then backwards. Four rounds is ample at this
  // size and stays deterministic, so the picture does not reshuffle itself on
  // every 60-second refresh.
  function reorder(k,ref){
    var list=cols[k];
    if(!list||list.length<2)return;
    var pos={};
    (cols[ref]||[]).forEach(function(it,ix){pos[it.i]=ix;});
    list.forEach(function(it,ix){
      var sum=0,n=0;
      it.adj.forEach(function(a){
        if(pos[a.o.i]!==undefined){sum+=pos[a.o.i];n++;}
      });
      it._b=n?sum/n:ix;   // nothing to line up with over there: hold position
      it._t=ix;
    });
    list.sort(function(a,b){return a._b-b._b||a._t-b._t;});
  }
  for(i=0;i<4;i++){
    for(var q=1;q<keys.length;q++)reorder(keys[q],keys[q-1]);
    for(var r=keys.length-2;r>=0;r--)reorder(keys[r],keys[r+1]);
  }

  // --- vertical: pull towards your neighbours, then undo the overlaps -----
  // Stack each column in its final order, then repeatedly move every item to
  // the average height of the rows it links to and push the pile apart again.
  // This is what straightens the long storage links instead of leaving them a
  // fan of crossing curves.
  keys.forEach(function(k){
    var y=TOP;
    cols[k].forEach(function(it){it.y=y;y+=it.h+GAP;});
  });
  // The sweeps above only ever compare against one neighbouring column, which
  // is too narrow here: a volume links back to guests several columns away.
  // Refining in coordinate space instead lets every link have a say, so the
  // first rounds are still free to re-order a column before it settles.
  for(i=0;i<24;i++){
    var settling=(i<12);
    keys.forEach(function(k){
      var list=cols[k],j,sh=0;
      list.forEach(function(it,ix){
        var sum=0,n=0;
        it.adj.forEach(function(a){sum+=(a.o.y+a.theirs)-a.mine;n++;});
        it._d=n?sum/n:it.y;
        it._t=ix;
      });
      if(settling)list.sort(function(a,b){return a._d-b._d||a._t-b._t;});
      list.forEach(function(it){it.y=it._d;});
      for(j=1;j<list.length;j++){
        var lo=list[j-1].y+list[j-1].h+GAP;
        if(list[j].y<lo)list[j].y=lo;
      }
      // Separating the pile can only push downwards, so recover the centre of
      // gravity the pulls asked for - otherwise every column creeps down.
      list.forEach(function(it){sh+=it._d-it.y;});
      if(list.length){
        sh/=list.length;
        list.forEach(function(it){it.y+=sh;});
      }
    });
  }

  // An item with no links of its own - an idle disk, say - has nothing to line
  // up with, so it must not be left holding a gap open. Close those, or a few
  // spare drives stretch the canvas and everything else has to shrink to fit.
  keys.forEach(function(k){
    var list=cols[k],j;
    for(j=1;j<list.length;j++){
      if(list[j].adj.length)continue;
      var lo=list[j-1].y+list[j-1].h+GAP;
      if(list[j].y>lo)list[j].y=lo;
    }
    var first=0;
    while(first<list.length&&!list[first].adj.length)first++;
    for(j=first-1;j>=0;j--){          // and the same for a run at the very top
      var hi=list[j+1].y-list[j].h-GAP;
      if(list[j].y<hi)list[j].y=hi;
    }
  });

  var minY=Infinity,maxY=-Infinity;
  items.forEach(function(it){
    if(it.y<minY)minY=it.y;
    if(it.y+it.h>maxY)maxY=it.y+it.h;
  });
  var dy=TOP-minY;
  items.forEach(function(it){it.y+=dy;});

  // --- the bands the columns fall into, labelled once each ---------------
  var bands=[];
  function band(name,from,to){
    var seen=keys.filter(function(k){return k>=from&&k<=to;});
    if(!seen.length)return;
    var last=seen[seen.length-1];
    bands.push({name:name,x:colX[seen[0]],w:colX[last]+colW[last]-colX[seen[0]]});
  }
  band('Edge',0,0);
  band('Guests and services',1,maxCol);
  band('Volumes',maxCol+1,maxCol+1);
  band('Disks',maxCol+2,maxCol+2);

  var bybox={};
  boxes.forEach(function(b){bybox[b.node.id]=b;});
  return {items:items,boxes:boxes,byId:byId,bybox:bybox,bands:bands,
          W:x+40,H:(maxY-minY)+TOP+40};
}

function boxOf(id){
  var n=LAY.byId[id];
  if(!n)return null;
  if(n.kind==='service')return LAY.bybox[n.group];
  for(var j=0;j<LAY.items.length;j++){if(LAY.items[j].node.id===id)return LAY.items[j];}
  return null;
}
function anchor(id,side){
  var n=LAY.byId[id],b=boxOf(id);
  if(!n||!b)return null;
  if(n.kind==='service'){
    var i=b.members.indexOf(n);
    if(i<0)return null;
    return {x:side==='r'?b.x+b.w:b.x, y:b.y+HDR+i*ROW+ROW/2};
  }
  return {x:side==='r'?b.x+b.w:b.x, y:b.y+b.h/2};
}

function edgePath(e){
  var ba=boxOf(e.from),bb=boxOf(e.to);
  if(!ba||!bb)return null;
  if(ba===bb){
    // Both ends sit in the same guest: bow the link out to the right so it
    // stays readable instead of collapsing onto the box edge.
    var s=anchor(e.from,'r'),t=anchor(e.to,'r');
    if(!s||!t)return null;
    var k=46+Math.abs(t.y-s.y)*0.3;
    return 'M'+s.x+','+s.y+' C'+(s.x+k)+','+s.y+' '+(t.x+k)+','+t.y+' '+t.x+','+t.y;
  }
  var fwd=(bb.x>=ba.x);
  var a=anchor(e.from,fwd?'r':'l'),b=anchor(e.to,fwd?'l':'r');
  if(!a||!b)return null;
  var dx=Math.abs(b.x-a.x),kk=Math.max(46,dx*0.42);
  var c1=fwd?a.x+kk:a.x-kk, c2=fwd?b.x-kk:b.x+kk;
  return 'M'+a.x+','+a.y+' C'+c1+','+a.y+' '+c2+','+b.y+' '+b.x+','+b.y;
}

function neighbours(id){
  var s={};s[id]=1;
  DATA.edges.forEach(function(e){
    if(!SHOW[e.kind])return;
    if(e.from===id)s[e.to]=1;
    if(e.to===id)s[e.from]=1;
  });
  return s;
}

function midpoint(p){
  var n=p.match(/-?[0-9.]+/g);
  if(!n||n.length<8)return null;
  var x0=+n[0],y0=+n[1],x1=+n[2],y1=+n[3],x2=+n[4],y2=+n[5],x3=+n[6],y3=+n[7];
  return {x:(x0+3*x1+3*x2+x3)/8, y:(y0+3*y1+3*y2+y3)/8};
}
function statusFill(st){
  return st==='ok'?'var(--ok)':st==='warn'?'var(--warn)':
         st==='bad'?'var(--bad)':'var(--muted)';
}

function draw(){
  if(!LAY)return;
  var hl=SEL?neighbours(SEL):null;
  var on=function(id){
    if(UPDONLY&&!hasUpd(id))return false;
    return !hl||!!hl[id];
  };
  var s='<g>';
  (LAY.bands||[]).forEach(function(bd){
    s+='<text class="zlabel" x="'+bd.x+'" y="'+(TOP-30)+'">'+esc(bd.name)+'</text>';
    s+='<line x1="'+bd.x+'" y1="'+(TOP-22)+'" x2="'+(bd.x+bd.w)+'" y2="'+(TOP-22)+
       '" stroke="var(--line)"/>';
  });
  s+='</g><g>';
  DATA.edges.forEach(function(e){
    if(!SHOW[e.kind])return;
    var p=edgePath(e);
    if(!p)return;
    var lit=!hl||(e.from===SEL||e.to===SEL);
    if(UPDONLY&&!(on(e.from)&&on(e.to)))lit=false;
    s+='<path d="'+p+'" fill="none" stroke="'+EC[e.kind]+'" stroke-width="'+
       (lit&&hl?2.6:1.5)+'" opacity="'+(lit?(hl?0.98:0.45):0.07)+
       '" marker-end="url(#a-'+e.kind+')"/>';
    if(LABELS&&lit&&e.label){
      var m=midpoint(p);
      if(m)s+='<text class="elabel" x="'+m.x+'" y="'+(m.y-5)+
              '" text-anchor="middle">'+esc(e.label)+'</text>';
    }
  });
  s+='</g><g>';
  LAY.items.forEach(function(it){s+=(it.members?boxSvg(it,on):nodeSvg(it,on));});
  s+='</g>';
  var g=document.getElementById('g');
  g.setAttribute('viewBox',VB.x+' '+VB.y+' '+VB.w+' '+VB.h);
  g.innerHTML=s;
}

function boxSvg(b,on){
  var lit=on(b.node.id)||b.members.some(function(m){return on(m.id);});
  var s='<g class="'+(lit?'':'dim')+'">';
  s+='<rect x="'+b.x+'" y="'+b.y+'" width="'+b.w+'" height="'+b.h+
     '" rx="12" fill="var(--card)" stroke="'+
     (SEL===b.node.id?'var(--accent)':'var(--line)')+'" stroke-width="'+
     (SEL===b.node.id?2.5:1.4)+'"/>';
  s+='<rect class="hit" data-id="'+b.node.id+'" x="'+b.x+'" y="'+b.y+'" width="'+b.w+
     '" height="'+HDR+'" rx="12" fill="transparent"/>';
  s+='<use href="#i-'+(b.node.icon||'lxc')+'" x="'+(b.x+13)+'" y="'+(b.y+13)+
     '" width="22" height="22"/>';
  s+='<text class="blabel" x="'+(b.x+43)+'" y="'+(b.y+20)+'">'+esc(b.node.label)+'</text>';
  s+='<text class="nsub" x="'+(b.x+43)+'" y="'+(b.y+35)+'">'+esc(b.node.sub||'')+'</text>';
  s+='<circle cx="'+(b.x+b.w-15)+'" cy="'+(b.y+22)+'" r="5" fill="'+
     statusFill(b.node.status)+'"/>';
  s+='<line x1="'+b.x+'" y1="'+(b.y+HDR)+'" x2="'+(b.x+b.w)+'" y2="'+(b.y+HDR)+
     '" stroke="var(--line)"/>';
  b.members.forEach(function(m,i){
    var y=b.y+HDR+i*ROW;
    s+='<rect class="hit" data-id="'+m.id+'" x="'+(b.x+1)+'" y="'+y+'" width="'+
       (b.w-2)+'" height="'+ROW+'" fill="'+
       (SEL===m.id?'color-mix(in srgb,var(--accent) 15%,transparent)':'transparent')+'"/>';
    var mu=(m.update==='update');
    s+='<use href="#i-'+(m.icon||'generic')+'" x="'+(b.x+13)+'" y="'+(y+10)+
       '" width="18" height="18"/>';
    s+='<text class="nlabel" x="'+(b.x+39)+'" y="'+(y+17)+'">'+esc(m.label)+'</text>';
    // With an update pending the version line carries both halves, so the
    // answer is on the graph itself and not only in the detail pane.
    s+='<text class="nsub'+(mu?' upd':'')+'" x="'+(b.x+39)+'" y="'+(y+29)+'">'+
       esc(mu?(m.sub+' \\u2192 '+m.latest):(m.sub||''))+'</text>';
    if(mu)s+=updTri(b.x+b.w-31,y+ROW/2,4.6);
    s+='<circle cx="'+(b.x+b.w-15)+'" cy="'+(y+ROW/2)+'" r="4.2" fill="'+
       statusFill(m.status)+'"/>';
  });
  return s+'</g>';
}

function nodeSvg(it,on){
  var n=it.node;
  var s='<g class="'+(on(n.id)?'':'dim')+'">';
  s+='<rect class="hit" data-id="'+n.id+'" x="'+it.x+'" y="'+it.y+'" width="'+it.w+
     '" height="'+it.h+'" rx="12" fill="var(--card)" stroke="'+
     (SEL===n.id?'var(--accent)':'var(--line)')+'" stroke-width="'+
     (SEL===n.id?2.5:1.4)+'"/>';
  s+='<use href="#i-'+(n.icon||'generic')+'" x="'+(it.x+13)+'" y="'+(it.y+it.h/2-11)+
     '" width="22" height="22"/>';
  s+='<text class="nlabel" x="'+(it.x+44)+'" y="'+(it.y+it.h/2-1)+'">'+esc(n.label)+'</text>';
  s+='<text class="nsub" x="'+(it.x+44)+'" y="'+(it.y+it.h/2+14)+'">'+esc(n.sub||'')+'</text>';
  if(n.update==='update')s+=updTri(it.x+it.w-31,it.y+15,5);
  s+='<circle cx="'+(it.x+it.w-14)+'" cy="'+(it.y+15)+'" r="4.6" fill="'+
     statusFill(n.status)+'"/>';
  return s+'</g>';
}

function detail(id){
  var el=document.getElementById('det');
  var n=id?LAY.byId[id]:null;
  if(!n){el.innerHTML='<div class="empty">Select a node in the graph.</div>';return;}
  var h='<h3><span class="chip '+esc(n.status)+'">'+esc(n.status)+'</span>'+
        (n.update==='update'?'<span class="chip warn">update</span>':'')+
        esc(n.label)+'</h3>';
  (n.meta||[]).forEach(function(kv){
    h+='<div class="kv"><b>'+esc(kv[0])+'</b><span>'+esc(kv[1])+'</span></div>';
  });
  var rel=DATA.edges.filter(function(e){return e.from===id||e.to===id;});
  if(rel.length){
    h+='<div style="margin:12px 0 4px;font-size:11px;text-transform:uppercase;'+
       'letter-spacing:.06em;color:var(--muted)">Connections</div>';
    rel.forEach(function(e){
      var other=(e.from===id)?e.to:e.from, o=LAY.byId[other];
      h+='<div class="kv"><b>'+((e.from===id)?'&rarr; ':'&larr; ')+
         esc(o?o.label:other)+'</b><span>'+esc(e.label||e.kind)+'</span></div>';
    });
  }
  if(n.link)h+='<div style="margin-top:12px"><a href="'+esc(n.link)+
    '" target="_blank" rel="noopener">Open '+esc(n.label)+'</a></div>';
  h+=controls(n);
  el.innerHTML=h;
}

// Buttons are only rendered for things the server actually knows how to drive,
// and only for admins - a non-admin gets the same read-only graph as before.
function controls(n){
  if(!CTL.admin)return '';
  var id=n.id, s='';
  var canCtl = !!CTL.ctl[id] || id.indexOf('ct:')===0;
  var canUpd = (n.update==='update') && !!CTL.upd[n.label];
  if(!canCtl && !canUpd)return '';
  s+='<div class="ops">';
  if(canUpd)s+='<button class="go" onclick="askUpd('+esc(JSON.stringify(n.label))+')">'
    +'Update to '+esc(n.latest||'latest')+'</button>';
  if(canCtl){
    var running = n.status==='ok' || n.status==='warn';
    s+='<button onclick="askOp('+esc(JSON.stringify(id))+',\\'restart\\')">Restart</button>';
    if(running)s+='<button class="stop" onclick="askOp('+esc(JSON.stringify(id))
      +',\\'stop\\')">Stop</button>';
    else s+='<button onclick="askOp('+esc(JSON.stringify(id))+',\\'start\\')">Start</button>';
  }
  s+='</div>';
  return s;
}

function oclose(){document.getElementById('omodal').className='omodal';OJOB=null;}

function obox(html){
  document.getElementById('obox').innerHTML=html;
  document.getElementById('omodal').className='omodal on';
}

function askUpd(name){
  var meta=CTL.upd[name]; if(!meta)return;
  var n=null; for(var k in LAY.byId){if(LAY.byId[k].label===name){n=LAY.byId[k];break;}}
  var s='<h2>Update '+esc(name)+'</h2>';
  s+='<div style="font-size:13px;color:var(--muted)">'
    +esc((n&&n.sub)||'')+' &rarr; '+esc((n&&n.latest)||'latest')+'</div>';
  if(meta.note)s+='<div class="wb"><b>Worth knowing first.</b><br>'+esc(meta.note)+'</div>';
  s+='<div class="wb">This runs as root on the host. The service will be '
    +'unavailable while it restarts.</div>';
  s+='<div class="oa"><button onclick="oclose()">Cancel</button>'
    +'<button class="go" id="o-go" onclick="doUpd('+esc(JSON.stringify(name))+')">'
    +'Update now</button></div>';
  obox(s);
}

function askOp(id,op){
  var meta=CTL.ctl[id]||{}, n=LAY.byId[id];
  var label=(n&&n.label)||id;
  var isCt=id.indexOf('ct:')===0;
  if(isCt&&CTL.ctwarn[id.slice(3)])meta={warn:CTL.ctwarn[id.slice(3)]};
  var verb=op.charAt(0).toUpperCase()+op.slice(1);
  var s='<h2>'+esc(verb)+' '+esc(label)+'</h2>';
  if(isCt)s+='<div style="font-size:13px;color:var(--muted)">This is the whole '
    +'container, so everything inside it goes with it.</div>';
  if(meta.warn)s+='<div class="wb"><b>Careful.</b><br>'+esc(meta.warn)+'</div>';
  s+='<div class="oa"><button onclick="oclose()">Cancel</button>'
    +'<button class="'+(op==='stop'?'danger':'go')+'" id="o-go" '
    +'onclick="doOp('+esc(JSON.stringify(id))+',\\''+esc(op)+'\\')">'+esc(verb)+'</button></div>';
  obox(s);
}

function post(url,body,label){
  var b=document.getElementById('o-go');
  if(b){b.disabled=true;b.textContent='Working...';}
  fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)}).then(function(r){return r.json();}).then(function(d){
      if(d.error){
        if(b){b.disabled=false;b.textContent=label;}
        document.getElementById('obox').insertAdjacentHTML('beforeend',
          '<div class="wb"><b>Refused.</b><br>'+esc(d.error)+'</div>');
        return;
      }
      OJOB=d.job;
      obox('<h2>Running</h2><div style="font-size:13px;color:var(--muted)">Job '
        +esc(d.job)+'. Closing this does not stop it.</div>'
        +'<div class="ol" id="ol">waiting for output...</div>'
        +'<div class="oa"><button onclick="oclose();load()">Close</button></div>');
      otick();
    }).catch(function(e){
      if(b){b.disabled=false;b.textContent=label;}
      alert('Request failed: '+e);
    });
}

function doUpd(name){post('/api/update',{service:name},'Update now');}
function doOp(id,op){post('/api/service',{target:id,op:op},op);}

function otick(){
  if(!OJOB)return;
  fetch('/api/runner/joblog?id='+encodeURIComponent(OJOB))
    .then(function(r){return r.json();}).then(function(d){
      var el=document.getElementById('ol'); if(!el||!OJOB)return;
      var atEnd=el.scrollTop+el.clientHeight>=el.scrollHeight-30;
      el.textContent=d.log||'waiting for output...';
      if(atEnd)el.scrollTop=el.scrollHeight;
      setTimeout(otick,2000);
    }).catch(function(){setTimeout(otick,4000);});
}

function select(id){
  SEL=(SEL===id?null:id);detail(SEL);draw();
  // Stacked layout: the Detail pane is below the fold, so a tap would look
  // like it did nothing. Only on the narrow layout, and only when selecting.
  if(SEL&&window.matchMedia('(max-width:1100px)').matches){
    var d=document.getElementById('det');
    if(d&&d.scrollIntoView)d.scrollIntoView({behavior:'smooth',block:'nearest'});
  }
}

// Selecting from a side pane is useless if the node is off-screen, so bring
// the viewport to it as well - the row height matters, not just the box.
function focusNode(id){
  select(id);
  var b=boxOf(id),n=LAY.byId[id];
  if(!b)return;
  var oy=(n&&n.kind==='service')?HDR+b.members.indexOf(n)*ROW+ROW/2:b.h/2;
  VB.x=b.x+b.w/2-VB.w/2;
  VB.y=b.y+oy-VB.h/2;
  draw();
}

function fit(){
  if(!LAY)return;
  var wrap=document.getElementById('svgwrap');
  var w=wrap.clientWidth||1200, h=wrap.clientHeight||700;
  var sc=Math.max(LAY.W/w,LAY.H/h);
  VB={x:0,y:0,w:w*sc,h:h*sc};
  draw();
}
function zoom(f){
  var cx=VB.x+VB.w/2, cy=VB.y+VB.h/2;
  VB.w*=f;VB.h*=f;VB.x=cx-VB.w/2;VB.y=cy-VB.h/2;
  draw();
}

// Pointer events rather than mouse events: the SVG sets touch-action:none to
// stop the browser panning the page, so with mouse-only handlers a touch device
// could neither pan nor zoom the diagram - it was a frozen picture. One pointer
// pans, two pinch. Mice keep working because they raise pointer events too.
function wire(){
  var g=document.getElementById('g');
  var pts=new Map(), drag=null, pinch=null;

  function toVB(cx,cy){                 // client pixels -> viewBox coordinates
    var r=g.getBoundingClientRect();
    return {x:VB.x+(cx-r.left)/r.width*VB.w, y:VB.y+(cy-r.top)/r.height*VB.h};
  }
  function mid(){
    var xs=0,ys=0,n=0;
    pts.forEach(function(p){xs+=p.x;ys+=p.y;n++;});
    return n?{x:xs/n,y:ys/n}:{x:0,y:0};
  }
  function gap(){
    var a=[]; pts.forEach(function(p){a.push(p);});
    return a.length<2?0:Math.hypot(a[0].x-a[1].x,a[0].y-a[1].y);
  }
  function startPan(id,x,y,moved){
    drag={x:x,y:y,vx:VB.x,vy:VB.y,moved:!!moved,id:id};
    g.classList.add('drag');
  }

  g.addEventListener('pointerdown',function(ev){
    try{g.setPointerCapture(ev.pointerId);}catch(e){}
    pts.set(ev.pointerId,{x:ev.clientX,y:ev.clientY});
    if(pts.size===1){
      startPan(ev.pointerId,ev.clientX,ev.clientY,false);
      pinch=null;
    }else if(pts.size===2){
      var c=mid();
      pinch={d:gap(),w:VB.w,h:VB.h,anchor:toVB(c.x,c.y)};
      drag=null;g.classList.remove('drag');
    }
  });

  g.addEventListener('pointermove',function(ev){
    if(!pts.has(ev.pointerId))return;
    pts.set(ev.pointerId,{x:ev.clientX,y:ev.clientY});
    if(pinch&&pts.size>=2){
      var d=gap(); if(!d||!pinch.d)return;
      var f=pinch.d/d;                  // fingers apart -> smaller viewBox -> zoom in
      var w=Math.max(60,Math.min(pinch.w*f,400000));
      var h=w*(pinch.h/pinch.w);
      var r=g.getBoundingClientRect(), c=mid();
      VB.w=w;VB.h=h;
      VB.x=pinch.anchor.x-(c.x-r.left)/r.width*w;
      VB.y=pinch.anchor.y-(c.y-r.top)/r.height*h;
      draw();
      return;
    }
    if(drag&&ev.pointerId===drag.id){
      var sc=VB.w/(g.clientWidth||1);
      var dx=(ev.clientX-drag.x)*sc, dy=(ev.clientY-drag.y)*sc;
      if(Math.abs(dx)>3||Math.abs(dy)>3)drag.moved=true;
      VB.x=drag.vx-dx;VB.y=drag.vy-dy;draw();
    }
  });

  function lift(ev){
    var wasDrag=drag&&ev.pointerId===drag.id, moved=wasDrag&&drag.moved;
    pts.delete(ev.pointerId);
    try{g.releasePointerCapture(ev.pointerId);}catch(e){}
    if(pts.size<2)pinch=null;
    if(wasDrag){
      drag=null;g.classList.remove('drag');
      if(!moved){
        // Pointer capture retargets the event to the SVG, so ev.target is no
        // use for hit-testing - ask the document what is under the finger.
        var el=document.elementFromPoint(ev.clientX,ev.clientY);
        var t=el&&el.closest?el.closest('.hit'):null;
        if(t)select(t.getAttribute('data-id'));
        else if(el&&g.contains(el))select(null);
      }
    }
    // A finger left after a pinch: hand panning back to the one still down.
    if(pts.size===1&&!drag){
      pts.forEach(function(p,k){startPan(k,p.x,p.y,true);});
    }
  }
  g.addEventListener('pointerup',lift);
  g.addEventListener('pointercancel',lift);
  g.addEventListener('wheel',function(ev){
    ev.preventDefault();
    var r=g.getBoundingClientRect();
    var mx=VB.x+(ev.clientX-r.left)/r.width*VB.w;
    var my=VB.y+(ev.clientY-r.top)/r.height*VB.h;
    var f=ev.deltaY>0?1.12:0.89;
    VB.w*=f;VB.h*=f;VB.x=mx-(mx-VB.x)*f;VB.y=my-(my-VB.y)*f;
    draw();
  },{passive:false});
  window.addEventListener('resize',fit);
}

function issues(){
  var el=document.getElementById('iss');
  if(!DATA.issues||!DATA.issues.length){
    el.innerHTML='<div class="none">Nothing to report - every guest, service, '+
                 'volume and disk looks healthy.</div>';
    return;
  }
  el.innerHTML=DATA.issues.map(function(i){return '<div>'+esc(i)+'</div>';}).join('');
}

function updates(){
  var el=document.getElementById('upd'),list=DATA.updates||[];
  if(!list.length){
    el.innerHTML='<div class="none">Everything tracked is on its latest release.</div>';
    return;
  }
  // The row index drives the click rather than the id, so a node id can never
  // be reinterpreted as markup on its way into the handler.
  el.innerHTML=list.map(function(u,ix){
    var a=u.url?'<a href="'+esc(u.url)+'" target="_blank" rel="noopener" '+
                'onclick="event.stopPropagation()">notes</a>':'';
    return '<div class="row" onclick="focusNode(DATA.updates['+ix+'].id)"><b>'+
           esc(u.name)+a+'</b><span>'+esc(u.detail)+'</span></div>';
  }).join('');
}

async function load(){
  var d;
  try{ d=await (await fetch('/api/topology',{cache:'no-store'})).json(); }
  catch(e){ return; }
  if(d.error){document.getElementById('stamp').textContent=d.error;return;}
  var first=!DATA;
  DATA=d;LAY=layout(d);
  var nu=(d.updates||[]).length;
  document.getElementById('stamp').textContent=
    d.nodes.length+' nodes, '+d.edges.length+' links - '+
    (nu?nu+' update'+(nu>1?'s':'')+' available':'everything up to date')+
    ' - collected '+d.generated;
  issues();updates();
  if(first)fit(); else draw();
  if(SEL)detail(SEL);
}

wire();load();
setInterval(load,60000);
</script>
"""


def nav(active, user=None, admin=False):
    def a(href, label):
        cls = ' class="on"' if href == active else ""
        return f'<a href="{href}"{cls}>{label}</a>'
    out = '<div class="nav">' + a("/", "Status")
    out += a("/catalog", "Catalog")
    out += a("/topology", "Topology")
    out += a("/fleet", "Fleet")
    # Only offered once something is plugged in - an empty page is worse than
    # no link, and a non-admin may see fewer add-ons than an admin does.
    if mdash_addons.has_visible(admin):
        out += a("/addons", "Dashboards")
    if admin:
        out += a("/appstore", "App store")
    if admin:
        out += a("/credentials", "Credentials")
    out += a("/files", "Files")
    if admin:
        out += a("/users", "Users")
    if admin:
        out += a("/usersync", "User sync")
    if admin:
        out += a("/tmux", "Terminal")
    if admin:
        out += a("/claude", "Claude")
    if admin:
        out += a("/usage", "Usage")
    if admin:
        out += a("/tunnel", "Routing")
    out += '<span class="sp"></span>'
    if user:
        # .nav .who hides this on phones - the link row needs the width more.
        out += f'<span class="who">{html.escape(user)}</span>'
    return out + '<a href="/logout">Sign out</a></div>'


LOGIN_PAGE = """<!doctype html>
<meta charset="utf-8"><title>Media stack</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f6f7f9" media="(prefers-color-scheme:light)">
<meta name="theme-color" content="#0d1117" media="(prefers-color-scheme:dark)">
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#14161a;--muted:#6b7280;--line:#e5e7eb;
--accent:#4f46e5;--bad:#dc2626;}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;
--muted:#8b949e;--line:#30363d;--accent:#818cf8;--bad:#f85149;}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;
padding:16px;background:var(--bg);color:var(--fg);-webkit-text-size-adjust:100%;
font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:clamp(20px,5vw,28px);width:min(380px,100%)}
h1{font-size:18px;margin:0 0 4px}
p.sub{color:var(--muted);font-size:13px;margin:0 0 20px}
label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);margin-bottom:6px}
input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:8px;
background:var(--bg);color:var(--fg);font-size:16px}
input:focus{outline:2px solid var(--accent);outline-offset:1px}
button{width:100%;margin-top:16px;padding:12px;border:0;border-radius:8px;
background:var(--accent);color:#fff;font-size:16px;font-weight:600;cursor:pointer;
min-height:46px}
button:hover{filter:brightness(1.08)}
.err{margin-top:14px;padding:9px 12px;border-radius:8px;font-size:13px;
background:color-mix(in srgb,var(--bad) 14%,transparent);
border:1px solid color-mix(in srgb,var(--bad) 40%,transparent);color:var(--bad)}
</style>
<div class="card">
  <h1>Media stack</h1>
  <p class="sub">pve-tower &middot; sign in to continue</p>
  <form method="post" action="/login">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" autofocus autocomplete="username"
           autocapitalize="none" spellcheck="false">
    <label for="p" style="margin-top:14px">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
  __ERR__
</div>
"""

DOWNLOAD_JS = """
<script>
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function tick(){
  const el=document.getElementById('downloads'); if(!el) return;
  try{
    const r=await fetch('/api/downloads',{cache:'no-store'});
    const d=await r.json();
    if(d.error){el.innerHTML='<div class="tablewrap"><table><tr><th>Downloads</th></tr>'+
      '<tr><td>qBittorrent unreachable</td></tr></table></div>';return;}
    if(!d.items.length){el.innerHTML='<div class="tablewrap"><table><tr><th>Downloads</th></tr>'+
      '<tr><td style="color:var(--muted)">nothing in the queue</td></tr></table></div>';return;}
    let h='<div class="tablewrap"><table class="resp"><tr class="hd">'+
      '<th>Downloading</th><th>State</th>'+
      '<th>Progress</th><th>Size</th><th>Down</th><th>Up</th><th>ETA</th></tr>';
    for(const t of d.items){
      const done=t.progress>=100;
      h+='<tr><td><b>'+esc(t.name.slice(0,70))+'</b></td>'+
         '<td data-label="State"><span class="pill '+(done?'ok':'warn')+'">'+
             esc(t.state)+'</span></td>'+
         '<td data-label="Progress" style="min-width:170px">'+t.progress+
             '%<div class="bar"><i style="width:'+
             Math.min(t.progress,100)+'%"></i></div></td>'+
         '<td data-label="Size">'+esc(t.size)+'</td>'+
         '<td data-label="Down">'+esc(t.dlspeed)+'</td>'+
         '<td data-label="Up">'+esc(t.upspeed)+'</td>'+
         '<td data-label="ETA">'+esc(t.eta)+'</td></tr>';
    }
    el.innerHTML=h+'</table></div>';
  }catch(e){}
}
tick(); setInterval(tick,5000);

async function todoPost(body){
  await fetch('/api/todo',{method:'POST',headers:{'Content-Type':'application/json'},
                           body:JSON.stringify(body)});
  todoDraw();
}
async function todoDraw(){
  const el=document.getElementById('todo'); if(!el) return;
  let d; try{ d=await (await fetch('/api/todo',{cache:'no-store'})).json(); }catch(e){ return; }
  const open=d.items.filter(i=>!i.done), done=d.items.filter(i=>i.done);
  const total=d.items.length, ndone=done.length;
  let h='<div class="tablewrap"><table class="todo">'+
        '<tr><th colspan="3">To do'+
        (total?' <span style="text-transform:none;letter-spacing:0;font-weight:400">('+
          ndone+' of '+total+' done)</span>':'')+'</th></tr>';
  h+='<tr><td colspan="3" class="tadd"><form onsubmit="var v=this.t.value;this.t.value=\\'\\';'+
     'todoPost({action:\\'add\\',text:v});return false">'+
     '<input name="t" placeholder="add an item…" required>'+
     '<button type="submit">Add</button>'+
     '</form></td></tr>';
  if(!total){
    h+='<tr><td colspan="3" style="color:var(--muted)">nothing outstanding</td></tr>';
  }
  for(const i of open.concat(done)){
    h+='<tr>'+
       '<td class="tcheck"><input type="checkbox" id="t'+i.id+'" '+(i.done?'checked':'')+
         ' onchange="todoPost({action:\\'toggle\\',id:'+i.id+'})"></td>'+
       '<td class="ttext"><label for="t'+i.id+'"'+
         (i.done?' class="tdone"':'')+'>'+esc(i.text)+'</label>'+
         '<span class="tdate">'+esc(i.added||'')+'</span></td>'+
       '<td class="tdel"><a href="#" onclick="todoPost({action:\\'delete\\',id:'+i.id+
         '});return false" title="remove">&times;</a></td>'+
       '</tr>';
  }
  el.innerHTML=h+'</table></div>';
}
todoDraw();

/* A path goes into a double-quoted onclick="", so the JSON quotes have to be
   HTML-escaped or the attribute ends at the first one and the handler is lost. */
function arg(s){return esc(JSON.stringify(s));}
let fbPath=null;
async function fbGo(p){
  const el=document.getElementById('filebrowser'); if(!el) return;
  let d;
  try{ d=await (await fetch('/api/browse'+(p?('?path='+encodeURIComponent(p)):''),
                            {cache:'no-store'})).json(); }catch(e){ return; }
  if(d.error){ el.innerHTML='<div class="tablewrap"><table><tr><th>Files</th></tr>'+
    '<tr><td>not accessible</td></tr></table></div>'; return; }
  fbPath=d.path;
  let roots=d.roots.map(r=>'<a href="#" onclick="fbGo('+arg(r)+');return false">'+
    esc(r)+'</a>').join(' &middot; ');
  let h='<div class="tablewrap"><table class="resp">'+
    '<tr class="hd"><th>Files &mdash; '+esc(d.path)+'</th><th style="width:110px">Size</th>'+
    '<th style="width:150px">Modified</th></tr>'+
    '<tr class="fbhead"><td colspan="3"><b>'+esc(d.path)+'</b></td></tr>'+
    '<tr><td colspan="3" style="font-size:12px;color:var(--muted)">'+roots+'</td></tr>';
  if(d.parent){
    h+='<tr><td><a href="#" onclick="fbGo('+arg(d.parent)+
       ');return false">&larr; up</a></td><td></td><td></td></tr>';
  }
  for(const e of d.entries){
    h+='<tr><td>'+(e.dir
        ? '<a href="#" onclick="fbGo('+arg(e.path)+');return false">&#128193; '+
          esc(e.name)+'</a>'
        : esc(e.name))+
       '</td><td class="ver" data-label="Size">'+esc(e.size||'—')+'</td>'+
       '<td class="ver" data-label="Modified">'+esc(e.mtime)+'</td></tr>';
  }
  if(!d.entries.length) h+='<tr><td colspan="3" style="color:var(--muted)">empty</td></tr>';
  if(d.truncated) h+='<tr><td colspan="3" style="color:var(--muted)">'+
    'listing truncated at 400 entries</td></tr>';
  el.innerHTML=h+'</table></div>';
}
fbGo(null);
</script>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "mdash"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def client_ip(self):
        """Best available client address, for throttling and the audit log.

        The forwarded header is only believed when the connection genuinely
        came from the tunnel connector; otherwise it is attacker-controlled.
        """
        peer = self.client_address[0]
        if peer in TRUSTED_PROXIES:
            fwd = (self.headers.get("CF-Connecting-IP") or "").split(",")[0].strip()
            if fwd:
                return fwd[:45]
        return peer

    def locked(self):
        n, first = _fails.get(self.client_ip(), (0, 0))
        if n >= _LOCK_AFTER and time.time() - first < _LOCK_SECONDS:
            return True
        if time.time() - first >= _LOCK_SECONDS:
            _fails.pop(self.client_ip(), None)
        return False

    def note_fail(self):
        n, first = _fails.get(self.client_ip(), (0, 0))
        _fails[self.client_ip()] = (n + 1, first or time.time())

    def secure_ctx(self):
        # Same trust rule. A direct bridge connection is plain HTTP, so marking
        # the cookie Secure there would stop the browser ever sending it back.
        if self.client_address[0] not in TRUSTED_PROXIES:
            return False
        return (self.headers.get("X-Forwarded-Proto") == "https"
                or self.headers.get("CF-Connecting-IP") is not None)

    def send_body(self, body, code=200, ctype="text/html; charset=utf-8", extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        if not any(k.lower() == "cache-control" for k, _ in (extra or [])):
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def send_file_stream(self, path):
        """Stream a file to the client in chunks, honouring Range requests.

        Deliberately never reads the whole file into memory - these can be
        15GB+ video files. Range support makes downloads resumable.
        """
        size = os.path.getsize(path)
        start, end = 0, size - 1
        partial = False
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):
            spec = rng[6:].split(",")[0].strip()
            try:
                a, _, b = spec.partition("-")
                if a:
                    start = int(a)
                    if b:
                        end = min(int(b), size - 1)
                else:
                    # suffix form: last N bytes
                    start = max(0, size - int(b))
                if start > end or start >= size:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                partial = True
            except ValueError:
                start, end, partial = 0, size - 1, False

        length = end - start + 1
        name = os.path.basename(path)
        # RFC 5987 so non-ASCII filenames survive
        ascii_name = name.encode("ascii", "replace").decode()
        self.send_response(206 if partial else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{ascii_name}"; '
                         f"filename*=UTF-8''{quote(name)}")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        remaining = length
        chunk = 1024 * 512
        try:
            with open(path, "rb") as f:
                f.seek(start)
                while remaining > 0:
                    buf = f.read(min(chunk, remaining))
                    if not buf:
                        break
                    self.wfile.write(buf)
                    remaining -= len(buf)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client cancelled the download

    def redirect(self, to, extra=None):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def current_user(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        c = http.cookies.SimpleCookie(raw)
        if COOKIE not in c:
            return None
        try:
            return valid_session(load_auth(), c[COOKIE].value)
        except Exception:
            return None

    def session_ok(self):
        return self.current_user() is not None

    def is_admin(self):
        u = self.current_user()
        if not u:
            return False
        try:
            return role_of(load_auth(), u) == "admin"
        except Exception:
            return False

    # ------------------------------------------------------------- pages
    def page_status(self):
        try:
            with open(DOC) as f:
                page = f.read()
        except Exception:
            return self.send_body("<h1>dashboard not generated yet</h1>", 503)
        page = decorate_status(page)
        # The sprite has to be in the document before anything <use>s it.
        page = page.replace('<div class="wrap">',
                            '<div class="wrap">' + TOPO_DEFS + STATUS_ICON_CSS
                            + nav("/", self.current_user(), self.is_admin()), 1)
        extra = ""
        if self.is_admin():
            # The status page is a static file the collector writes, and it has
            # no idea who is looking at it. Rather than teach the collector
            # about roles, the controls are grafted on here for admins only.
            ctl = {"ctl": {k: {"warn": v.get("warn", "")}
                           for k, v in service_control().items()},
                   "ctwarn": {str(k): v for k, v in ct_warns().items()}}
            extra = STATUS_CTL_JS.replace(
                "__SCTL__", json.dumps(ctl).replace("</", "<\\/"))
        return self.send_body(page + DOWNLOAD_JS + extra)

    def page_credentials(self):
        try:
            with open(CRED_FILE) as f:
                raw = f.read()
        except Exception:
            return self.send_body("<h1>credentials file unreadable</h1>", 500)

        blocks, title, rows = [], None, []

        def flush():
            if title is None and not rows:
                return
            blocks.append((title or "General", list(rows)))

        for line in raw.splitlines():
            st = line.strip()
            if st.startswith("===") and st.endswith("==="):
                flush(); rows = []
                title = st.strip("= ").strip()
            elif st and not st.startswith("#"):
                rows.append(st)
        flush()

        p = [f"<!doctype html><meta charset='utf-8'><title>Credentials</title>",
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             f"<style>{CSS}</style>",
             nav("/credentials", self.current_user(), self.is_admin()),
             "<h1>Credentials</h1>",
             '<div class="sub">read live from /root/media-stack-credentials.txt '
             '&middot; never written into the static dashboard file</div>',
             '<div class="warnbox">These are full administrative credentials for the '
             'hypervisor and every container. Anyone who gets past this single login '
             'gets all of them. Put a Cloudflare Access policy in front of this host.</div>']
        for t, lines in blocks:
            if not lines:
                continue
            p.append(f'<div class="sec">{html.escape(t)}</div>')
            # No header row to label cells from, so on phones these just wrap.
            p.append('<div class="tablewrap"><table class="wrapcells">')
            for ln in lines:
                cells = [c for c in ln.split("  ") if c.strip()]
                if len(cells) >= 2:
                    p.append("<tr>" + "".join(
                        f'<td class="ver">{html.escape(c.strip())}</td>' for c in cells) + "</tr>")
                else:
                    p.append(f'<tr><td colspan="4">{html.escape(ln)}</td></tr>')
            p.append("</table></div>")
        return self.send_body("\n".join(p))

    def page_users(self, msg=""):
        auth = load_auth()
        users = auth.get("users") or {}
        me = self.current_user()
        admins = [n for n, u in users.items() if u.get("role") == "admin"]
        p = ["<!doctype html><meta charset='utf-8'><title>Users</title>",
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             f"<style>{CSS}</style>",
             nav("/users", me, True), "<h1>Users</h1>",
             '<div class="sub">Accounts that can sign in here. Admins additionally see '
             'the Credentials page and this one. Adding a user or changing a password '
             'also pushes it to the services each person is ticked for on '
             '<a href="/usersync">User sync</a>.</div>']
        if msg:
            p.append(f'<div class="warnbox">{html.escape(msg)}</div>')

        p.append('<div class="sec">Add a user</div>')
        p.append('<div class="tablewrap"><table><tr><td>'
                 '<form method="post" action="/users" class="rowform">'
                 '<input type="hidden" name="action" value="add">'
                 '<input name="username" placeholder="username" required '
                 'autocapitalize="none" spellcheck="false" class="fi">'
                 '<input name="password" type="password" placeholder="password" required class="fi">'
                 '<input name="email" type="email" placeholder="email (optional)" '
                 'autocapitalize="none" spellcheck="false" class="fi">'
                 '<select name="role" class="fi">'
                 '<option value="user">user</option><option value="admin">admin</option></select>'
                 '<button type="submit" class="fb">Add user</button>'
                 '</form></td></tr></table></div>')

        p.append('<div class="sec">Existing users</div>')
        p.append('<div class="tablewrap"><table class="resp">'
                 '<tr class="hd"><th>User</th><th>Email</th><th>Role</th>'
                 '<th>Change password</th><th></th></tr>')
        for name in sorted(users):
            r = users[name].get("role", "user")
            is_me = ' <span style="color:var(--muted)">(you)</span>' if name == me else ""
            p.append(f'<tr><td><b>{html.escape(name)}</b>{is_me}</td>')
            # Immich, Grafana and RomM all insist on an address; without a real
            # one the sync makes up <user>@<domain>, which works but cannot
            # receive mail.
            p.append('<td class="stk" data-label="Email">'
                     '<form method="post" action="/users" class="rowform">'
                     '<input type="hidden" name="action" value="email">'
                     f'<input type="hidden" name="username" value="{html.escape(name)}">'
                     f'<input name="email" type="email" class="fi" '
                     f'value="{html.escape(users[name].get("email") or "")}" '
                     'placeholder="(default)" autocapitalize="none" spellcheck="false">'
                     '<button type="submit" class="fb">Set</button></form></td>')
            p.append('<td class="stk" data-label="Role">'
                     '<form method="post" action="/users" class="rowform">'
                     '<input type="hidden" name="action" value="role">'
                     f'<input type="hidden" name="username" value="{html.escape(name)}">'
                     '<select name="role" class="fi">'
                     f'<option value="admin"{" selected" if r == "admin" else ""}>admin</option>'
                     f'<option value="user"{" selected" if r == "user" else ""}>user</option>'
                     '</select><button type="submit" class="fb">Set</button></form></td>')
            p.append('<td class="stk" data-label="Password">'
                     '<form method="post" action="/users" class="rowform">'
                     '<input type="hidden" name="action" value="passwd">'
                     f'<input type="hidden" name="username" value="{html.escape(name)}">'
                     '<input name="password" type="password" placeholder="new password" '
                     'required class="fi">'
                     '<button type="submit" class="fb">Set</button></form></td>')
            if name == me:
                p.append('<td style="color:var(--muted)">&mdash;</td>')
            else:
                p.append('<td><form method="post" action="/users" class="rowform" '
                         'onsubmit="return confirm(\'Delete this user?\')">'
                         '<input type="hidden" name="action" value="delete">'
                         f'<input type="hidden" name="username" value="{html.escape(name)}">'
                         '<button type="submit" class="fb del">Delete</button></form></td>')
            p.append("</tr>")
        p.append("</table></div>")
        p.append(f'<div class="sub" style="margin-top:14px">'
                 f'{len(users)} account(s), {len(admins)} admin(s). Usernames may contain '
                 'letters, digits, dot, dash and underscore. Sessions last 12 hours.</div>')
        return self.send_body("\n".join(p))


    def page_files(self, qs):
        start = (parse_qs(qs).get("path") or [BROWSE_ROOTS[0]])[0]
        if safe_path(start) is None:
            start = BROWSE_ROOTS[0]
        admin = "true" if self.is_admin() else "false"
        roots = json.dumps(BROWSE_ROOTS)
        page = FILES_PAGE
        page = page.replace("__NAV__", nav("/files", self.current_user(), self.is_admin()))
        page = page.replace("__CSS__", CSS + FILES_CSS)
        page = page.replace("__START__", json.dumps(start))
        page = page.replace("__ADMIN__", admin)
        page = page.replace("__ROOTS__", roots)
        return self.send_body(page)

    def page_topology(self):
        page = TOPO_PAGE
        page = page.replace("__NAV__", nav("/topology", self.current_user(),
                                           self.is_admin()))
        page = page.replace("__CSS__", CSS + TOPO_CSS)
        page = page.replace("__DEFS__", TOPO_DEFS)
        # What this viewer is allowed to drive, and the caveats worth showing
        # before they do. Only names and notes cross over - never a container
        # id, unit or path, so the page cannot compose its own request.
        ctl = {
            "admin": self.is_admin(),
            "ctl": {k: {"warn": v.get("warn", "")}
                    for k, v in service_control().items()},
            "upd": {k: {"note": v.get("note", "")}
                    for k, v in update_recipes().items()},
            "ctwarn": {str(k): v for k, v in ct_warns().items()},
        }
        page = page.replace("__CTL__",
                            json.dumps(ctl).replace("</", "<\\/"))
        return self.send_body(page)

    def page_appstore(self):
        page = APPSTORE_PAGE
        page = page.replace("__NAV__", nav("/appstore", self.current_user(),
                                           self.is_admin()))
        page = page.replace("__CSS__", CSS + APPSTORE_CSS)
        # The package and add-on tabs are self-contained - markup, styles and
        # an IIFE each - so they drop straight in rather than needing their own
        # copy of the app store's plumbing.
        page = page.replace("__PKG_PANEL__", mdash_packages.PANEL)
        page = page.replace("__ADDON_PANEL__", mdash_addons.PANEL)
        return self.send_body(page)

    def page_catalog(self):
        page = CATALOG_PAGE
        page = page.replace("__NAV__", nav("/catalog", self.current_user(),
                                           self.is_admin()))
        page = page.replace("__CSS__", CSS + CATALOG_CSS)
        # Deep links go to whatever hostname the tunnel publishes for
        # Jellyfin, falling back to its LAN address when nothing is published.
        jf = site.find("Jellyfin") or {}
        jf_base = f"https://{jf['host']}" if jf.get("host") else jf.get("url") or ""
        page = page.replace("__JS__",
                            CATALOG_JS.replace("__PAGE__", str(CATALOG_PAGE_SIZE))
                                      .replace("__JF__", json.dumps(jf_base)))
        return self.send_body(page)

    def api_catalog(self, qs):
        p = parse_qs(qs)
        kind = (p.get("kind") or ["movies"])[0]
        if kind not in CATALOG_KINDS:
            return self.send_body('{"error":"unknown kind"}', 400, "application/json")
        sort = (p.get("sort") or ["name"])[0]
        if sort not in CATALOG_SORTS:
            sort = "name"
        try:
            start = max(0, int((p.get("start") or ["0"])[0]))
            limit = int((p.get("limit") or [str(CATALOG_PAGE_SIZE)])[0])
        except ValueError:
            return self.send_body('{"error":"bad paging"}', 400, "application/json")
        limit = max(1, min(limit, CATALOG_MAX_PAGE))
        d = catalog_query(kind, start=start, limit=limit,
                          search=(p.get("search") or [""])[0][:120],
                          genre=(p.get("genre") or [""])[0][:60], sort=sort)
        if d is None:
            return self.send_body(
                '{"error":"Jellyfin did not answer - check the media container '
                'and the dashboard API key."}', 200, "application/json")
        return self.send_body(json.dumps(d), 200, "application/json")

    def do_GET(self):
        u = urlparse(self.path)
        path, qs = u.path, u.query
        if path == "/login":
            return self.send_body(LOGIN_PAGE.replace("__ERR__", ""))
        if path == "/logout":
            gone = f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            return self.redirect("/login", [("Set-Cookie", gone)])
        # A federating peer presents a bearer token rather than a session
        # cookie, and may reach exactly this one read-only route.
        if mdash_fleetui.handle_export(self, path):
            return
        if not self.session_ok():
            if path.startswith("/api/"):
                return self.send_body('{"error":"unauthenticated"}', 401, "application/json")
            return self.redirect("/login")

        # /tmux, /api/tmux, /tmux/ws and the xterm assets. Checks admin itself.
        if mdash_tmux.handle_get(self, path, qs):
            return
        # /claude, /api/claude/*. Checks admin itself.
        if mdash_claude.handle_get(self, path, qs):
            return
        # /usage and /api/usage. Checks admin itself.
        if mdash_usage.handle_get(self, path, qs):
            return
        # /tunnel, /api/tunnel. Checks admin itself.
        if mdash_tunnel.handle_get(self, path, qs):
            return
        # /usersync, /api/usersync/state. Checks admin itself.
        if mdash_usersync.handle_get(self, path, qs):
            return
        # /addons and its viewer. Viewing is open to any signed-in user, so
        # this one checks the role per route rather than per module.
        if mdash_addons.handle_get(self, path, qs):
            return
        # /api/packages/*. Admin-only, checked inside.
        if mdash_packages.handle_get(self, path, qs):
            return
        # /fleet and /api/fleet. Viewing is open to any signed-in user; the
        # peer list is filtered to admins inside.
        if mdash_fleetui.handle_get(self, path, qs):
            return

        if path in ("/", "/index.html"):
            return self.page_status()
        if path == "/credentials":
            if not self.is_admin():
                return self.send_body("<h1>403</h1><p>Admins only.</p>", 403)
            return self.page_credentials()
        if path == "/files":
            return self.page_files(qs)
        if path == "/catalog":
            return self.page_catalog()
        if path == "/api/catalog":
            return self.api_catalog(qs)
        if path == "/api/catalog/genres":
            kind = (parse_qs(qs).get("kind") or ["movies"])[0]
            if kind not in CATALOG_KINDS:
                return self.send_body('{"error":"unknown kind"}', 400,
                                      "application/json")
            return self.send_body(json.dumps({"genres": catalog_genres(kind)}),
                                  200, "application/json")
        if path == "/topology":
            return self.page_topology()
        if path == "/api/topology":
            try:
                with open(TOPO_FILE) as f:
                    return self.send_body(f.read(), 200, "application/json")
            except FileNotFoundError:
                return self.send_body(
                    '{"error":"topology not collected yet - the collector runs '
                    'every 2 minutes"}', 200, "application/json")
            except Exception:
                return self.send_body('{"error":"topology unreadable"}', 200,
                                      "application/json")
        if path == "/appstore":
            # Deploying software is an admin action, so the page that offers it
            # is admin-only too - no point rendering buttons that will 403.
            if not self.is_admin():
                return self.send_body("<h1>403</h1><p>Admins only.</p>", 403)
            return self.page_appstore()
        if path == "/api/appstore":
            if not self.is_admin():
                return self.send_body('{"error":"admins only"}', 403,
                                      "application/json")
            cat = app_catalog()
            return self.send_body(json.dumps({
                "fetched": cat.get("fetched", 0),
                "commit": cat.get("commit", ""),
                "apps": cat.get("apps", []),
                "compose": [{k: v for k, v in t.items() if k != "compose"}
                            for t in cat.get("compose", [])],
                "capacity": host_capacity(),
                "hosts": deploy_targets(),
                "sources": cat.get("sources", []),
            }), 200, "application/json")
        if path == "/api/svcicon":
            # Artwork for the status page, which every signed-in user can see,
            # so this is session-gated rather than admin-gated. The name is
            # matched against the indexed set before any fetch happens.
            body = svc_icon_bytes(parse_qs(qs).get("name", [""])[0])
            if body is None:
                return self.send_body(b"", 404, "image/svg+xml")
            return self.send_body(body, 200, "image/svg+xml",
                                  [("Cache-Control", "public, max-age=86400")])
        if path == "/api/appicon":
            # Only the app store shows these, and that is admin-only. Gating it
            # too keeps a non-admin from making this process fetch anything.
            if not self.is_admin():
                return self.send_body(b"", 403, "image/svg+xml")
            body = icon_bytes(parse_qs(qs).get("slug", [""])[0])
            if body is None:
                return self.send_body(b"", 404, "image/svg+xml")
            # Immutable in practice - upstream publishes a new name rather than
            # changing an existing icon - so let the browser keep it for a day.
            return self.send_body(body, 200, "image/svg+xml",
                                  [("Cache-Control", "public, max-age=86400")])
        # Namespaced under /api/runner/ deliberately: /api/jobs was already
        # taken by the file browser's copy-progress poller, and registering a
        # second handler for it silently shadowed the first.
        if path == "/api/runner/jobs":
            if not self.is_admin():
                return self.send_body('{"error":"admins only"}', 403,
                                      "application/json")
            return self.send_body(json.dumps({"jobs": job_list()}), 200,
                                  "application/json")
        if path == "/api/runner/joblog":
            if not self.is_admin():
                return self.send_body('{"error":"admins only"}', 403,
                                      "application/json")
            jid = (parse_qs(qs).get("id") or [""])[0]
            body = job_log(jid)
            if body is None:
                return self.send_body('{"error":"bad job id"}', 400,
                                      "application/json")
            return self.send_body(json.dumps({"log": body}), 200,
                                  "application/json")
        if path == "/users":
            if not self.is_admin():
                return self.send_body("<h1>403</h1><p>Admins only.</p>", 403)
            return self.page_users(parse_qs(qs).get("msg", [""])[0])
        if path == "/api/poster":
            item = (parse_qs(qs).get("id") or [""])[0]
            if not item.isalnum():
                return self.send_body(b"", 400, "image/jpeg")
            try:
                with open(JELLYFIN_KEY_FILE) as f:
                    key = f.read().strip()
                r = subprocess.run(
                    ["curl", "-sf", "--max-time", "10",
                     "-H", f"X-Emby-Token: {key}",
                     f"{jellyfin_base()}/Items/{item}"
                     f"/Images/Primary?maxHeight=450&quality=80"],
                    capture_output=True, timeout=14)
                if r.returncode != 0 or not r.stdout:
                    return self.send_body(b"", 404, "image/jpeg")
                # Posters are immutable per item id; let the browser cache them.
                return self.send_body(r.stdout, 200, "image/jpeg",
                                      extra=[("Cache-Control", "private, max-age=86400")])
            except Exception:
                return self.send_body(b"", 404, "image/jpeg")

        if path == "/api/todo":
            return self.send_body(json.dumps({"items": load_todo()}), 200, "application/json")

        if path == "/api/browse":
            want = (parse_qs(qs).get("path") or [BROWSE_ROOTS[0]])[0]
            d = safe_path(want)
            if d is None or not os.path.isdir(d):
                return self.send_body('{"error":"forbidden"}', 403, "application/json")
            entries = []
            try:
                for n in sorted(os.listdir(d), key=str.lower):
                    if n.startswith("$") or n == "System Volume Information":
                        continue
                    full = os.path.join(d, n)
                    try:
                        st = os.stat(full)
                    except Exception:
                        continue
                    isdir = os.path.isdir(full)
                    entries.append({"name": n, "path": full, "dir": isdir,
                                    "img": (not isdir) and preview_kind(full) in ("image", "raw"),
                                    "size": "" if isdir else human(st.st_size),
                                    "mtime": time.strftime("%Y-%m-%d %H:%M",
                                                           time.localtime(st.st_mtime))})
            except PermissionError:
                return self.send_body('{"error":"denied"}', 403, "application/json")
            entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
            parent = os.path.dirname(d)
            return self.send_body(json.dumps({
                "path": d,
                "parent": parent if safe_path(parent) else None,
                "roots": BROWSE_ROOTS,
                "entries": entries[:400],
                "truncated": len(entries) > 400,
            }), 200, "application/json")

        if path == "/api/thumb":
            want = (parse_qs(qs).get("path") or [""])[0]
            f = safe_path(want)
            if f is None or not os.path.isfile(f) or preview_kind(f) not in ("image", "raw"):
                return self.send_body(b"", 404, "image/jpeg")
            data = thumb_for(f)
            if not data:
                return self.send_body(b"", 404, "image/jpeg")
            return self.send_body(data, 200, "image/jpeg",
                                  extra=[("Cache-Control", "private, max-age=86400")])

        if path == "/api/download":
            want = (parse_qs(qs).get("path") or [""])[0]
            f = safe_path(want)
            if f is None or not os.path.isfile(f):
                return self.send_body('{"error":"forbidden"}', 403, "application/json")
            audit(self.current_user(), f"DOWNLOAD {f}")
            return self.send_file_stream(f)

        if path == "/api/file":
            want = (parse_qs(qs).get("path") or [""])[0]
            f = safe_path(want)
            if f is None or not os.path.isfile(f):
                return self.send_body('{"error":"forbidden"}', 403, "application/json")
            kind = preview_kind(f)
            size = os.path.getsize(f)
            ext = os.path.splitext(f)[1].lower()
            if kind == "image":
                if size > IMAGE_MAX:
                    return self.send_body('{"error":"too large"}', 413, "application/json")
                with open(f, "rb") as fh:
                    return self.send_body(fh.read(), 200, IMAGE_EXT[ext],
                                          extra=[("Content-Disposition", "inline")])
            if kind == "raw":
                data = raw_embedded_jpeg(f, prefer_large=True)
                if not data:
                    return self.send_body(json.dumps({
                        "kind": "raw", "name": os.path.basename(f), "size": human(size),
                        "note": "No embedded preview found in this RAW file."}),
                        200, "application/json")
                return self.send_body(data, 200, "image/jpeg",
                                      extra=[("Content-Disposition", "inline")])
            if kind == "pdf":
                if size > IMAGE_MAX:
                    return self.send_body('{"error":"too large"}', 413, "application/json")
                with open(f, "rb") as fh:
                    return self.send_body(fh.read(), 200, "application/pdf",
                                          extra=[("Content-Disposition", "inline")])
            if kind == "text":
                with open(f, "rb") as fh:
                    raw = fh.read(TEXT_MAX)
                txt = raw.decode("utf-8", "replace")
                if size > TEXT_MAX:
                    txt += f"\n\n--- truncated at {TEXT_MAX // 1024}KB of {human(size)} ---"
                return self.send_body(txt, 200, "text/plain; charset=utf-8")
            # media and everything else: metadata only, never the bytes
            return self.send_body(json.dumps({
                "kind": kind, "name": os.path.basename(f), "size": human(size),
                "note": ("Video and audio are not streamed through the dashboard - "
                         "play them in Jellyfin instead." if kind == "media"
                         else "No preview available for this file type."),
            }), 200, "application/json")

        if path == "/api/jobs":
            with _jobs_lock:
                return self.send_body(json.dumps({"jobs": list(_jobs.values())[-20:]}),
                                      200, "application/json")
        if path == "/api/downloads":
            rows = qbit_downloads()
            if rows is None:
                return self.send_body('{"error":"unreachable","items":[]}', 200, "application/json")
            return self.send_body(json.dumps({"items": rows}), 200, "application/json")
        return self.send_body("<h1>404</h1>", 404)

    def do_POST(self):
        p = urlparse(self.path).path
        # /api/claude/run and /api/claude/stop. Checks session and admin
        # itself, like every other branch here.
        if mdash_claude.handle_post(self, p):
            return
        # /tmux/scroll and /tmux/search. Checks session and admin itself.
        if mdash_tmux.handle_post(self, p):
            return
        if mdash_tunnel.handle_post(self, p):
            return
        # /api/usersync/*. Checks session and admin itself.
        if mdash_usersync.handle_post(self, p):
            return
        # /api/addons. Checks session and admin itself.
        if mdash_addons.handle_post(self, p):
            return
        # /api/fleet/*. Checks admin itself.
        if mdash_fleetui.handle_post(self, p):
            return
        # /api/packages. Checks session and admin itself.
        if mdash_packages.handle_post(self, p):
            return
        if p == "/api/todo":
            if not self.session_ok():
                return self.send_body('{"error":"unauthenticated"}', 401, "application/json")
            n = int(self.headers.get("Content-Length") or 0)
            if n > 4096:
                return self.send_body('{"error":"too large"}', 413, "application/json")
            try:
                body = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
            except Exception:
                return self.send_body('{"error":"bad json"}', 400, "application/json")
            items = todo_apply(body.get("action", ""), body)
            return self.send_body(json.dumps({"items": items}), 200, "application/json")
        if p in ("/api/update", "/api/deploy", "/api/service", "/api/sources"):
            # Anything that changes the host is admin-only. A 'user' account can
            # see that an update exists but cannot apply it.
            if not self.is_admin():
                return self.send_body('{"error":"admins only"}', 403,
                                      "application/json")
            n = int(self.headers.get("Content-Length") or 0)
            if n > 4096:
                return self.send_body('{"error":"too large"}', 413,
                                      "application/json")
            try:
                b = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
            except Exception:
                return self.send_body('{"error":"bad json"}', 400,
                                      "application/json")
            me = self.current_user()

            def bad(m, code=400):
                return self.send_body(json.dumps({"error": m}), code,
                                      "application/json")

            if p == "/api/update":
                svc = str(b.get("service") or "")
                r = update_recipes().get(svc)
                if not r:
                    return bad(f"no update recipe for '{svc}'")
                jid = enqueue(r["action"], dict(r["params"]), me)
                audit(me, f"UPDATE {svc} -> job {jid}")
                return self.send_body(json.dumps({"job": jid}), 200,
                                      "application/json")

            if p == "/api/sources":
                act = str(b.get("action") or "")
                cur = load_sources_file()
                if act == "refresh":
                    jid = enqueue("catalog.refresh", {}, me)
                    audit(me, f"CATALOG refresh -> job {jid}")
                    return self.send_body(json.dumps({"job": jid}), 200,
                                          "application/json")
                if act == "add":
                    kind = str(b.get("kind") or "")
                    if kind not in ("helpers", "compose"):
                        return bad("kind must be helpers or compose")
                    repo = str(b.get("repo") or "").strip().strip("/")
                    # Accept a pasted URL as well as owner/name - it is what
                    # anyone will have on their clipboard.
                    repo = re.sub(r"^https?://(www\.)?github\.com/", "", repo)
                    repo = re.sub(r"\.git$", "", repo)
                    if not SRC_REPO_RE.match(repo):
                        return bad("repository must look like owner/name")
                    ref = str(b.get("ref") or "main").strip() or "main"
                    if not SRC_REF_RE.match(ref):
                        return bad("branch has unexpected characters")
                    path = str(b.get("path") or "").strip().strip("/")
                    if not SRC_PATH_RE.match(path):
                        return bad("path has unexpected characters")
                    sid = re.sub(r"[^a-z0-9-]+", "-",
                                 (b.get("id") or repo.split("/")[-1]).lower()).strip("-")
                    if not SRC_ID_RE.match(sid or ""):
                        return bad("could not derive a usable id for that repo")
                    if any(r.get("id") == sid for r in cur[kind]):
                        return bad(f"a source called '{sid}' already exists")
                    row = {"id": sid, "name": str(b.get("name") or repo)[:80],
                           "repo": repo, "ref": ref, "path": path,
                           "enabled": True}
                    if kind == "helpers":
                        dirs = [d.strip().strip("/") for d in
                                str(b.get("dirs") or "ct").split(",") if d.strip()]
                        sets = []
                        for d in dirs:
                            if not SRC_PATH_RE.match(d):
                                return bad(f"bad script directory '{d}'")
                            tgt = ("ct" if d.split("/")[-1] in ("ct", "lxc")
                                   else "vm" if d.split("/")[-1] == "vm" else "host")
                            sets.append({"dir": d, "target": tgt,
                                         "label": row["name"]})
                        row["sets"] = sets
                    cur[kind].append(row)
                    save_sources_file(cur)
                    jid = enqueue("catalog.refresh", {}, me)
                    audit(me, f"SOURCE add {kind} {repo}@{ref} -> job {jid}")
                    return self.send_body(json.dumps({"job": jid, "id": sid}),
                                          200, "application/json")
                if act in ("remove", "toggle"):
                    sid = str(b.get("id") or "")
                    hit = None
                    for kind in ("helpers", "compose"):
                        for r in cur[kind]:
                            if r.get("id") == sid:
                                hit = (kind, r)
                    if not hit:
                        # The stock sources are re-asserted by the runner on
                        # every load, so there is nothing here to edit.
                        return bad("that source is built in and cannot be "
                                   "changed from here")
                    kind, row = hit
                    if act == "remove":
                        cur[kind] = [r for r in cur[kind] if r.get("id") != sid]
                    else:
                        row["enabled"] = not row.get("enabled", True)
                    save_sources_file(cur)
                    jid = enqueue("catalog.refresh", {}, me)
                    audit(me, f"SOURCE {act} {sid} -> job {jid}")
                    return self.send_body(json.dumps({"job": jid}), 200,
                                          "application/json")
                return bad("unknown sources action")

            if p == "/api/service":
                target = str(b.get("target") or "")
                op = str(b.get("op") or "")
                if op not in ("start", "stop", "restart"):
                    return bad("op must be start, stop or restart")
                r = service_control().get(target)
                if r:
                    params = dict(r["params"])
                    params["op"] = op
                    jid = enqueue(r["action"], params, me)
                elif target.startswith("ct:"):
                    # Container ids are not enumerated in a table - any LXC the
                    # collector reports can be controlled - so the id is checked
                    # for shape here and for existence again in the runner.
                    try:
                        cid = int(target[3:])
                    except ValueError:
                        return bad("bad container id")
                    jid = enqueue("service.ct", {"cid": cid, "op": op}, me)
                else:
                    return bad(f"'{target}' cannot be controlled from here")
                audit(me, f"SERVICE {op} {target} -> job {jid}")
                return self.send_body(json.dumps({"job": jid}), 200,
                                      "application/json")

            # deploy: either a new container from a helper script, or a compose
            # stack into a container that already runs docker.
            kind = str(b.get("kind") or "")
            slug = str(b.get("slug") or "")
            if not re.match(r"^[a-z0-9][a-z0-9._-]{0,63}$", slug):
                return bad("bad app id")
            cat = app_catalog()
            if kind == "script":
                if not any(a["slug"] == slug for a in cat.get("apps", [])):
                    return bad(f"'{slug}' is not in the helper-script catalog")
                params = {"slug": slug}
                # Optional operator overrides. Bounds are enforced again in the
                # runner against real free memory and storage.
                for k in ("cpu", "ram", "disk", "ctid"):
                    if b.get(k) not in (None, ""):
                        try:
                            params[k] = int(b[k])
                        except (TypeError, ValueError):
                            return bad(f"{k} must be a number")
                if b.get("hostname"):
                    h = str(b["hostname"])
                    if not re.match(r"^[a-z0-9][a-z0-9-]{0,62}$", h):
                        return bad("hostname must be lowercase letters, digits "
                                   "and dashes")
                    params["hostname"] = h
                jid = enqueue("deploy.script", params, me)
                audit(me, f"DEPLOY script {slug} {json.dumps(params)} -> job {jid}")
                return self.send_body(json.dumps({"job": jid}), 200,
                                      "application/json")
            if kind == "compose":
                if not any(t["slug"] == slug for t in cat.get("compose", [])):
                    return bad(f"'{slug}' is not in the compose catalog")
                try:
                    cid = int(b.get("cid"))
                except (TypeError, ValueError):
                    return bad("pick a container to deploy into")
                if not any(h["cid"] == cid and h.get("docker")
                           for h in deploy_targets()):
                    return bad(f"container {cid} is not a known docker host")
                jid = enqueue("deploy.compose", {"cid": cid, "slug": slug}, me)
                audit(me, f"DEPLOY compose {slug} into {cid} -> job {jid}")
                return self.send_body(json.dumps({"job": jid}), 200,
                                      "application/json")
            return bad("unknown deploy kind")
        if p == "/api/fileop":
            # Writes are admin-only. A 'user' account is read + preview.
            if not self.is_admin():
                return self.send_body('{"error":"admins only"}', 403, "application/json")
            n = int(self.headers.get("Content-Length") or 0)
            if n > 8192:
                return self.send_body('{"error":"too large"}', 413, "application/json")
            try:
                b = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
            except Exception:
                return self.send_body('{"error":"bad json"}', 400, "application/json")

            me = self.current_user()
            action = b.get("action", "")
            src = safe_path(b.get("src") or "")
            if src is None or not os.path.exists(src):
                return self.send_body('{"error":"source not found or outside allowed roots"}',
                                      400, "application/json")

            def bad(m, code=400):
                return self.send_body(json.dumps({"error": m}), code, "application/json")

            if action == "delete":
                # Never unlink. Move into an on-device trash folder so it is recoverable.
                t = trash_dir_for(src)
                base = os.path.basename(src.rstrip("/"))
                dest = os.path.join(t, f"{time.strftime('%Y%m%d-%H%M%S')}-{base}")
                try:
                    shutil.move(src, dest)
                except Exception as e:
                    audit(me, f"DELETE FAIL {src}: {e}")
                    return bad(str(e)[:200], 500)
                audit(me, f"DELETE {src} -> {dest}")
                return self.send_body(json.dumps({"ok": True, "trash": dest}),
                                      200, "application/json")

            if action == "rename":
                name = (b.get("name") or "").strip()
                if not name or "/" in name or name in (".", ".."):
                    return bad("invalid name")
                dest = os.path.join(os.path.dirname(src), name)
                if safe_path(dest) is None:
                    return bad("destination outside allowed roots")
                if os.path.exists(dest):
                    return bad("a file with that name already exists")
                try:
                    os.rename(src, dest)
                except Exception as e:
                    audit(me, f"RENAME FAIL {src}: {e}")
                    return bad(str(e)[:200], 500)
                audit(me, f"RENAME {src} -> {dest}")
                return self.send_body(json.dumps({"ok": True, "path": dest}),
                                      200, "application/json")

            if action == "mkdir":
                name = (b.get("name") or "").strip()
                if not name or "/" in name or name in (".", ".."):
                    return bad("invalid name")
                dest = os.path.join(src if os.path.isdir(src) else os.path.dirname(src), name)
                if safe_path(dest) is None:
                    return bad("destination outside allowed roots")
                if os.path.exists(dest):
                    return bad("already exists")
                try:
                    os.makedirs(dest)
                    os.chown(dest, 101000, 101000)
                except Exception as e:
                    return bad(str(e)[:200], 500)
                audit(me, f"MKDIR {dest}")
                return self.send_body(json.dumps({"ok": True, "path": dest}),
                                      200, "application/json")

            if action in ("move", "copy"):
                dstdir = safe_path(b.get("dst") or "")
                if dstdir is None or not os.path.isdir(dstdir):
                    return bad("destination folder not found or outside allowed roots")
                dest = os.path.join(dstdir, os.path.basename(src.rstrip("/")))
                if os.path.exists(dest):
                    return bad("destination already has a file with that name")
                if os.path.realpath(dest).startswith(os.path.realpath(src) + os.sep):
                    return bad("cannot move a folder inside itself")
                if action == "move":
                    try:
                        shutil.move(src, dest)
                    except Exception as e:
                        audit(me, f"MOVE FAIL {src} -> {dest}: {e}")
                        return bad(str(e)[:200], 500)
                    audit(me, f"MOVE {src} -> {dest}")
                    return self.send_body(json.dumps({"ok": True, "path": dest}),
                                          200, "application/json")
                jid = start_copy(src, dest, me)
                return self.send_body(json.dumps({"ok": True, "job": jid}),
                                      200, "application/json")

            return bad("unknown action")
        if p == "/users":
            if not self.is_admin():
                return self.send_body("<h1>403</h1><p>Admins only.</p>", 403)
            n = int(self.headers.get("Content-Length") or 0)
            if n > 4096:
                return self.send_body("<h1>413</h1>", 413)
            f = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            action = (f.get("action") or [""])[0]
            name = (f.get("username") or [""])[0].strip()
            pw = (f.get("password") or [""])[0]
            role = (f.get("role") or ["user"])[0]
            email = (f.get("email") or [""])[0].strip()
            auth = load_auth()
            users = auth.setdefault("users", {})
            me = self.current_user()
            admins = [u for u, v in users.items() if v.get("role") == "admin"]

            if not USERNAME_OK.match(name or ""):
                msg = "Invalid username."
            elif action == "add":
                if name in users:
                    msg = f"User '{name}' already exists."
                elif len(pw) < 8:
                    msg = "Password must be at least 8 characters."
                else:
                    salt, h = hash_pw(pw)
                    users[name] = {"salt": salt, "hash": h,
                                   "role": "admin" if role == "admin" else "user"}
                    if email:
                        users[name]["email"] = email
                    save_auth(auth)
                    # The plaintext exists only here, so this is the one moment
                    # the new account can be pushed to the services.
                    msg = f"Added user '{name}'. " + sync_note(
                        mdash_usersync.on_account_created(name, pw, me))
            elif action == "passwd":
                if name not in users:
                    msg = "No such user."
                elif len(pw) < 8:
                    msg = "Password must be at least 8 characters."
                else:
                    salt, h = hash_pw(pw)
                    users[name].update({"salt": salt, "hash": h})
                    save_auth(auth)
                    msg = f"Password updated for '{name}'. " + sync_note(
                        mdash_usersync.on_password_changed(name, pw, me))
            elif action == "email":
                ok, why = mdash_usersync.set_email(name, email, me)
                msg = (f"Email for '{name}' set to "
                       f"{email or 'the default'}.") if ok else why
            elif action == "role":
                if name not in users:
                    msg = "No such user."
                elif role != "admin" and admins == [name]:
                    msg = "Refusing to demote the last admin."
                else:
                    users[name]["role"] = "admin" if role == "admin" else "user"
                    save_auth(auth)
                    msg = f"Role for '{name}' set to {users[name]['role']}."
            elif action == "delete":
                if name == me:
                    msg = "You cannot delete your own account."
                elif name not in users:
                    msg = "No such user."
                elif users[name].get("role") == "admin" and admins == [name]:
                    msg = "Refusing to delete the last admin."
                else:
                    left = mdash_usersync.on_account_deleted(name, me)
                    del users[name]
                    save_auth(auth)
                    msg = f"Deleted user '{name}'."
                    if left:
                        # Deliberately not cascaded: those accounts hold watch
                        # history and photo libraries, and this is the one
                        # action that cannot be undone from here.
                        msg += (" Their accounts on " + ", ".join(left) +
                                " were left in place - remove them there if you "
                                "want them gone.")
            else:
                msg = "Unknown action."
            return self.redirect("/users?msg=" + quote(msg))
        if p != "/login":
            return self.send_body("<h1>404</h1>", 404)
        if self.locked():
            err = '<div class="err">Too many attempts. Try again in a few minutes.</div>'
            return self.send_body(LOGIN_PAGE.replace("__ERR__", err), 429)
        n = int(self.headers.get("Content-Length") or 0)
        if n > 4096:
            return self.send_body("<h1>413</h1>", 413)
        body = self.rfile.read(n).decode("utf-8", "replace")
        form = parse_qs(body)
        user = (form.get("username") or [""])[0].strip()
        pw = (form.get("password") or [""])[0]
        try:
            auth = load_auth()
        except Exception:
            return self.send_body("<h1>auth not configured</h1>", 500)
        if user and pw and verify_user(auth, user, pw):
            _fails.pop(self.client_ip(), None)
            audit(user, f"login OK from {self.client_ip()}")
            flags = "; Secure" if self.secure_ctx() else ""
            cookie = (f"{COOKIE}={make_session(auth, user)}; Path=/; Max-Age={SESSION_SECONDS}"
                      f"; HttpOnly; SameSite=Lax{flags}")
            return self.redirect("/", [("Set-Cookie", cookie)])
        self.note_fail()
        audit(user or "-", f"login FAILED from {self.client_ip()}")
        time.sleep(1)
        err = '<div class="err">Incorrect password.</div>'
        return self.send_body(LOGIN_PAGE.replace("__ERR__", err), 401)


if __name__ == "__main__":
    # Peers are polled from here rather than from the collector: a slow or
    # unreachable host must not eat into the collector's start timeout, and the
    # fleet page stays fresh between collector runs. No-op with no peers.
    mdash_fleet.start_poller()
    ThreadingHTTPServer(BIND, Handler).serve_forever()
