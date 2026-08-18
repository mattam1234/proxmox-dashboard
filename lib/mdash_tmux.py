"""Admin-only tmux terminal for the media dashboard.

Lives in its own module so the dashboard script needs only a few lines to wire
it in. Everything here is reached through the dashboard's own session cookie and
admin role - there is no second listening port and no second credential.

Wiring (in media-dashboard-web.py):

    import sys; sys.path.insert(0, "/usr/local/lib/mdash")
    import mdash_tmux

    # in do_GET, after the session check:
    if mdash_tmux.handle_get(self, path, qs):
        return

    # in nav(), inside the `if admin:` block:
    out += a("/tmux", "Terminal")

A pane opened here is a root shell on this host, so: admin role is re-checked at
attach time rather than trusted from page load, the websocket verifies Origin,
the session name is matched against the live list instead of being interpolated,
attaches are capped and idle-timed, and both attach and detach are audited.
"""
import base64
import fcntl
import hashlib
import html
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time

TMUX_BIN = "/usr/bin/tmux"
XTERM_DIR = "/usr/share/javascript/xterm"
RESURRECT_DIR = "/root/.tmux/resurrect"
SESSION_NAME_OK = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")

TERM_IDLE_SECONDS = 4 * 3600      # a forgotten browser tab must not hold a pty
TERM_MAX_ATTACH = 4               # concurrent browser terminals
READ_CHUNK = 65536

_attach_count = [0]
_attach_lock = threading.Lock()


def _main_attr(name, default=None):
    """Borrow nav()/audit()/CSS from the dashboard script without importing it."""
    return getattr(sys.modules.get("__main__"), name, default)


def _audit(user, msg):
    fn = _main_attr("audit")
    if fn:
        try:
            fn(user, msg)
        except Exception:
            pass


# ------------------------------------------------------------------ tmux data
def tmux_cmd(*args, timeout=5):
    """Run one tmux command against the default server -> (rc, stdout)."""
    try:
        r = subprocess.run([TMUX_BIN, *args], capture_output=True, timeout=timeout)
        return r.returncode, r.stdout.decode("utf-8", "replace")
    except Exception:
        return 1, ""


def tmux_sessions():
    """Sessions with their panes, or [] when no tmux server is running."""
    rc, out = tmux_cmd("list-sessions", "-F",
                       "#{session_name}\t#{session_windows}\t#{session_attached}"
                       "\t#{session_created}\t#{session_activity}")
    if rc != 0:
        return []
    sessions, index = [], {}
    now = int(time.time())
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 5:
            continue
        try:
            age = now - int(f[3])
            idle = now - int(f[4])
        except ValueError:
            age = idle = 0
        s = {"name": f[0], "windows": f[1], "attached": f[2] != "0",
             "age": age, "idle": idle, "panes": []}
        index[f[0]] = s
        sessions.append(s)

    rc, out = tmux_cmd("list-panes", "-a", "-F",
                       "#{session_name}\t#{window_index}\t#{window_name}"
                       "\t#{pane_index}\t#{pane_current_command}"
                       "\t#{pane_current_path}\t#{pane_width}x#{pane_height}")
    if rc == 0:
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) < 7 or f[0] not in index:
                continue
            index[f[0]]["panes"].append(
                {"window": f[1], "window_name": f[2], "pane": f[3],
                 "cmd": f[4], "path": f[5], "size": f[6]})
    return sessions


def tmux_overview():
    """Header facts: boot unit state, last resurrect snapshot, live sessions."""
    try:
        r = subprocess.run(["systemctl", "is-active", "tmux-boot.service"],
                           capture_output=True, timeout=5)
        unit = r.stdout.decode().strip() or "unknown"
    except Exception:
        unit = "unknown"
    snap, snap_age = None, None
    try:
        target = os.path.join(RESURRECT_DIR,
                              os.readlink(os.path.join(RESURRECT_DIR, "last")))
        st = os.stat(target)
        snap = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
        snap_age = int(time.time() - st.st_mtime)
    except Exception:
        pass
    sessions = tmux_sessions()
    return {"unit": unit, "snapshot": snap, "snapshot_age": snap_age,
            "server": bool(sessions), "sessions": sessions,
            "attached": _attach_count[0], "max_attach": TERM_MAX_ATTACH}


# ------------------------------------------------------------ scrollback
# A browser attached over the websocket can only scroll tmux's history if the
# terminal forwards wheel events, which a phone has no way to produce. These
# helpers drive tmux's own copy-mode from the server instead, so scrollback
# works from a button or a swipe on any device.
SCROLL_ACTIONS = {
    "up": ("scroll-up", True),
    "down": ("scroll-down", True),
    "pageup": ("page-up", False),
    "pagedown": ("page-down", False),
    "top": ("history-top", False),
    "bottom": ("history-bottom", False),
}
MAX_SCROLL_LINES = 40


def scroll_state(session):
    """(in_copy_mode, lines_scrolled_back) for a session's active pane."""
    rc, out = tmux_cmd("display-message", "-p", "-t", session,
                       "#{pane_in_mode} #{scroll_position}")
    if rc != 0:
        return False, 0
    parts = (out or "").split()
    in_mode = bool(parts and parts[0] == "1")
    try:
        pos = int(parts[1]) if len(parts) > 1 and parts[1] else 0
    except ValueError:
        pos = 0
    return in_mode, pos


def scroll(session, action, lines=3):
    """Move through a session's scrollback. Returns the resulting state."""
    if action == "exit":
        tmux_cmd("send-keys", "-t", session, "-X", "cancel")
        return scroll_state(session)

    entry = SCROLL_ACTIONS.get(action)
    if not entry:
        return None
    cmd, repeatable = entry

    in_mode, _ = scroll_state(session)
    if not in_mode:
        # copy-mode is what exposes the history; entering it does not disturb
        # the running program, and "exit" puts the pane back on the live tail.
        tmux_cmd("copy-mode", "-t", session)

    if repeatable:
        n = max(1, min(MAX_SCROLL_LINES, int(lines or 1)))
        tmux_cmd("send-keys", "-t", session, "-X", "-N", str(n), cmd)
    else:
        tmux_cmd("send-keys", "-t", session, "-X", cmd)

    in_mode, pos = scroll_state(session)
    # Landing back at the bottom means there is nothing above to look at, so
    # leave copy-mode rather than stranding the pane in it.
    if in_mode and pos == 0 and action in ("down", "pagedown", "bottom"):
        tmux_cmd("send-keys", "-t", session, "-X", "cancel")
        in_mode = False
    return {"in_mode": in_mode, "pos": pos}


def search_history(session, text):
    """Jump to the most recent occurrence of `text` in the scrollback."""
    in_mode, _ = scroll_state(session)
    if not in_mode:
        tmux_cmd("copy-mode", "-t", session)
    tmux_cmd("send-keys", "-t", session, "-X", "search-backward", text)
    in_mode, pos = scroll_state(session)
    return {"in_mode": in_mode, "pos": pos}


def session_exists(name):
    """Match against the live list - never interpolate a client string."""
    if not name or not SESSION_NAME_OK.match(name):
        return False
    return any(s["name"] == name for s in tmux_sessions())


# ------------------------------------------------------------ websocket frames
WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x2, 0x8, 0x9, 0xA


def ws_accept_key(key):
    return base64.b64encode(
        hashlib.sha1((key + WS_MAGIC).encode()).digest()).decode()


def ws_frame(payload, opcode=OP_BIN):
    """Server -> client frame. Server frames are never masked."""
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


def ws_take_frame(buf):
    """Pull one whole frame from buf -> (opcode, payload, rest), or None."""
    if len(buf) < 2:
        return None
    b0, b1 = buf[0], buf[1]
    opcode = b0 & 0x0F
    masked = b1 & 0x80
    ln = b1 & 0x7F
    off = 2
    if ln == 126:
        if len(buf) < 4:
            return None
        ln = struct.unpack("!H", buf[2:4])[0]
        off = 4
    elif ln == 127:
        if len(buf) < 10:
            return None
        ln = struct.unpack("!Q", buf[2:10])[0]
        off = 10
    if ln > (1 << 20):                 # a terminal never sends a 1MB frame
        raise ValueError("oversized frame")
    mask = b""
    if masked:
        if len(buf) < off + 4:
            return None
        mask = buf[off:off + 4]
        off += 4
    if len(buf) < off + ln:
        return None
    data = bytearray(buf[off:off + ln])
    if masked:
        for i in range(ln):
            data[i] ^= mask[i % 4]
    return opcode, bytes(data), buf[off + ln:]


# -------------------------------------------------------------------- the pty
def pty_resize(fd, cols, rows):
    cols = max(20, min(int(cols), 500))
    rows = max(5, min(int(rows), 200))
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


def pty_attach(session, cols, rows):
    """Fork a pty running `tmux attach` against an existing session.

    pty.fork() is what gives the child a controlling terminal; tmux refuses to
    attach without one. The child execs immediately, so forking from a server
    thread is safe.
    """
    pid, fd = pty.fork()
    if pid == 0:                       # child
        try:
            os.environ.pop("TMUX", None)   # never nest inside our own server
            os.environ["TERM"] = "xterm-256color"
            os.environ.setdefault("LANG", "C.UTF-8")
            os.execv(TMUX_BIN, [TMUX_BIN, "-u", "attach-session", "-t", session])
        except Exception:
            pass
        os._exit(1)
    pty_resize(fd, cols, rows)
    return pid, fd


def _reap(pid, fd):
    """Detach the tmux client and clean up. The tmux session itself lives on."""
    try:
        os.close(fd)
    except Exception:
        pass
    try:
        os.kill(pid, signal.SIGHUP)
    except Exception:
        pass
    for _ in range(50):
        try:
            if os.waitpid(pid, os.WNOHANG)[0]:
                return
        except ChildProcessError:
            return
        except Exception:
            break
        time.sleep(0.02)
    try:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    except Exception:
        pass


# ------------------------------------------------------------------ ws handler
def serve_terminal(h, session):
    """Upgrade this request to a websocket and bridge it to a tmux pty."""
    user = h.current_user()
    key = h.headers.get("Sec-WebSocket-Key")
    if not key or "websocket" not in (h.headers.get("Upgrade") or "").lower():
        return h.send_body('{"error":"expected websocket"}', 400, "application/json")

    # Cross-site websocket hijacking: the browser will happily open a ws from
    # any origin and attach our cookies, so the Origin must match this host.
    origin = h.headers.get("Origin") or ""
    if origin:
        want = (h.headers.get("Host") or "").split(":")[0].lower()
        got = origin.split("://")[-1].split("/")[0].split(":")[0].lower()
        if not want or got != want:
            _audit(user, f"tmux terminal REFUSED bad origin {origin!r}")
            return h.send_body('{"error":"bad origin"}', 403, "application/json")

    if not session_exists(session):
        return h.send_body('{"error":"no such session"}', 404, "application/json")

    with _attach_lock:
        if _attach_count[0] >= TERM_MAX_ATTACH:
            return h.send_body('{"error":"too many terminals open"}', 429,
                               "application/json")
        _attach_count[0] += 1

    pid = fd = None
    try:
        h.wfile.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + ws_accept_key(key).encode() + b"\r\n\r\n")
        h.wfile.flush()
        h.close_connection = True

        pid, fd = pty_attach(session, 80, 24)
        _audit(user, f"tmux terminal ATTACH session={session}")

        sock = h.connection
        sock.setblocking(False)
        os.set_blocking(fd, False)
        buf = b""
        last = time.time()

        while True:
            r, _w, _x = select.select([sock, fd], [], [], 30)
            now = time.time()
            if not r:
                if now - last > TERM_IDLE_SECONDS:
                    break
                try:                       # keep intermediaries from timing out
                    sock.sendall(ws_frame(b"", OP_PING))
                except OSError:
                    break
                continue
            last = now

            if fd in r:                    # pty -> browser
                try:
                    data = os.read(fd, READ_CHUNK)
                except (OSError, BlockingIOError):
                    data = b""
                if not data:
                    break
                try:
                    sock.sendall(ws_frame(data, OP_BIN))
                except OSError:
                    break

            if sock in r:                  # browser -> pty
                try:
                    chunk = sock.recv(READ_CHUNK)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while True:
                    try:
                        got = ws_take_frame(buf)
                    except ValueError:
                        got = None
                        buf = b""
                        break
                    if not got:
                        break
                    opcode, payload, buf = got
                    if opcode == OP_CLOSE:
                        raise StopIteration
                    if opcode == OP_PING:
                        try:
                            sock.sendall(ws_frame(payload, OP_PONG))
                        except OSError:
                            raise StopIteration
                        continue
                    if opcode not in (OP_TEXT, OP_BIN):
                        continue
                    try:
                        msg = json.loads(payload.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    if msg.get("t") == "i":
                        try:
                            os.write(fd, str(msg.get("d", "")).encode())
                        except OSError:
                            raise StopIteration
                    elif msg.get("t") == "r":
                        pty_resize(fd, msg.get("c", 80), msg.get("r", 24))
    except (StopIteration, BrokenPipeError, ConnectionResetError):
        pass
    except Exception:
        pass
    finally:
        if pid:
            _reap(pid, fd)
        with _attach_lock:
            _attach_count[0] = max(0, _attach_count[0] - 1)
        _audit(user, f"tmux terminal DETACH session={session}")
        try:
            h.connection.sendall(ws_frame(b"", OP_CLOSE))
        except Exception:
            pass


# ----------------------------------------------------------------- the page
CSS = """
/* Same as .cld: a bare 1fr floors at min-content, and a terminal is wide
   unbreakable content, so the column could outgrow the viewport. */
.tmx{display:grid;grid-template-columns:300px minmax(0,1fr);gap:14px;align-items:start}
.tmx>*{min-width:0}
#termwrap{min-width:0;max-width:100%}
@media(max-width:900px){.tmx{grid-template-columns:1fr}}
.tmx .side{display:flex;flex-direction:column;gap:10px}
/* #hdr is a sibling of .tmx, not a child - scoped to `.tmx .hdr` it never
   matched and the row rendered as bare text. */
.hdr{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);
  padding:8px 12px;background:var(--card);border:1px solid var(--line);border-radius:8px}
.hdr b{color:var(--fg);font-weight:600}
.sess{background:var(--card);border:1px solid var(--line);border-radius:8px;
  padding:10px 12px;cursor:pointer;text-align:left;width:100%;font:inherit;color:inherit}
.sess:hover{border-color:var(--accent)}
.sess.on{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.sess .nm{font-weight:600;display:flex;justify-content:space-between;align-items:center}
.sess .dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none}
.sess .dot.live{background:#16a34a}
.sess .meta{font-size:11px;color:var(--muted);margin-top:4px}
.sess .pane{font-size:11px;color:var(--muted);font-family:ui-monospace,monospace;
  margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#termwrap{background:#000;border:1px solid var(--line);border-radius:8px;padding:8px;
  min-height:420px}
#termbar{display:flex;justify-content:space-between;align-items:center;gap:10px;
  font-size:12px;color:var(--muted);margin-bottom:6px}
#termbar .st{font-weight:600}
#termbar .st.ok{color:#16a34a}
#termbar .st.off{color:var(--bad)}
.warn{font-size:12px;color:var(--muted);border-left:3px solid var(--bad);
  padding:6px 10px;margin-bottom:12px}
/* --- Phones: same treatment as the Claude page. The session list collapses
   behind a picker instead of pushing the terminal below the fold, and the
   terminal gets a definite height so the fit addon sizes it to the screen. --- */
.pickrow{display:none}
.keybar{display:none}
@media (max-width:900px){
.tmx{display:block}
.pickrow{display:flex;margin-bottom:9px}
.sesspick{flex:1;min-width:0;display:flex;align-items:center;gap:8px;min-height:44px;
  padding:0 13px;background:var(--card);border:1px solid var(--line);border-radius:8px;
  font:inherit;color:inherit;text-align:left;cursor:pointer}
.sesspick .cur{flex:1;min-width:0;font-weight:600;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.sesspick .chev{flex:none;color:var(--muted);font-size:11px;transition:transform .15s}
.tmx.sideopen .sesspick .chev{transform:rotate(180deg)}
.tmx .side{display:none;max-height:50vh;overflow:auto;margin-bottom:10px}
.tmx.sideopen .side{display:flex}
.warn{font-size:11.5px;padding:5px 9px;margin-bottom:9px}
.hdr{gap:10px;font-size:11.5px;padding:6px 10px;margin-bottom:9px}
#termwrap{min-height:0;height:56vh;height:56dvh;padding:6px}
/* A phone keyboard has no esc, tab, ctrl or arrows, so the shell is unusable
   without these. Sticky to the bottom so it rides above the soft keyboard. */
.keybar{display:flex;gap:6px;overflow-x:auto;overscroll-behavior-x:contain;
  position:sticky;bottom:0;z-index:6;background:var(--bg);
  margin-top:8px;padding:7px 0 calc(7px + env(safe-area-inset-bottom));
  scrollbar-width:none;-ms-overflow-style:none}
.keybar::-webkit-scrollbar{display:none}
.keybar button{flex:0 0 auto;min-width:46px;min-height:42px;padding:0 12px;
  border:1px solid var(--line);border-radius:8px;background:var(--card);
  color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:13px;font-weight:600;cursor:pointer}
.keybar button:active,.keybar button.on{background:var(--accent);color:#fff;
  border-color:var(--accent)}
}
@media (pointer:coarse){.sess{padding:13px 12px}}

/* --- scrollback controls -------------------------------------------------
   tmux keeps the history, but a browser can only reach it by forwarding wheel
   events - which a touchscreen never produces. These drive tmux copy-mode
   over HTTP instead, so the same controls work on a phone and a desktop. */
.sbar{display:flex;gap:6px;align-items:center;margin-top:8px;overflow-x:auto;
  overscroll-behavior-x:contain;scrollbar-width:none;-ms-overflow-style:none}
.sbar::-webkit-scrollbar{display:none}
.sbar button{flex:0 0 auto;min-width:46px;min-height:42px;padding:0 12px;
  border:1px solid var(--line);border-radius:8px;background:var(--card);
  color:var(--fg);font:inherit;font-size:13px;font-weight:600;cursor:pointer}
.sbar button:hover{border-color:var(--accent)}
.sbar button:active{background:var(--accent);color:#fff;border-color:var(--accent)}
.sbar .pos{flex:0 0 auto;font-size:12px;color:var(--muted);padding:0 4px;
  white-space:nowrap;font-variant-numeric:tabular-nums}
.sbar .pos.back{color:var(--accent);font-weight:600}
.sbar input{flex:1 1 130px;min-width:110px;min-height:42px;padding:0 11px;
  border:1px solid var(--line);border-radius:8px;background:var(--card);
  color:var(--fg);font:inherit;font-size:13px}
.sbar input:focus{outline:2px solid var(--accent);outline-offset:1px}
/* A live-tail button only makes sense while looking at history. */
.sbar #s-live{display:none}
.sbar.inhist #s-live{display:inline-block;background:var(--accent);color:#fff;
  border-color:var(--accent)}
@media(max-width:900px){.sbar{position:sticky;bottom:0;z-index:7;
  background:var(--bg);padding:7px 0 0}
  .sbar input{flex:1 1 90px;min-width:80px}}
"""

PAGE = """<!doctype html>
<meta charset="utf-8"><title>Terminal</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/tmux/vendor/xterm.css">
<style>__CSS__</style>
<div class="wrap">
__NAV__
<h1>tmux</h1>
<p class="warn">These panes are root shells on the host. Anything typed here runs
as root, and the session keeps running after you close the tab.</p>
<div class="hdr" id="hdr">loading...</div>
<div class="tmx">
  <div class="pickrow">
    <button class="sesspick" id="sesspick" aria-expanded="false">
      <span class="cur" id="curpick">Sessions</span>
      <span class="chev">&#9660;</span>
    </button>
  </div>
  <div class="side" id="sessions"></div>
  <div>
    <div id="termbar">
      <span>attached to <b id="curname">-</b></span>
      <span class="st off" id="status">disconnected</span>
    </div>
    <div id="termwrap"></div>
    <div class="sbar" id="sbar">
      <button data-s="top" title="oldest output">&#8673;</button>
      <button data-s="pageup" title="page back">&#9650;&#9650;</button>
      <button data-s="up" title="scroll back">&#9650;</button>
      <button data-s="down" title="scroll forward">&#9660;</button>
      <button data-s="pagedown" title="page forward">&#9660;&#9660;</button>
      <button data-s="bottom" id="s-live" title="back to live output">live</button>
      <span class="pos" id="spos">live</span>
      <input id="hsearch" type="search" placeholder="find in history"
             autocapitalize="none" autocorrect="off" spellcheck="false">
    </div>
    <div class="keybar" id="keybar">
      <button data-k="kbd" aria-label="show keyboard">&#9000;</button>
      <button data-k="esc">esc</button>
      <button data-k="tab">tab</button>
      <button data-k="ctrl" id="k-ctrl">ctrl</button>
      <button data-k="left">&#8592;</button>
      <button data-k="up">&#8593;</button>
      <button data-k="down">&#8595;</button>
      <button data-k="right">&#8594;</button>
      <button data-k="cc">^C</button>
      <button data-k="cd">^D</button>
      <button data-k="cz">^Z</button>
      <button data-k="home">home</button>
      <button data-k="end">end</button>
      <button data-k="pgup">pgup</button>
      <button data-k="pgdn">pgdn</button>
      <button data-k="pipe">|</button>
      <button data-k="tilde">~</button>
      <button data-k="slash">/</button>
    </div>
  </div>
</div>
</div>
<script src="/tmux/vendor/xterm.js"></script>
<script src="/tmux/vendor/xterm-addon-fit.js"></script>
<script>__JS__</script>
"""

JS = """
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',
  '"':'&quot;',"'":'&#39;'}[c]));
const ago=s=>{s=Math.max(0,s|0);if(s<60)return s+'s';if(s<3600)return (s/60|0)+'m';
  if(s<86400)return (s/3600|0)+'h';return (s/86400|0)+'d';};

let term,fit,ws,current=null;

// ---- soft-keyboard support -------------------------------------------------
const ESC=String.fromCharCode(27);
const KEYSEQ={esc:ESC,tab:String.fromCharCode(9),
  up:ESC+'[A',down:ESC+'[B',right:ESC+'[C',left:ESC+'[D',
  cc:String.fromCharCode(3),cd:String.fromCharCode(4),cz:String.fromCharCode(26),
  home:ESC+'[H',end:ESC+'[F',pgup:ESC+'[5~',pgdn:ESC+'[6~',
  pipe:'|',tilde:'~',slash:'/'};
let ctrlArmed=false;

function wsSend(d){if(ws&&ws.readyState===1)ws.send(JSON.stringify({t:'i',d:d}));}
function setCtrl(on){ctrlArmed=on;
  const b=document.getElementById('k-ctrl');if(b)b.classList.toggle('on',on);}

// xterm takes input through a hidden textarea; focusing it is what actually
// raises the keyboard on a phone, and term.focus() alone often will not.
function focusTerm(){
  const t=document.querySelector('#termwrap textarea');
  if(t)t.focus({preventScroll:true}); else if(term)term.focus();
}

function initKeys(){
  document.querySelectorAll('#keybar button').forEach(b=>{
    // Without this the button takes focus on press and the keyboard drops away.
    b.addEventListener('pointerdown',e=>e.preventDefault());
    b.addEventListener('click',()=>{
      const k=b.dataset.k;
      if(k==='kbd'){focusTerm();return;}
      if(k==='ctrl'){setCtrl(!ctrlArmed);focusTerm();return;}
      const q=KEYSEQ[k]; if(q)wsSend(q);
      focusTerm();
    });
  });
  const w=document.getElementById('termwrap');
  if(w)w.addEventListener('click',()=>{
    if(term&&!term.hasSelection())focusTerm();});
}

// ---- scrollback ------------------------------------------------------------
// tmux owns the history; these calls drive its copy-mode from the server, so
// they behave the same whether they came from a button, a swipe or a key.
let scrollPos=0, sPend=0, sTimer=null;

function setPos(){
  const el=document.getElementById('spos');
  const bar=document.getElementById('sbar');
  if(!el)return;
  el.textContent=scrollPos>0?('\u2191 '+scrollPos+' line'+(scrollPos===1?'':'s')+' back'):'live';
  el.classList.toggle('back',scrollPos>0);
  if(bar)bar.classList.toggle('inhist',scrollPos>0);
}

async function sscroll(action,lines){
  if(!current)return;
  try{
    const r=await fetch('/tmux/scroll',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({session:current,action:action,lines:lines||3})});
    const d=await r.json();
    if(d&&!d.error){scrollPos=d.pos|0;setPos();}
  }catch(e){}
}

// A swipe produces a stream of small deltas; batch them into one request so a
// long drag is a few calls rather than dozens.
function scrollBy(lines){
  sPend+=lines;
  if(sTimer)return;
  sTimer=setTimeout(()=>{
    const n=sPend; sPend=0; sTimer=null;
    if(n)sscroll(n>0?'up':'down',Math.min(40,Math.abs(n)));
  },60);
}

async function hsearch(){
  const box=document.getElementById('hsearch');
  const text=(box.value||'').trim();
  if(!text||!current)return;
  try{
    const r=await fetch('/tmux/search',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({session:current,text:text})});
    const d=await r.json();
    if(d&&!d.error){scrollPos=d.pos|0;setPos();}
  }catch(e){}
}

function initScroll(){
  document.querySelectorAll('#sbar button[data-s]').forEach(b=>{
    // Keep focus in the terminal so the phone keyboard does not drop away.
    b.addEventListener('pointerdown',e=>e.preventDefault());
    b.addEventListener('click',()=>sscroll(b.dataset.s,10));
  });
  const box=document.getElementById('hsearch');
  if(box)box.addEventListener('keydown',e=>{
    if(e.key==='Enter'){e.preventDefault();hsearch();}});

  // Touch: drag down for older output, up for newer. Only takes over the
  // gesture once it is clearly vertical, so tap-to-focus and text selection
  // still work.
  const w=document.getElementById('termwrap');
  if(w){
    let y0=null,x0=null,acc=0,own=false;
    w.addEventListener('touchstart',e=>{
      if(e.touches.length!==1){y0=null;return;}
      y0=e.touches[0].clientY; x0=e.touches[0].clientX; acc=0; own=false;
    },{passive:true});
    w.addEventListener('touchmove',e=>{
      if(y0===null||e.touches.length!==1)return;
      const y=e.touches[0].clientY, x=e.touches[0].clientX;
      const dy=y-y0, dx=x-x0;
      if(!own){
        if(Math.abs(dy)<10||Math.abs(dy)<Math.abs(dx))return;
        own=true;                       // vertical drag: this is a scroll
      }
      y0=y; acc+=dy;
      const step=16;                    // px of travel per line of history
      if(Math.abs(acc)>=step){
        const lines=Math.trunc(acc/step); acc-=lines*step;
        scrollBy(lines);
      }
      e.preventDefault();               // stop the page scrolling instead
    },{passive:false});
    w.addEventListener('touchend',()=>{y0=null;own=false;},{passive:true});
  }

  // Desktop: the wheel goes to tmux already when mouse reporting is on, so
  // this only adds the keyboard shortcuts a terminal user expects.
  document.addEventListener('keydown',e=>{
    if(!current||!e.shiftKey)return;
    if(e.key==='PageUp'){e.preventDefault();sscroll('pageup');}
    else if(e.key==='PageDown'){e.preventDefault();sscroll('pagedown');}
  });
}

function setStatus(t,ok){const e=document.getElementById('status');
  e.textContent=t;e.className='st '+(ok?'ok':'off');}

function initTerm(){
  const narrow=window.matchMedia('(max-width:900px)').matches;
  term=new Terminal({fontSize:narrow?11:13,cursorBlink:true,scrollback:5000,
    fontFamily:'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace',
    theme:{background:'#000000',foreground:'#e6edf3'}});
  fit=new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById('termwrap'));
  fit.fit();
  term.onData(async d=>{
    if(ctrlArmed&&d.length===1){
      const c=d.toLowerCase().charCodeAt(0);
      if(c>=97&&c<=122)d=String.fromCharCode(c-96);
      setCtrl(false);
    }
    // Typing while looking at history would otherwise be swallowed by tmux's
    // copy-mode key bindings, so leave history first and then send the key.
    if(scrollPos>0)await sscroll('exit');
    wsSend(d);
  });
  window.addEventListener('resize',()=>{fit.fit();sendSize();});
}
function sendSize(){
  if(ws&&ws.readyState===1)ws.send(JSON.stringify({t:'r',c:term.cols,r:term.rows}));
}

// The picker stands in for the session list once it is collapsed on a phone.
function setPick(){
  const el=document.getElementById('curpick');
  if(el)el.textContent=current||'Sessions';
}
function setSide(open){
  const c=document.querySelector('.tmx'); if(c)c.classList.toggle('sideopen',open);
  const p=document.getElementById('sesspick');
  if(p)p.setAttribute('aria-expanded',open?'true':'false');
}

function attach(name){
  if(ws){try{ws.close();}catch(e){}ws=null;}
  current=name;
  document.getElementById('curname').textContent=name;
  setPick(); setSide(false);
  document.querySelectorAll('.sess').forEach(b=>
    b.classList.toggle('on',b.dataset.name===name));
  term.reset();
  scrollPos=0; setPos();
  setStatus('connecting',false);
  const proto=location.protocol==='https:'?'wss:':'ws:';
  ws=new WebSocket(proto+'//'+location.host+'/tmux/ws?session='+encodeURIComponent(name));
  ws.binaryType='arraybuffer';
  ws.onopen=()=>{setStatus('attached',true);fit.fit();sendSize();term.focus();};
  ws.onmessage=e=>{term.write(new Uint8Array(e.data));};
  ws.onclose=()=>{setStatus('disconnected',false);};
  ws.onerror=()=>{setStatus('error',false);};
}

async function refresh(){
  let d;
  try{d=await (await fetch('/api/tmux',{cache:'no-store'})).json();}
  catch(e){return;}
  const h=document.getElementById('hdr');
  h.innerHTML='<span>boot unit <b>'+esc(d.unit)+'</b></span>'
    +'<span>snapshot <b>'+esc(d.snapshot||'never')+'</b>'
    +(d.snapshot_age!=null?' ('+ago(d.snapshot_age)+' ago)':'')+'</span>'
    +'<span>sessions <b>'+d.sessions.length+'</b></span>'
    +'<span>terminals <b>'+d.attached+'/'+d.max_attach+'</b></span>';
  const box=document.getElementById('sessions');
  if(!d.sessions.length){box.innerHTML='<div class="sess">no tmux server running</div>';return;}
  box.innerHTML=d.sessions.map(s=>{
    const panes=s.panes.slice(0,4).map(p=>'<div class="pane">'+esc(p.window+':'+p.pane)
      +' '+esc(p.cmd)+' <span style="opacity:.6">'+esc(p.path)+'</span></div>').join('');
    return '<button class="sess'+(s.name===current?' on':'')+'" data-name="'+esc(s.name)+'">'
      +'<div class="nm">'+esc(s.name)+'<span class="dot'+(s.attached?' live':'')+'"></span></div>'
      +'<div class="meta">'+esc(s.windows)+' window'+(s.windows==='1'?'':'s')
      +' &middot; up '+ago(s.age)+' &middot; idle '+ago(s.idle)+'</div>'+panes+'</button>';
  }).join('');
  box.querySelectorAll('.sess').forEach(b=>{
    if(b.dataset.name)b.onclick=()=>attach(b.dataset.name);});
}

document.getElementById('sesspick').onclick=()=>setSide(
  !document.querySelector('.tmx').classList.contains('sideopen'));

initTerm();
initKeys();
initScroll();
setPos();
refresh();
setInterval(refresh,5000);
"""


# ------------------------------------------------------------------- routing
_VENDOR = {
    "xterm.js": (os.path.join(XTERM_DIR, "xterm.js"), "application/javascript"),
    "xterm.css": (os.path.join(XTERM_DIR, "xterm.css"), "text/css"),
    "xterm-addon-fit.js": (os.path.join(XTERM_DIR, "addons/fit/xterm-addon-fit.js"),
                           "application/javascript"),
}


def handle_get(h, path, qs):
    """Handle a tmux route. Returns True when it took the request.

    The caller must already have checked that a session cookie is valid; the
    admin role is checked here, per request.
    """
    if path not in ("/tmux", "/api/tmux", "/tmux/ws") and \
            not path.startswith("/tmux/vendor/"):
        return False

    if not h.is_admin():
        if path.startswith("/api/") or path == "/tmux/ws":
            h.send_body('{"error":"forbidden"}', 403, "application/json")
        else:
            h.send_body("<h1>403</h1><p>Admins only.</p>", 403)
        return True

    if path == "/tmux":
        nav = _main_attr("nav")
        base_css = _main_attr("CSS", "")
        page = PAGE.replace("__CSS__", base_css + CSS)
        page = page.replace("__NAV__", nav("/tmux", h.current_user(), True) if nav else "")
        page = page.replace("__JS__", JS)
        h.send_body(page)
        return True

    if path == "/api/tmux":
        h.send_body(json.dumps(tmux_overview()), 200, "application/json")
        return True

    if path.startswith("/tmux/vendor/"):
        name = path.rsplit("/", 1)[-1]
        entry = _VENDOR.get(name)
        if not entry:
            h.send_body(b"", 404, "application/octet-stream")
            return True
        try:
            with open(entry[0], "rb") as f:
                body = f.read()
        except Exception:
            h.send_body(b"", 404, "application/octet-stream")
            return True
        h.send_body(body, 200, entry[1],
                    extra=[("Cache-Control", "private, max-age=3600")])
        return True

    if path == "/tmux/ws":
        from urllib.parse import parse_qs
        session = (parse_qs(qs).get("session") or [""])[0]
        serve_terminal(h, session)
        return True

    return False


def handle_post(h, path):
    """Handle a tmux POST. Returns True when it took the request.

    Scrollback control lives here rather than in the websocket so it works on a
    phone, where there is no wheel to forward and a touch drag would otherwise
    be swallowed by the page.
    """
    if path not in ("/tmux/scroll", "/tmux/search"):
        return False
    if not h.session_ok():
        h.send_body('{"error":"unauthenticated"}', 401, "application/json")
        return True
    if not h.is_admin():
        h.send_body('{"error":"forbidden"}', 403, "application/json")
        return True

    try:
        n = int(h.headers.get("Content-Length") or 0)
    except ValueError:
        n = 0
    if n > 4096:
        h.send_body('{"error":"too large"}', 413, "application/json")
        return True
    try:
        body = json.loads(h.rfile.read(n).decode("utf-8", "replace"))
    except Exception:
        h.send_body('{"error":"bad json"}', 400, "application/json")
        return True

    session = (body.get("session") or "").strip()
    # Matched against the live list rather than interpolated, same rule the
    # attach path follows.
    if not SESSION_NAME_OK.match(session) or not session_exists(session):
        h.send_body('{"error":"no such session"}', 404, "application/json")
        return True

    if path == "/tmux/search":
        text = (body.get("text") or "").strip()[:120]
        if not text:
            h.send_body('{"error":"empty search"}', 400, "application/json")
            return True
        state = search_history(session, text)
        _audit(h.current_user(), f"tmux terminal SEARCH session={session} {text!r}")
        h.send_body(json.dumps(state or {}), 200, "application/json")
        return True

    action = (body.get("action") or "").strip()
    if action != "exit" and action not in SCROLL_ACTIONS:
        h.send_body('{"error":"bad action"}', 400, "application/json")
        return True
    try:
        lines = int(body.get("lines") or 3)
    except (TypeError, ValueError):
        lines = 3
    state = scroll(session, action, lines)
    if state is None:
        h.send_body('{"error":"bad action"}', 400, "application/json")
        return True
    if isinstance(state, tuple):
        state = {"in_mode": state[0], "pos": state[1]}
    h.send_body(json.dumps(state), 200, "application/json")
    return True
