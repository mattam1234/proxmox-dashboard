"""Admin-only Claude Code console for the media dashboard.

Lives in its own module so the dashboard script needs only a few lines to wire
it in. Everything here is reached through the dashboard's own session cookie and
admin role - there is no second listening port and no second credential.

Wiring (in media-dashboard-web.py):

    import mdash_claude

    # in do_GET, after the session check:
    if mdash_claude.handle_get(self, path, qs):
        return

    # at the top of do_POST (it checks the session itself):
    if mdash_claude.handle_post(self, p):
        return

    # in nav(), inside the `if admin:` block:
    out += a("/claude", "Claude")

Two things here are worth knowing before reading the code.

*Where a run executes.* The dashboard unit is sandboxed (ProtectSystem=strict,
ProtectHome=read-only), so a plain child process could not even write Claude's
own session files, let alone administer the host. Rather than loosen that
sandbox for the whole dashboard, each run is launched as a transient systemd
unit via `systemd-run --pipe`: PID 1 spawns it, so it lands outside the
dashboard's sandbox with full root, while the dashboard keeps its hardening.
We keep the pipe, so stopping a run is `systemctl stop` on a named unit rather
than a guessed kill.

*Why an allowlist instead of --dangerously-skip-permissions.* That flag (and
--permission-mode bypassPermissions) is refused outright when Claude runs as
root. The supported way to get non-interactive approval is an explicit
permissions allowlist, passed per run via --settings. The effect is the same -
tools run without prompting - and anything not on the list is denied rather
than hanging a headless run forever.

A run here is therefore root on the hypervisor with tools auto-approved, so:
admin is re-checked per request rather than trusted from page load, prompts are
length-capped, concurrent runs are capped, and the prompt plus every single tool
call is written to the dashboard audit log.

Display deliberately reads Claude's own transcript files rather than only the
live stream, so sessions started from a terminal - not just from this page -
show up here with full history.
"""
import glob
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid

CLAUDE_BIN = "/root/.local/bin/claude"
PROJECTS_DIR = "/root/.claude/projects"
DEFAULT_CWD = "/root"
UNIT_PREFIX = "mdash-claude-"

MAX_CONCURRENT = 2                # simultaneous runs started from this page
MAX_PROMPT = 8000                 # characters
MAX_BODY = 32 * 1024              # bytes of POST body
KEEP_RUNS = 40                    # run records held in memory
SESSION_LIST_MAX = 80
TEXT_CLIP = 6000                  # chars per message shown
TOOL_CLIP = 1500                  # chars per tool input/result shown
META_HEAD_LINES = 60              # lines read when summarising a session

SID_OK = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
MODEL_OK = re.compile(r"^[A-Za-z0-9._-]{1,40}$")

# Auto-approval list. Claude refuses the bypass flag as root (see module
# docstring), so every tool it may use without prompting is named here. A tool
# missing from this list is denied, not prompted - new tool names therefore
# fail closed and need adding here on purpose.
ALLOW_TOOLS = [
    "Bash", "Read", "Edit", "Write", "NotebookEdit", "Glob", "Grep",
    "WebFetch", "WebSearch", "Task", "Skill", "TodoWrite", "ToolSearch",
    "BashOutput", "KillShell", "ExitPlanMode", "EnterPlanMode",
    "ListAgents", "SendMessage", "TaskOutput", "TaskStop", "Monitor",
    "ScheduleWakeup", "PushNotification", "ReportFindings",
    "CronCreate", "CronDelete", "CronList",
    "EnterWorktree", "ExitWorktree", "RemoteTrigger", "DesignSync",
]
RUN_SETTINGS = json.dumps({"permissions": {"allow": ALLOW_TOOLS}})

RUN_PATH = ("/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:"
            "/usr/bin:/sbin:/bin")

# ------------------------------------------------------------- run controls
EFFORT_LEVELS = ["low", "medium", "high", "xhigh", "max"]

# Permission modes offered in the UI. bypassPermissions is deliberately absent:
# Claude refuses it as root (see module docstring), so offering it would only
# produce failed runs. "default" means our own allowlist, nothing extra.
PERMISSION_MODES = ["plan", "acceptEdits", "auto", "dontAsk"]

MODEL_CHOICES = ["opus", "sonnet", "haiku", "fable"]

# Agent types the CLI ships with, plus anything defined on disk. Kept as a
# plain list because the CLI has no "list agent types" command - re-check it
# after a Claude Code upgrade.
BUILTIN_AGENTS = ["Explore", "Plan", "general-purpose", "claude-code-guide"]
AGENT_DIRS = ["/root/.claude/agents"]

# Where a skill can come from. The bundled skills that ship inside the CLI
# unpack under /tmp, which PrivateTmp hides from the dashboard, so they are
# listed from the static set below rather than discovered.
SKILL_DIRS = [
    "/root/.claude/skills",
    "/root/.claude/plugins/marketplaces/*/plugins/*/skills/*",
    "/root/.claude/plugins/marketplaces/*/external_plugins/*/skills/*",
]
BUILTIN_SKILLS = [
    ("code-review", "Review the current diff or a PR for bugs and cleanups"),
    ("security-review", "Security review of pending changes on this branch"),
    ("simplify", "Reuse/simplification/efficiency pass over changed code"),
    ("run", "Launch and drive this project's app to see a change working"),
    ("init", "Write a CLAUDE.md describing this codebase"),
    ("loop", "Run a prompt or command on a recurring interval"),
    ("schedule", "Create or manage scheduled cloud agents"),
    ("update-config", "Configure hooks, permissions and settings.json"),
    ("dataviz", "Chart and dashboard design guidance"),
    ("artifact-design", "Design guidance for published artifacts"),
    ("claude-api", "Reference for the Claude API and Anthropic SDKs"),
]

NAME_OK = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")

_opts_cache = [None]              # (checked_at, options dict)
OPTS_TTL = 60.0

_ratelimit = [None]               # last rate-limit window seen on a run stream
_foreign_cache = [None]           # (checked_at, sids held by a terminal Claude)


def rate_limit_snapshot():
    """The subscription usage window last reported by a run started here."""
    with _cache_lock:
        return dict(_ratelimit[0]) if _ratelimit[0] else None

_runs = {}                        # id -> run record
_run_seq = [0]
_runs_lock = threading.Lock()

_tcache = {}                      # transcript path -> incremental parse state
_mcache = {}                      # transcript path -> (size, mtime, meta)
_units_cache = [None]             # (checked_at, live session ids) from systemd
_cache_lock = threading.Lock()


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


def _clip(s, n):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + f"\n... [{len(s) - n} more characters]"


# ------------------------------------------------- what this host can offer
def _skill_meta(path):
    """Name and description from a SKILL.md front matter block."""
    name = os.path.basename(os.path.dirname(path))
    desc = ""
    try:
        with open(path, "r", errors="replace") as f:
            head = [next(f, "") for _ in range(20)]
    except OSError:
        return None
    for line in head:
        line = line.strip()
        if line.startswith("name:"):
            name = line[5:].strip().strip("\"'") or name
        elif line.startswith("description:"):
            desc = line[12:].strip().strip("\"'")
    return {"name": name, "desc": _clip(desc, 200), "source": "disk"}


def list_skills():
    """Skills this host can resolve, disk-discovered first then the built-ins."""
    out, seen = [], set()
    for pattern in SKILL_DIRS:
        for d in sorted(glob.glob(pattern)):
            p = os.path.join(d, "SKILL.md")
            if not os.path.isfile(p):
                continue
            m = _skill_meta(p)
            if m and m["name"] not in seen and NAME_OK.match(m["name"]):
                seen.add(m["name"])
                out.append(m)
    for name, desc in BUILTIN_SKILLS:
        if name not in seen:
            seen.add(name)
            out.append({"name": name, "desc": desc, "source": "built-in"})
    return out


def list_agent_types():
    """Agent types: the CLI's own, plus any defined under /root/.claude/agents."""
    out = list(BUILTIN_AGENTS)
    for d in AGENT_DIRS:
        try:
            for n in sorted(os.listdir(d)):
                if n.endswith(".md"):
                    n = n[:-3]
                    if NAME_OK.match(n) and n not in out:
                        out.append(n)
        except OSError:
            continue
    return out


def _cli(args, timeout=25):
    """Run a claude subcommand as the dashboard, returning stdout or ''."""
    try:
        r = subprocess.run([CLAUDE_BIN] + args, capture_output=True, text=True,
                           timeout=timeout, cwd=DEFAULT_CWD,
                           env={"HOME": DEFAULT_CWD, "PATH": RUN_PATH,
                                "TERM": "dumb"})
        return r.stdout or ""
    except Exception:
        return ""


def env_status():
    """Version, MCP servers and plugins - what a run will actually have."""
    version = (_cli(["--version"], timeout=15).strip().split() or [""])[0]

    mcp = []
    for line in _cli(["mcp", "list"], timeout=40).splitlines():
        line = line.strip()
        if not line or ":" not in line or line.lower().startswith("checking"):
            continue
        name, _, rest = line.partition(":")
        ok = "✔" in rest or "connected" in rest.lower()
        url = rest.split("-")[0].strip() if "-" in rest else rest.strip()
        mcp.append({"name": name.strip()[:60], "url": url[:80], "ok": ok})

    plugins = []
    for p in sorted(glob.glob(
            "/root/.claude/plugins/marketplaces/*/plugins/*")):
        if os.path.isdir(p):
            plugins.append(os.path.basename(p))
    return {"version": version, "mcp": mcp, "plugins": plugins[:40],
            "plugin_count": len(plugins)}


def options():
    """Everything the composer needs to render, cached briefly."""
    now = time.time()
    with _cache_lock:
        c = _opts_cache[0]
        if c and now - c[0] < OPTS_TTL:
            return c[1]
    opts = {"models": MODEL_CHOICES, "efforts": EFFORT_LEVELS,
            "modes": PERMISSION_MODES, "agents": list_agent_types(),
            "skills": list_skills(), "env": env_status()}
    with _cache_lock:
        _opts_cache[0] = (now, opts)
    return opts


def _in_our_unit(pid):
    """True when this pid is one of our own transient run units."""
    try:
        with open(f"/proc/{int(pid)}/cgroup") as f:
            return UNIT_PREFIX in f.read()
    except (OSError, ValueError, TypeError):
        return False


def foreign_live_sids():
    """Sessions currently held open by a Claude this dashboard did not start.

    Resuming one of those would put two writers on a single transcript - the
    terminal session and the run - so it is refused rather than silently
    interleaved.
    """
    now = time.time()
    with _cache_lock:
        c = _foreign_cache[0]
        if c and now - c[0] < 4.0:
            return set(c[1])
    out = set()
    try:
        for a in json.loads(_cli(["agents", "--json"], timeout=20) or "[]"):
            if not isinstance(a, dict):
                continue
            sid, pid = a.get("sessionId") or "", a.get("pid")
            if not SID_OK.match(sid) or not pid:
                continue
            if not os.path.isdir(f"/proc/{pid}"):
                continue          # stale entry, process is gone
            if not _in_our_unit(pid):
                out.add(sid)
    except Exception:
        pass
    with _cache_lock:
        _foreign_cache[0] = (now, set(out))
    return out


def host_tasks():
    """Every Claude process on this host, not just runs started from here.

    `claude agents --json` reports interactive and background sessions alike,
    which is what makes this a host-wide view rather than a dashboard-only one.
    """
    tasks = []
    raw = _cli(["agents", "--json"], timeout=25)
    try:
        for a in json.loads(raw or "[]"):
            if not isinstance(a, dict):
                continue
            started = a.get("startedAt")
            tasks.append({
                "kind": a.get("kind") or "session",
                "name": str(a.get("name") or "")[:40],
                "sid": a.get("sessionId") or "",
                "pid": a.get("pid"),
                "cwd": str(a.get("cwd") or "")[:80],
                "status": a.get("status") or "idle",
                # startedAt is epoch milliseconds.
                "started": int(started / 1000) if isinstance(started, (int, float)) else None,
                "source": "cli",
            })
    except Exception:
        pass

    with _runs_lock:
        for r in _runs.values():
            if r["state"] == "running":
                tasks.append({"kind": "dashboard", "name": f"run #{r['id']}",
                              "sid": r["sid"], "pid": None, "cwd": r["cwd"],
                              "status": "busy", "started": r["started"],
                              "source": "dashboard", "tools": r["tools"]})
    return tasks


# --------------------------------------------------------------- transcripts
def session_path(sid):
    """Absolute path of a session's transcript, or None. sid is validated."""
    if not SID_OK.match(sid or ""):
        return None
    try:
        projects = os.listdir(PROJECTS_DIR)
    except OSError:
        return None
    for proj in projects:
        p = os.path.join(PROJECTS_DIR, proj, sid + ".jsonl")
        if os.path.isfile(p):
            return p
    return None


def _tool_line(name, inp):
    """One-line summary of a tool call - the argument that identifies it."""
    if not isinstance(inp, dict):
        return ""
    if name == "Bash":
        return inp.get("command") or inp.get("description") or ""
    if name in ("Read", "Write", "Edit", "NotebookEdit"):
        return inp.get("file_path") or ""
    if name in ("Grep", "Glob"):
        return " ".join(x for x in (inp.get("pattern"), inp.get("path")) if x)
    if name in ("Task", "Agent"):
        return inp.get("description") or ""
    if name == "WebFetch":
        return inp.get("url") or ""
    if name == "WebSearch":
        return inp.get("query") or ""
    if name == "Skill":
        return inp.get("skill") or ""
    if name == "TodoWrite":
        todos = inp.get("todos")
        if isinstance(todos, list):
            return f"{len(todos)} item(s)"
    try:
        return json.dumps(inp)[:200]
    except Exception:
        return ""


def _result_text(block):
    """Flatten a tool_result content field, which may be a string or blocks."""
    c = block.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        out = []
        for b in c:
            if isinstance(b, dict):
                if b.get("type") == "text":
                    out.append(b.get("text") or "")
                elif b.get("type") == "image":
                    out.append("[image]")
            elif isinstance(b, str):
                out.append(b)
        return "\n".join(out)
    return "" if c is None else str(c)


def _events_from_line(d):
    """Normalise one transcript line into zero or more display events."""
    t = d.get("type")
    ts = (d.get("timestamp") or "")[:19].replace("T", " ")
    side = bool(d.get("isSidechain"))

    if t == "summary":
        return []
    if t not in ("user", "assistant"):
        return []
    if d.get("isMeta"):
        return []

    msg = d.get("message") or {}
    content = msg.get("content")
    out = []

    if isinstance(content, str):
        text = content.strip()
        # Command wrappers and injected reminders are plumbing, not conversation.
        if not text or text.startswith("<"):
            return []
        out.append({"role": t, "kind": "text", "ts": ts, "side": side,
                    "text": _clip(text, TEXT_CLIP)})
        return out

    if not isinstance(content, list):
        return []

    for b in content:
        if not isinstance(b, dict):
            continue
        bt = b.get("type")
        if bt == "text":
            text = (b.get("text") or "").strip()
            if not text or (t == "user" and text.startswith("<")):
                continue
            out.append({"role": t, "kind": "text", "ts": ts, "side": side,
                        "text": _clip(text, TEXT_CLIP)})
        elif bt == "thinking":
            text = (b.get("thinking") or "").strip()
            if text:
                out.append({"role": t, "kind": "thinking", "ts": ts,
                            "side": side, "text": _clip(text, TEXT_CLIP)})
        elif bt == "tool_use":
            name = b.get("name") or "tool"
            out.append({"role": "assistant", "kind": "tool", "ts": ts,
                        "side": side, "tool": name, "id": b.get("id") or "",
                        "text": _clip(_tool_line(name, b.get("input")), TOOL_CLIP)})
        elif bt == "tool_result":
            out.append({"role": "user", "kind": "output", "ts": ts,
                        "side": side, "err": bool(b.get("is_error")),
                        "text": _clip(_result_text(b), TOOL_CLIP)})
    return out


def read_events(path):
    """Parsed events for a transcript, re-reading only what was appended.

    Transcripts are append-only and reach several MB, so a poll every couple of
    seconds must not re-parse the whole file.
    """
    try:
        st = os.stat(path)
    except OSError:
        return []
    with _cache_lock:
        c = _tcache.get(path)
        if c and c["ino"] == st.st_ino and c["off"] <= st.st_size:
            off, events, tail = c["off"], c["events"], c["tail"]
        else:
            off, events, tail = 0, [], b""
        if off == st.st_size:
            return events

    try:
        with open(path, "rb") as f:
            f.seek(off)
            chunk = f.read()
    except OSError:
        return events

    buf = tail + chunk
    lines = buf.split(b"\n")
    tail = lines.pop()                       # keep any partial trailing line
    # Resuming mid-file: recover the Task call the fallback attributes to.
    last_task = ""
    for ev in reversed(events[-500:]):
        if ev.get("spawns"):
            last_task = ev.get("id") or ""
            break
    for raw in lines:
        if not raw.strip():
            continue
        try:
            d = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            continue
        # Subagent work arrives as sidechain lines carrying the id of the Task
        # call that spawned them. The key has been spelled several ways across
        # versions, and older transcripts omit it entirely - hence the fallback
        # to the most recent Task call, which is what the nesting really means.
        parent = (d.get("parentToolUseID") or d.get("parent_tool_use_id")
                  or d.get("parentToolUseId") or "")
        for ev in _events_from_line(d):
            ev["i"] = len(events)
            if ev.get("kind") == "tool" and ev.get("tool") in ("Task", "Agent") \
                    and not ev.get("side"):
                last_task = ev.get("id") or ""
                ev["spawns"] = True
            if ev.get("side"):
                ev["p"] = parent or last_task
            events.append(ev)

    with _cache_lock:
        _tcache[path] = {"ino": st.st_ino, "off": st.st_size,
                         "events": events, "tail": tail}
        if len(_tcache) > 24:                # bound memory on a long-lived server
            for k in list(_tcache)[:8]:
                if k != path:
                    _tcache.pop(k, None)
    return events


def _meta(path):
    """Cheap summary of a session: title, cwd, size, last activity."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (st.st_size, int(st.st_mtime))
    with _cache_lock:
        c = _mcache.get(path)
        if c and c[0] == key:
            return dict(c[1])

    title, cwd, ver, branch = "", DEFAULT_CWD, "", ""
    seen_cwd = False
    entries = 0
    try:
        with open(path, "rb") as f:
            head = []
            for _ in range(META_HEAD_LINES):
                line = f.readline()
                if not line:
                    break
                head.append(line)
            rest = f.read()
        entries = sum(b.count(b"\n") for b in head) + rest.count(b"\n")
        for raw in head:
            try:
                d = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                continue
            # First cwd wins: that is where the session was started, which is
            # how Claude locates it on resume. Later lines drift with any cd.
            if not seen_cwd and d.get("cwd"):
                cwd, seen_cwd = d["cwd"], True
            ver = d.get("version") or ver
            branch = d.get("gitBranch") or branch
            if title:
                continue
            if d.get("type") == "user" and not d.get("isMeta"):
                m = d.get("message") or {}
                c = m.get("content")
                text = ""
                if isinstance(c, str):
                    text = c
                elif isinstance(c, list):
                    for b in c:
                        if isinstance(b, dict) and b.get("type") == "text":
                            text = b.get("text") or ""
                            break
                text = text.strip()
                if text and not text.startswith("<"):
                    title = " ".join(text.split())[:120]
    except OSError:
        return None

    meta = {"title": title or "(no prompt)", "cwd": cwd, "entries": entries,
            "bytes": st.st_size, "mtime": int(st.st_mtime),
            "version": ver, "branch": branch}
    with _cache_lock:
        _mcache[path] = (key, dict(meta))
    return dict(meta)


def list_sessions():
    """Every Claude session on this host, newest activity first."""
    found = []
    try:
        projects = sorted(os.listdir(PROJECTS_DIR))
    except OSError:
        projects = []
    for proj in projects:
        d = os.path.join(PROJECTS_DIR, proj)
        if not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            if not n.endswith(".jsonl"):
                continue
            sid = n[:-6]
            if not SID_OK.match(sid):
                continue
            found.append((sid, os.path.join(d, n)))

    live = {}
    with _runs_lock:
        for r in _runs.values():
            if r["state"] == "running":
                live[r["sid"]] = r["id"]
    for sid in live_sids():           # includes runs orphaned by a restart
        live.setdefault(sid, None)

    elsewhere = foreign_live_sids()
    out = []
    for sid, path in found:
        m = _meta(path)
        if not m:
            continue
        m.update(id=sid, running=sid in live, run=live.get(sid),
                 elsewhere=sid in elsewhere)
        out.append(m)
    out.sort(key=lambda s: (s["running"], s["mtime"]), reverse=True)
    return out[:SESSION_LIST_MAX]


# ---------------------------------------------------------------- run control
def _run_public(r):
    return {k: r[k] for k in ("id", "sid", "state", "started", "ended", "user",
                              "prompt", "tools", "cost", "turns", "error",
                              "model", "cwd", "effort", "mode", "agent")}


def active_runs():
    with _runs_lock:
        return [_run_public(r) for r in _runs.values() if r["state"] == "running"]


def live_sids():
    """Session ids with a run in flight, according to systemd rather than memory.

    A run is a transient unit, so it survives a dashboard restart while the
    in-memory record does not. Asking systemd means a restart mid-run shows the
    conversation as still running instead of silently orphaning it. The unit
    name carries the full session id for exactly this lookup.
    """
    now = time.time()
    with _cache_lock:
        cached = _units_cache[0]
        if cached and now - cached[0] < 2.0:
            return set(cached[1])
    sids = set()
    try:
        r = subprocess.run(
            ["systemctl", "list-units", "--no-legend", "--no-pager", "--plain",
             "--type=service", "--state=active", f"{UNIT_PREFIX}*.service"],
            capture_output=True, text=True, timeout=10)
        for line in (r.stdout or "").splitlines():
            unit = line.split()[0] if line.split() else ""
            if not unit.startswith(UNIT_PREFIX) or not unit.endswith(".service"):
                continue
            rest = unit[len(UNIT_PREFIX):-len(".service")]
            sid = rest.split("-", 1)[1] if "-" in rest else ""
            if SID_OK.match(sid):
                sids.add(sid)
    except Exception:
        pass
    with _cache_lock:
        _units_cache[0] = (now, set(sids))
    return sids


def unit_for_sid(sid):
    """Name of the live unit running that session, if any."""
    if not SID_OK.match(sid or ""):
        return None
    try:
        r = subprocess.run(
            ["systemctl", "list-units", "--no-legend", "--no-pager", "--plain",
             "--type=service", "--state=active", f"{UNIT_PREFIX}*.service"],
            capture_output=True, text=True, timeout=10)
        for line in (r.stdout or "").splitlines():
            unit = line.split()[0] if line.split() else ""
            if unit.startswith(UNIT_PREFIX) and unit.endswith("-" + sid + ".service"):
                return unit[:-len(".service")]
    except Exception:
        pass
    return None


def _reader(r, proc):
    """Consume the stream-json output of one run: status, cost, audit trail."""
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                # stderr is merged into this pipe; keep it for the error field.
                r["stderr"] = (r.get("stderr", "") + line + "\n")[-4000:]
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            t = d.get("type")
            if t == "rate_limit_event":
                # The subscription's own usage window. It rides the live stream
                # and is never written to the transcript, so this is the only
                # place it can be captured - and only for runs started here.
                info = d.get("rate_limit_info") or {}
                if isinstance(info, dict):
                    with _cache_lock:
                        _ratelimit[0] = {"seen": int(time.time()),
                                         "status": info.get("status"),
                                         "kind": info.get("rateLimitType"),
                                         "resets": info.get("resetsAt"),
                                         "overage": info.get("isUsingOverage")}
            elif t == "system" and d.get("subtype") == "init":
                r["sid"] = d.get("session_id") or r["sid"]
            elif t == "assistant":
                for b in ((d.get("message") or {}).get("content") or []):
                    if isinstance(b, dict) and b.get("type") == "tool_use":
                        name = b.get("name") or "tool"
                        r["tools"] += 1
                        _audit(r["user"], f"CLAUDE TOOL run={r['id']} "
                                          f"{name}: {_tool_line(name, b.get('input'))[:200]}")
            elif t == "result" or "total_cost_usd" in d:
                r["cost"] = d.get("total_cost_usd")
                r["turns"] = d.get("num_turns")
                if d.get("is_error"):
                    r["error"] = str(d.get("result") or d.get("subtype") or "error")[:500]
    except Exception as e:
        r["error"] = r.get("error") or str(e)[:300]
    finally:
        try:
            rc = proc.wait(timeout=30)
        except Exception:
            rc = -1
        with _runs_lock:
            if r["state"] == "running":
                if r.get("stopped"):
                    r["state"] = "stopped"
                elif rc == 0 and not r.get("error"):
                    r["state"] = "done"
                else:
                    r["state"] = "error"
                    if not r.get("error"):
                        r["error"] = (r.get("stderr") or f"exit code {rc}").strip()[:500]
            r["ended"] = int(time.time())
        _audit(r["user"], f"CLAUDE {r['state'].upper()} run={r['id']} sid={r['sid']} "
                          f"tools={r['tools']} turns={r.get('turns')} "
                          f"cost={r.get('cost')}")


def start_run(user, prompt, resume_sid=None, model=None, effort=None,
              mode=None, agent=None):
    """Launch one headless run. Returns (run_record, error_message)."""
    prompt = (prompt or "").strip()
    if not prompt:
        return None, "empty prompt"
    if len(prompt) > MAX_PROMPT:
        return None, f"prompt too long (limit {MAX_PROMPT} characters)"
    if model and not MODEL_OK.match(model):
        return None, "bad model"
    if effort and effort not in EFFORT_LEVELS:
        return None, "bad effort level"
    if mode and mode not in PERMISSION_MODES:
        return None, "bad permission mode"
    if agent and (not NAME_OK.match(agent) or agent not in list_agent_types()):
        return None, "bad agent"

    cwd = DEFAULT_CWD
    if resume_sid:
        path = session_path(resume_sid)
        if not path:
            return None, "no such session"
        if resume_sid in foreign_live_sids():
            return None, ("that conversation is open in a terminal right now - "
                          "resuming it here would have two Claudes writing to "
                          "one transcript. Start a new conversation instead.")
        m = _meta(path) or {}
        cand = m.get("cwd") or DEFAULT_CWD
        # Resuming has to happen in the session's own directory, since that is
        # how Claude locates the conversation.
        cwd = cand if os.path.isdir(cand) else DEFAULT_CWD

    # systemd is the authority on what is actually in flight, so the cap holds
    # even for runs this process has forgotten across a restart.
    in_flight = live_sids()
    with _runs_lock:
        for r in _runs.values():
            if r["state"] == "running":
                in_flight.add(r["sid"])
        if len(in_flight) >= MAX_CONCURRENT:
            return None, f"{MAX_CONCURRENT} runs already going - wait for one to finish"
        if resume_sid and resume_sid in in_flight:
            return None, "that conversation already has a run in flight"
        _run_seq[0] += 1
        jid = _run_seq[0]

    sid = resume_sid or str(uuid.uuid4())
    # The full session id goes in the unit name so a live run can be matched
    # back to its conversation after a dashboard restart (see live_sids).
    unit = f"{UNIT_PREFIX}{jid}-{sid}"
    cmd = [
        "systemd-run", "--pipe", "--quiet", "--collect", "--unit", unit,
        f"--property=WorkingDirectory={cwd}",
        "--setenv=HOME=/root", f"--setenv=PATH={RUN_PATH}", "--setenv=TERM=dumb",
        CLAUDE_BIN, "-p", prompt,
        "--output-format", "stream-json", "--verbose",
        "--settings", RUN_SETTINGS,
    ]
    cmd += ["--resume", sid] if resume_sid else ["--session-id", sid]
    if model:
        cmd += ["--model", model]
    if effort:
        cmd += ["--effort", effort]
    if agent:
        cmd += ["--agent", agent]
    if mode:
        # Plan mode makes the run propose an approach instead of acting on it;
        # the other modes narrow what runs without asking. The allowlist in
        # --settings still applies underneath whichever mode is chosen.
        cmd += ["--permission-mode", mode]

    r = {"id": jid, "sid": sid, "unit": unit, "state": "running",
         "started": int(time.time()), "ended": None, "user": user,
         "prompt": prompt[:400], "tools": 0, "cost": None, "turns": None,
         "error": "", "stderr": "", "model": model or "", "cwd": cwd,
         "effort": effort or "", "mode": mode or "", "agent": agent or "",
         "stopped": False}

    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        return None, f"could not launch: {e}"

    with _runs_lock:
        _runs[jid] = r
        if len(_runs) > KEEP_RUNS:
            for k in sorted(_runs)[:len(_runs) - KEEP_RUNS]:
                if _runs[k]["state"] != "running":
                    _runs.pop(k, None)

    _audit(user, f"CLAUDE RUN run={jid} sid={sid} cwd={cwd} "
                 f"model={model or 'default'} effort={effort or 'default'} "
                 f"mode={mode or 'default'} agent={agent or 'default'} "
                 f"prompt={prompt[:300]!r}")
    threading.Thread(target=_reader, args=(r, proc), daemon=True).start()
    return r, None


def stop_run(user, jid, sid=None):
    """Stop a run by id, or - for one this process has forgotten - by session."""
    unit = None
    with _runs_lock:
        r = _runs.get(jid)
        if r:
            if r["state"] != "running":
                return "run already finished"
            r["stopped"] = True
            unit = r["unit"]
    if not unit:
        unit = unit_for_sid(sid) if sid else None
    if not unit:
        return "no such run"
    try:
        subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=15)
    except Exception as e:
        return str(e)[:200]
    _audit(user, f"CLAUDE STOP run={jid} unit={unit}")
    return None


# ----------------------------------------------------------------------- page
CSS = """
/* minmax(0,...), not a bare 1fr. 1fr means minmax(auto,1fr), and that auto
   floor is the track's min-content width - one long .tool line (which is
   white-space:nowrap) drags the chat column past the viewport and scrolls the
   whole page sideways on desktop. min-width:0 stops the same one level down.
   Matches .mid / .fm / .tp elsewhere in the dashboard. */
.cld{display:grid;grid-template-columns:330px minmax(0,1fr);gap:14px;align-items:start}
.cld>*{min-width:0}
#stream,#composer,#prompt{min-width:0;max-width:100%}
@media(max-width:980px){.cld{grid-template-columns:1fr}}
.cld .side{display:flex;flex-direction:column;gap:8px;max-height:78vh;overflow:auto}
/* #hdr is a sibling of .cld, not a child - scoping this to `.cld .hdr` meant
   it never matched and the row rendered as bare text. */
.hdr{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);
  padding:8px 12px;background:var(--card);border:1px solid var(--line);border-radius:8px;
  margin-bottom:10px}
.hdr b{color:var(--fg);font-weight:600}
.cs{background:var(--card);border:1px solid var(--line);border-radius:8px;
  padding:9px 11px;cursor:pointer;text-align:left;width:100%;font:inherit;color:inherit}
.cs:hover{border-color:var(--accent)}
.cs.on{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.cs .ti{font-weight:600;font-size:13px;display:flex;gap:6px;align-items:flex-start}
.cs .ti span.t{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cs .dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none;
  margin-top:4px}
.cs .dot.live{background:#16a34a;animation:cpulse 1.4s infinite}
@keyframes cpulse{50%{opacity:.35}}
.cs .meta{font-size:11px;color:var(--muted);margin-top:3px;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis}
#newbtn{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:9px;
  font:inherit;font-weight:600;cursor:pointer;flex:none}
#stream{background:var(--card);border:1px solid var(--line);border-radius:8px;
  padding:12px;height:60vh;overflow:auto}
.ev{margin-bottom:12px;font-size:13.5px;line-height:1.55}
.ev .who{font-size:11px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);margin-bottom:3px}
.ev.user .bd{background:color-mix(in srgb,var(--accent) 12%,transparent);
  border:1px solid color-mix(in srgb,var(--accent) 35%,transparent);
  border-radius:8px;padding:8px 11px;white-space:pre-wrap;overflow-wrap:anywhere}
.ev.asst .bd{white-space:pre-wrap;overflow-wrap:anywhere}
.ev.think .bd{white-space:pre-wrap;color:var(--muted);font-style:italic;
  border-left:2px solid var(--line);padding-left:9px}
.ev.side{opacity:.78;border-left:2px solid var(--line);padding-left:9px}
.tool{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
  background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:6px 9px;
  cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tool b{color:var(--accent);font-weight:600}
.out{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
  background:var(--bg);border:1px solid var(--line);border-left:3px solid var(--muted);
  border-radius:0 7px 7px 0;padding:7px 9px;margin-top:4px;white-space:pre-wrap;
  overflow-wrap:anywhere;max-height:260px;overflow:auto}
.out.err{border-left-color:var(--bad)}
.out.hid{display:none}
#composer{margin-top:10px;display:flex;flex-direction:column;gap:8px}
#prompt{width:100%;min-height:78px;padding:10px 12px;border:1px solid var(--line);
  border-radius:8px;background:var(--card);color:var(--fg);font:inherit;resize:vertical}
#prompt:focus{outline:2px solid var(--accent);outline-offset:1px}
#crow{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
#crow .grow{flex:1}
.cbtn{padding:9px 16px;border:0;border-radius:8px;background:var(--accent);color:#fff;
  font:inherit;font-weight:600;cursor:pointer}
.cbtn:disabled{opacity:.5;cursor:default}
.cbtn.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
.cbtn.stop{background:var(--bad)}
#csel{padding:8px 10px;border:1px solid var(--line);border-radius:8px;
  background:var(--card);color:var(--fg);font:inherit}
#note{font-size:12px;color:var(--muted)}
#note.bad{color:var(--bad)}
.warn{font-size:12px;color:var(--muted);border-left:3px solid var(--bad);
  padding:6px 10px;margin-bottom:12px}
.chip{display:inline-block;font-size:11px;color:var(--muted);border:1px solid var(--line);
  border-radius:999px;padding:1px 9px;margin-left:6px}
/* --- Phones -------------------------------------------------------------
   The session list used to stack above the transcript as a tall scroller, so
   reaching the conversation meant scrolling past the warning, the header and
   every session. On narrow screens it collapses behind a picker that names the
   current conversation, and the rest of the chrome is trimmed so the
   transcript and the composer fit on one screen. --------------------------- */
.pickrow{display:none}
@media (max-width:980px){
.cld{display:block}
.pickrow{display:flex;gap:8px;margin-bottom:9px}
.sesspick{flex:1;min-width:0;display:flex;align-items:center;gap:8px;min-height:44px;
  padding:0 13px;background:var(--card);border:1px solid var(--line);border-radius:8px;
  font:inherit;color:inherit;text-align:left;cursor:pointer}
.sesspick .cur{flex:1;min-width:0;font-weight:600;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.sesspick .chev{flex:none;color:var(--muted);font-size:11px;transition:transform .15s}
.cld.sideopen .sesspick .chev{transform:rotate(180deg)}
#newmob{flex:none;width:44px;min-height:44px;border:1px solid var(--line);
  border-radius:8px;background:var(--card);color:var(--accent);font:inherit;
  font-size:21px;line-height:1;font-weight:600;cursor:pointer}
.cld .side{display:none;max-height:54vh;overflow:auto;margin-bottom:10px}
.cld.sideopen .side{display:flex}
#newbtn{display:none}
.warn{font-size:11.5px;padding:5px 9px;margin-bottom:9px}
.hdr{gap:10px;font-size:11.5px;padding:6px 10px;margin-bottom:9px}
#stream{height:52vh;height:52dvh;min-height:230px;padding:10px}
#composer{margin-top:8px;gap:6px}
#prompt{min-height:62px;font-size:16px}
#crow{gap:6px}
#crow #note{flex:1 1 100%;order:3;margin:0}
#crow #csel{flex:0 0 auto;font-size:16px}
#crow .cbtn{flex:1}
.ev{font-size:14px}
.out{max-height:200px}
}
@media (pointer:coarse){.cs{padding:12px 11px}.cbtn{min-height:44px}}

/* --- run controls, host tasks, environment, subagent tree --- */
.sel{padding:7px 9px;border:1px solid var(--line);border-radius:8px;
  background:var(--card);color:var(--fg);font:inherit;font-size:12.5px;max-width:200px}
.ctrls{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:2px}
/* Subagent work is indented under the Task call that spawned it, so a fan-out
   reads as a tree instead of interleaved noise. */
.ev.sub{margin-left:20px;padding-left:11px;border-left:2px solid
  color-mix(in srgb,var(--accent) 45%,transparent)}
.ev.sub.side{opacity:1}
.tool.spawn{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
/* Matches the dashboard's own card treatment so the side panes sit with the
   rest of the UI rather than looking bolted on. */
.pane{background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);box-shadow:var(--shadow);padding:10px 12px;
  font-size:12px}
.pane h3{margin:0 0 7px;font-size:11px;text-transform:uppercase;
  letter-spacing:.06em;color:var(--muted);font-weight:600}
.trow{display:flex;gap:7px;align-items:baseline;padding:4px 0;
  border-top:1px solid var(--line)}
.trow:first-of-type{border-top:0}
.trow .nm{font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.trow .mu{color:var(--muted);font-size:11px;white-space:nowrap}
.dotb{width:7px;height:7px;border-radius:50%;background:var(--muted);flex:none;
  align-self:center}
.dotb.busy{background:#16a34a;animation:cpulse 1.4s infinite}
.dotb.bad{background:var(--bad)}
@media(max-width:760px){.sel{max-width:none;flex:1 1 44%;font-size:16px}}
"""

PAGE = """<!doctype html>
<meta charset="utf-8"><title>Claude</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
<div class="wrap">
__NAV__
<h1>Claude Code</h1>
<p class="warn">A run here executes on this host as root with tools
auto-approved - the same reach as the terminal. Your prompt and every tool call
it makes are written to the dashboard audit log.</p>
<div class="hdr" id="hdr">loading...</div>
<div class="cld">
  <div class="pickrow">
    <button class="sesspick" id="sesspick" aria-expanded="false">
      <span class="cur" id="curtitle">New conversation</span>
      <span class="chev">&#9660;</span>
    </button>
    <button id="newmob" title="New conversation" aria-label="New conversation">+</button>
  </div>
  <div class="side">
    <button id="newbtn">+ New conversation</button>
    <div id="sessions"></div>
    <div class="pane" id="taskpane">
      <h3>Tasks on this host</h3>
      <div id="tasks">loading...</div>
    </div>
    <div class="pane" id="envpane">
      <h3>Environment</h3>
      <div id="env">loading...</div>
    </div>
  </div>
  <div>
    <div id="stream"></div>
    <div id="composer">
      <textarea id="prompt" placeholder="Ask Claude to do something on this host.
Ctrl+Enter to send."></textarea>
      <div class="ctrls">
        <select class="sel" id="agentsel" title="agent type">
          <option value="">default agent</option>
        </select>
        <select class="sel" id="effortsel" title="effort level">
          <option value="">default effort</option>
        </select>
        <select class="sel" id="modesel" title="permission mode">
          <option value="">act directly</option>
        </select>
        <select class="sel" id="skillsel" title="insert a skill invocation">
          <option value="">insert skill...</option>
        </select>
      </div>
      <div id="crow">
        <select id="csel" title="model">
          <option value="">default model</option>
          <option value="opus">opus</option>
          <option value="sonnet">sonnet</option>
          <option value="haiku">haiku</option>
        </select>
        <span id="note" class="grow"></span>
        <button class="cbtn stop" id="stopbtn" style="display:none">Stop</button>
        <button class="cbtn" id="sendbtn">Send</button>
      </div>
    </div>
  </div>
</div>
</div>
<script>__JS__</script>
"""

JS = """
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;',
  '>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ago=s=>{s=Math.max(0,s|0);if(s<60)return s+'s';if(s<3600)return (s/60|0)+'m';
  if(s<86400)return (s/3600|0)+'h';return (s/86400|0)+'d';};

let current=null;        // selected session id, null = new conversation
let shown=0;             // events already rendered for `current`
let running=false;       // is the selected session running
let runId=null;          // run id for the selected session
let busy=false;          // a send is in flight
let timer=null;
const elsewhere=new Set();  // sessions a terminal Claude currently holds open

const $=id=>document.getElementById(id);
function note(t,bad){const n=$('note');n.textContent=t||'';n.className=(bad?'bad ':'')+'grow';}

// On phones the session list is collapsed, so the picker has to carry the name
// of whatever conversation is selected. No-ops on desktop, where it is hidden.
function setPick(){
  const el=$('curtitle'); if(!el)return;
  if(!current){el.textContent='New conversation';return;}
  let t='conversation';
  document.querySelectorAll('.cs').forEach(b=>{
    if(b.dataset.id===current){const n=b.querySelector('.t');if(n)t=n.textContent;}});
  el.textContent=t;
}
function setSide(open){
  const c=document.querySelector('.cld'); if(c)c.classList.toggle('sideopen',open);
  const p=$('sesspick'); if(p)p.setAttribute('aria-expanded',open?'true':'false');
}

function atBottom(){const s=$('stream');return s.scrollHeight-s.scrollTop-s.clientHeight<60;}
function pin(was){if(was){const s=$('stream');s.scrollTop=s.scrollHeight;}}

function evNode(e){
  const d=document.createElement('div');
  // e.p is set on events produced by a subagent: indent them under the Task
  // call that spawned them so a fan-out reads as a tree.
  const nest=(e.side?' side':'')+(e.p?' sub':'');
  if(e.kind==='tool'){
    d.className='ev'+nest;
    d.innerHTML='<div class="tool'+(e.spawns?' spawn':'')+'"><b>'+esc(e.tool)+'</b> '
      +esc(e.text)+'</div>';
    return d;
  }
  if(e.kind==='output'){
    d.className='ev'+nest;
    d.innerHTML='<div class="out hid'+(e.err?' err':'')+'">'+esc(e.text)+'</div>';
    return d;
  }
  if(e.kind==='thinking'){
    d.className='ev think'+nest;
    d.innerHTML='<div class="who">thinking</div><div class="bd">'+esc(e.text)+'</div>';
    return d;
  }
  d.className='ev '+(e.role==='user'?'user':'asst')+nest;
  d.innerHTML='<div class="who">'+(e.role==='user'?'you':'claude')
    +(e.side?' &middot; subagent':'')+'</div><div class="bd">'+esc(e.text)+'</div>';
  return d;
}

// A tool line and its output are separate events; clicking the line toggles the
// output that follows it.
function wireTools(root){
  root.querySelectorAll('.tool').forEach(t=>{
    if(t.dataset.w)return; t.dataset.w='1';
    t.onclick=()=>{
      let n=t.parentElement.nextElementSibling;
      const o=n&&n.querySelector('.out');
      if(o)o.classList.toggle('hid');
    };
  });
}

function render(events,append){
  const s=$('stream'), was=atBottom();
  if(!append)s.innerHTML='';
  const frag=document.createDocumentFragment();
  events.forEach(e=>frag.appendChild(evNode(e)));
  s.appendChild(frag);
  wireTools(s);
  if(!append){s.scrollTop=s.scrollHeight;}else{pin(was);}
}

async function loadTranscript(reset){
  if(!current){render([],false);shown=0;return;}
  if(reset){shown=0;}
  let d;
  try{
    d=await (await fetch('/api/claude/transcript?id='+encodeURIComponent(current)
      +'&since='+shown,{cache:'no-store'})).json();
  }catch(e){return;}
  if(d.error){note(d.error,true);return;}
  running=!!d.running; runId=d.run&&d.run.id||null;
  if(d.events&&d.events.length){render(d.events,!reset&&shown>0);shown=d.total;}
  else if(reset){render([],false);shown=d.total||0;}
  $('stopbtn').style.display=running?'':'none';
  if(d.run){
    const r=d.run;
    let t='run #'+r.id+' '+r.state+' &middot; '+r.tools+' tool call'+(r.tools===1?'':'s');
    if(r.cost!=null)t+=' &middot; $'+Number(r.cost).toFixed(3);
    if(r.error)t+=' &middot; '+esc(String(r.error).slice(0,160));
    $('note').innerHTML=t; $('note').className=(r.error?'bad ':'')+'grow';
  }else if(running){
    note('running (started outside this dashboard process)');
  }
}

function selectSession(sid){
  current=sid; shown=0; running=false;
  document.querySelectorAll('.cs').forEach(b=>b.classList.toggle('on',b.dataset.id===sid));
  note(sid?'':'new conversation');
  setPick(); setSide(false);
  loadTranscript(true);
}

async function refresh(){
  let d;
  try{d=await (await fetch('/api/claude/sessions',{cache:'no-store'})).json();}
  catch(e){return;}
  if(d.error){return;}
  $('hdr').innerHTML='<span>sessions <b>'+d.sessions.length+'</b></span>'
    +'<span>running <b>'+d.busy+'/'+d.max+'</b></span>'
    +'<span>host <b>'+esc(d.host)+'</b></span>';
  const box=$('sessions');
  elsewhere.clear();
  d.sessions.forEach(s=>{if(s.elsewhere)elsewhere.add(s.id);});
  box.innerHTML=d.sessions.map(s=>{
    const age=Math.max(0,d.now-s.mtime);
    // A session someone has open in a terminal cannot be resumed from here -
    // two Claudes writing one transcript - so say so on the row itself.
    const tag=s.elsewhere?'<span class="chip">in terminal</span>':'';
    return '<button class="cs'+(s.id===current?' on':'')+'" data-id="'+esc(s.id)+'">'
      +'<div class="ti"><span class="dot'+(s.running?' live':'')+'"></span>'
      +'<span class="t">'+esc(s.title)+'</span></div>'
      +'<div class="meta">'+esc(s.cwd)+' &middot; '+s.entries+' entries &middot; '
      +ago(age)+' ago'+tag+'</div></button>';
  }).join('')||'<div class="cs">no sessions yet</div>';
  box.querySelectorAll('.cs').forEach(b=>{
    if(b.dataset.id)b.onclick=()=>selectSession(b.dataset.id);});
  setPick();
  // A run started elsewhere (or the one we just sent) should keep the view live.
  if(current&&d.sessions.some(s=>s.id===current&&s.running))running=true;
}

async function send(){
  const p=$('prompt').value.trim();
  if(!p||busy)return;
  if(current&&elsewhere.has(current)){
    note('that conversation is open in a terminal - start a new one',true);
    return;
  }
  busy=true;$('sendbtn').disabled=true;note('starting...');
  let d;
  try{
    d=await (await fetch('/api/claude/run',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({prompt:p,resume:current,model:$('csel').value,
        effort:$('effortsel').value,mode:$('modesel').value,
        agent:$('agentsel').value})})).json();
  }catch(e){note('request failed',true);busy=false;$('sendbtn').disabled=false;return;}
  busy=false;$('sendbtn').disabled=false;
  if(d.error){note(d.error,true);return;}
  $('prompt').value='';
  note('running');
  if(d.session_id!==current){current=d.session_id;shown=0;}
  running=true;
  await refresh();
  loadTranscript(true);
}

async function stopRun(){
  // A run orphaned by a dashboard restart has no run id left, only its unit,
  // so the session id is sent as the fallback handle.
  if(!running)return;
  try{
    await fetch('/api/claude/stop',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({id:runId,sid:current})});
  }catch(e){}
  note('stopping...');
}

// Rebuilds a select from scratch each time rather than appending, so a repeat
// poll cannot stack duplicate options; the current choice is preserved.
function fill(sel,values,placeholder,label){
  const el=$(sel), keep=el.value;
  el.innerHTML='<option value="">'+esc(placeholder)+'</option>'
    +values.map(v=>{
      const val=v.name||v, txt=label?label(v):val;
      const ti=v.desc?' title="'+esc(v.desc)+'"':'';
      return '<option value="'+esc(val)+'"'+ti+'>'+esc(txt)+'</option>';
    }).join('');
  if(keep)el.value=keep;
}

// Options change rarely (a plugin added, an MCP server going down), so this
// runs at load and then only on the slow poll.
async function loadOptions(){
  let d;
  try{d=await (await fetch('/api/claude/options',{cache:'no-store'})).json();}
  catch(e){return;}
  if(d.error)return;
  fill('csel',d.models||[],'default model');
  fill('agentsel',d.agents||[],'default agent',a=>'agent: '+a);
  fill('effortsel',d.efforts||[],'default effort',e=>'effort: '+e);
  fill('modesel',d.modes||[],'act directly',
    m=>m==='plan'?'plan only (propose, don\\u2019t act)':'mode: '+m);
  fill('skillsel',d.skills||[],'insert skill...',s=>'/'+(s.name||s));
  const e=d.env||{};
  const mcp=(e.mcp||[]).map(m=>'<div class="trow"><span class="dotb'
    +(m.ok?' busy':' bad')+'"></span><span class="nm">'+esc(m.name)
    +'</span><span class="mu">'+(m.ok?'connected':'down')+'</span></div>').join('')
    ||'<div class="trow"><span class="mu">no MCP servers</span></div>';
  $('env').innerHTML='<div class="trow"><span class="nm">Claude Code</span>'
    +'<span class="mu">'+esc(e.version||'?')+'</span></div>'
    +'<div class="trow"><span class="nm">plugins</span><span class="mu">'
    +(e.plugin_count||0)+' installed</span></div>'+mcp;
}

// Every Claude on the host, terminal sessions included - not just runs started
// from this page.
async function loadTasks(){
  let d;
  try{d=await (await fetch('/api/claude/tasks',{cache:'no-store'})).json();}
  catch(e){return;}
  if(d.error)return;
  const rows=(d.tasks||[]).map(t=>{
    const busyDot=(t.status==='busy'||t.source==='dashboard')?' busy':'';
    const age=t.started?ago(Math.max(0,d.now-t.started)):'';
    return '<div class="trow"><span class="dotb'+busyDot+'"></span>'
      +'<span class="nm">'+esc(t.name||(t.sid||'').slice(0,8))+'</span>'
      +'<span class="mu">'+esc(t.kind)+(age?' &middot; '+age:'')+'</span></div>';
  });
  $('tasks').innerHTML=rows.join('')
    ||'<div class="trow"><span class="mu">nothing running</span></div>';
}

$('sendbtn').onclick=send;
$('stopbtn').onclick=stopRun;
$('newbtn').onclick=()=>{selectSession(null);$('prompt').focus();};
$('newmob').onclick=()=>{selectSession(null);$('prompt').focus();};
$('sesspick').onclick=()=>setSide(
  !document.querySelector('.cld').classList.contains('sideopen'));
$('prompt').addEventListener('keydown',e=>{
  if(e.key==='Enter'&&(e.ctrlKey||e.metaKey)){e.preventDefault();send();}});

// Populate the run controls, the skills picker and the environment pane
// from what this host can actually offer, rather than hardcoding a menu.
// The tasks pane is host-wide: it lists every Claude on this machine, so a
// terminal session shows up here next to runs started from this page.
$('skillsel').onchange=()=>{
  const v=$('skillsel').value;
  if(!v)return;
  const p=$('prompt');
  p.value=('/'+v+' '+p.value).trimStart();
  $('skillsel').value='';
  p.focus();
};

refresh();
selectSession(null);
loadOptions();
loadTasks();
timer=setInterval(()=>{refresh();if(current)loadTranscript(false);},
  1500);
// Host tasks and environment shell out to the CLI, so they poll far slower
// than the transcript does.
setInterval(loadTasks,6000);
setInterval(loadOptions,60000);
"""


# -------------------------------------------------------------------- routing
def _json(h, obj, code=200):
    h.send_body(json.dumps(obj), code, "application/json")


def _forbidden(h, path):
    if path.startswith("/api/"):
        _json(h, {"error": "forbidden"}, 403)
    else:
        h.send_body("<h1>403</h1><p>Admins only.</p>", 403)


def _body(h):
    try:
        n = int(h.headers.get("Content-Length") or 0)
    except ValueError:
        return None, "bad length"
    if n > MAX_BODY:
        return None, "too large"
    try:
        return json.loads(h.rfile.read(n).decode("utf-8", "replace")), None
    except Exception:
        return None, "bad json"


def handle_get(h, path, qs):
    """Handle a Claude route. Returns True when it took the request.

    The caller must already have checked that a session cookie is valid; the
    admin role is checked here, per request.
    """
    if path not in ("/claude", "/api/claude/sessions", "/api/claude/transcript",
                    "/api/claude/options", "/api/claude/tasks"):
        return False
    if not h.is_admin():
        _forbidden(h, path)
        return True

    if path == "/claude":
        nav = _main_attr("nav")
        base_css = _main_attr("CSS", "")
        page = PAGE.replace("__CSS__", base_css + CSS)
        page = page.replace("__NAV__", nav("/claude", h.current_user(), True) if nav else "")
        page = page.replace("__JS__", JS)
        h.send_body(page)
        return True

    if path == "/api/claude/sessions":
        sessions = list_sessions()
        _json(h, {"sessions": sessions, "runs": active_runs(),
                  "busy": sum(1 for s in sessions if s["running"]),
                  "max": MAX_CONCURRENT, "now": int(time.time()),
                  "host": os.uname().nodename})
        return True

    if path == "/api/claude/options":
        _json(h, options())
        return True

    if path == "/api/claude/tasks":
        _json(h, {"tasks": host_tasks(), "now": int(time.time())})
        return True

    # /api/claude/transcript
    from urllib.parse import parse_qs
    q = parse_qs(qs)
    sid = (q.get("id") or [""])[0]
    try:
        since = max(0, int((q.get("since") or ["0"])[0]))
    except ValueError:
        since = 0
    p = session_path(sid)
    if not p:
        _json(h, {"error": "no such session"}, 404)
        return True
    events = read_events(p)
    with _runs_lock:
        mine = [r for r in _runs.values() if r["sid"] == sid]
        run = _run_public(max(mine, key=lambda r: r["id"])) if mine else None
    running = bool(run and run["state"] == "running") or sid in live_sids()
    _json(h, {"events": events[since:], "total": len(events),
              "running": running, "run": run, "sid": sid})
    return True


def handle_post(h, path):
    """Handle a Claude POST. Returns True when it took the request."""
    if path not in ("/api/claude/run", "/api/claude/stop"):
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

    if path == "/api/claude/run":
        resume = (body.get("resume") or "").strip() or None
        if resume and not SID_OK.match(resume):
            _json(h, {"error": "bad session id"}, 400)
            return True
        r, err = start_run(user, body.get("prompt") or "", resume,
                           (body.get("model") or "").strip() or None,
                           (body.get("effort") or "").strip() or None,
                           (body.get("mode") or "").strip() or None,
                           (body.get("agent") or "").strip() or None)
        if err:
            _json(h, {"error": err}, 400)
            return True
        _json(h, {"ok": True, "id": r["id"], "session_id": r["sid"]})
        return True

    # /api/claude/stop
    try:
        jid = int(body.get("id"))
    except (TypeError, ValueError):
        jid = None
    sid = (body.get("sid") or "").strip() or None
    if sid and not SID_OK.match(sid):
        _json(h, {"error": "bad session id"}, 400)
        return True
    if jid is None and not sid:
        _json(h, {"error": "bad id"}, 400)
        return True
    err = stop_run(user, jid, sid)
    if err:
        _json(h, {"error": err}, 400)
        return True
    _json(h, {"ok": True})
    return True
