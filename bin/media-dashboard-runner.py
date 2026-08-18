#!/usr/bin/env python3
"""Carries out privileged maintenance jobs asked for by the dashboard web UI.

The web UI runs under ProtectSystem=strict and deliberately cannot reach
pct/lxc-attach - loosening that to let an authenticated web page drive the
hypervisor directly would put the whole host one bug away from the internet.
So the UI only ever *describes* work: it drops a spool file naming an action
and its parameters, and this - the single privileged component - decides what
that actually means in terms of commands.

The distinction matters. A spool file never carries a command line. It names
an action from ACTIONS below and supplies parameters that are re-validated
here against the live host. A spool file an attacker somehow got to write can
therefore only ask for work this runner already knew how to do, against
targets that already exist.
"""
import base64
import json
import os
import re
import shutil
import subprocess
import tarfile
import threading
import time
import urllib.request

STATE_DIR = "/var/lib/media-dashboard"
JOB_DIR = os.path.join(STATE_DIR, "jobs")
# Read-only lookups the web UI cannot make itself: it runs under
# ProtectSystem=strict and so cannot reach pct/lxc-attach. Same spool pattern as
# jobs, but answered in-line and never producing a shell word from a parameter.
QUERY_DIR = os.path.join(STATE_DIR, "queries")
CATALOG_FILE = os.path.join(STATE_DIR, "catalog.json")
# Same file the web UI writes file operations to, so there is one trail
# covering every privileged thing done through the dashboard.
AUDIT_LOG = os.path.join(STATE_DIR, "fileops.log")

POLL = 2                        # seconds between spool sweeps
QUERY_POLL = 0.25               # queries are interactive, so swept far faster
QUERY_TTL = 180                 # unclaimed answers are binned after this
QUERY_TIMEOUT = 90              # apt on a cold cache is slow but not this slow
JOB_TIMEOUT = 3600              # a container build can legitimately take a while
JOB_RETENTION = 7 * 86400       # keep finished jobs (and their logs) this long
CATALOG_TTL = 24 * 3600
LOG_CAP = 2 * 1024 * 1024       # per-job log ceiling, so a chatty build cannot fill /var

CT_REPO = "community-scripts/ProxmoxVE"
CT_TARBALL = f"https://codeload.github.com/{CT_REPO}/tar.gz/refs/heads/main"

# Where the catalogue comes from. Editable through the app store so a new
# collection of scripts or compose stacks can be added without touching code.
SOURCES_FILE = "/etc/media-dashboard/sources.json"

_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,100}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]{0,120}$")

DEFAULT_SOURCES = {
    "helpers": [{
        "id": "community-scripts",
        "name": "Proxmox VE Helper-Scripts",
        "repo": CT_REPO,
        "ref": "main",
        "builtin": True,
        "enabled": True,
        "sets": [
            {"dir": "ct", "target": "ct", "unattended": True,
             "label": "LXC container"},
            {"dir": "vm", "target": "vm", "unattended": False,
             "label": "Virtual machine"},
            {"dir": "tools/pve", "target": "host", "unattended": False,
             "label": "Proxmox host tool"},
            {"dir": "tools/addon", "target": "host", "unattended": False,
             "label": "Host add-on"},
        ],
    }],
    "compose": [{
        "id": "builtin",
        "name": "Built-in stacks",
        "builtin": True,
        "enabled": True,
    }],
}


def load_sources():
    """Catalogue sources, falling back to the shipped defaults.

    The builtin entries are re-asserted on every load rather than trusted from
    disk, so a mangled file cannot quietly remove the stock catalogue.
    """
    data = {}
    try:
        with open(SOURCES_FILE) as f:
            data = json.load(f)
    except Exception:
        pass
    out = {"helpers": [], "compose": []}
    for kind in ("helpers", "compose"):
        seen = set()
        for row in (data.get(kind) or []):
            if not isinstance(row, dict) or not row.get("id"):
                continue
            if row.get("builtin"):
                continue                       # re-added from defaults below
            out[kind].append(row)
            seen.add(row["id"])
        for row in DEFAULT_SOURCES[kind]:
            if row["id"] not in seen:
                out[kind].insert(0, dict(row))
    return out


def valid_source(row, kind):
    """Reject a source we could not safely fetch, with a reason for the UI."""
    if not _REPO_RE.match(str(row.get("repo") or "")):
        raise ValueError("repository must look like owner/name")
    if not _REF_RE.match(str(row.get("ref") or "main")):
        raise ValueError("branch or tag has unexpected characters")
    if not _PATH_RE.match(str(row.get("path") or "")):
        raise ValueError("path has unexpected characters")
    if kind == "helpers":
        for s in (row.get("sets") or []):
            if not _PATH_RE.match(str(s.get("dir") or "")):
                raise ValueError("script directory has unexpected characters")
    return True


def repo_tarball(repo, ref):
    return f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{ref}"

# Deploying into an existing container writes a compose file under this root.
# Anything outside it is refused, so a stack name cannot escape into /etc.
COMPOSE_ROOT = "/opt"

_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PKG = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}$")


def audit(user, msg):
    """Shared with the web UI - one file records who asked for what."""
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{user}\t{msg}\n")
    except Exception:
        pass


def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        return (r.stdout or "").strip()
    except Exception:
        return ""


def lxc_ids():
    """Container ids that exist right now.

    Re-read per job rather than cached: a job may have been queued before the
    container it names was created, or after it was destroyed.
    """
    out = run("pct list", timeout=20)
    return [int(l.split()[0]) for l in out.splitlines()[1:]
            if l.split() and l.split()[0].isdigit()]


def running_ct(cid):
    return run(f"pct status {cid}", timeout=15).endswith("running")


# ---- parameter validation
#
# Every helper raises ValueError with a message meant for the operator; the
# runner turns that into a failed job rather than letting a bad parameter
# reach a shell.

def need_ct(params, key="cid"):
    try:
        cid = int(params.get(key))
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a container id")
    if cid not in lxc_ids():
        raise ValueError(f"container {cid} does not exist on this host")
    if not running_ct(cid):
        raise ValueError(f"container {cid} is not running")
    return cid


def need_slug(params, key):
    v = str(params.get(key) or "")
    if not _SLUG.match(v):
        raise ValueError(f"{key} must be a short lowercase name")
    return v


def need_dir(cid, params, key="dir"):
    """A compose directory, checked to be under COMPOSE_ROOT and to exist."""
    v = str(params.get(key) or "")
    full = os.path.normpath(v)
    if not full.startswith(COMPOSE_ROOT + "/") or ".." in v:
        raise ValueError(f"compose directory must live under {COMPOSE_ROOT}")
    probe = run(f"pct exec {cid} -- test -f {sh(full)}/docker-compose.yml "
                f"&& echo ok", timeout=20)
    if probe != "ok":
        raise ValueError(f"no docker-compose.yml in {full} inside container {cid}")
    return full


def sh(s):
    """Single-quote for the shell. Used only on values already regex-validated."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def need_target(p, key="target"):
    """Where a package operation happens: the Proxmox host, or a container.

    Returns None for the host and a container id otherwise, so callers can pass
    the answer straight to in_target(). 'host' is spelled out rather than being
    the default for a missing value - an operation on the hypervisor should
    never be something a caller fell into by omitting a field.
    """
    t = str(p.get(key) or "")
    if t == "host":
        return None
    if not t.isdigit():
        raise ValueError(f"{key} must be 'host' or a container id")
    return need_ct({"cid": t})


def in_target(cid, cmd):
    """Wrap a shell snippet so it runs on the host or inside a container."""
    if cid is None:
        return f"bash -lc {sh(cmd)}"
    return f"pct exec {cid} -- bash -lc {sh(cmd)}"


def target_label(cid):
    return "the host" if cid is None else f"container {cid}"


# ---- actions
#
# Each builder returns a list of (label, command) pairs run in order; the first
# non-zero return code fails the job. Builders may also raise ValueError during
# validation, before anything runs.

def act_update_docker(p):
    cid = need_ct(p)
    d = need_dir(cid, p)
    # --remove-orphans is deliberately absent: an operator may have added
    # sidecars to the stack by hand and we are not here to prune them.
    #
    # The image ids are compared across the pull because "docker compose pull"
    # exits 0 whether or not it actually got anything. A stack pinned to an
    # image the upstream project has since renamed or abandoned would otherwise
    # report a clean success forever while never moving a byte.
    pull = (
        "set -e; cd {d}; "
        "before=$(docker compose config --images | sort -u "
        "| xargs -r -n1 docker image inspect -f '{{{{.Id}}}}' 2>/dev/null | sort); "
        "docker compose pull; "
        "after=$(docker compose config --images | sort -u "
        "| xargs -r -n1 docker image inspect -f '{{{{.Id}}}}' 2>/dev/null | sort); "
        "if [ \"$before\" = \"$after\" ]; then "
        "echo; echo 'NOTE: the registry had nothing newer for the image tags this "
        "stack is pinned to.'; echo 'The service is already running that image. If "
        "the dashboard still shows an update, the project has most likely moved to "
        "a different image or tag and the compose file needs editing by hand.'; "
        "fi"
    ).format(d=sh(d))
    return [
        ("pull", f"pct exec {cid} -- bash -lc {sh(pull)}"),
        ("recreate", f"pct exec {cid} -- bash -lc 'cd {sh(d)} && docker compose up -d'"),
        ("prune", f"pct exec {cid} -- bash -lc 'docker image prune -f'"),
    ]


def act_update_apt(p):
    cid = need_ct(p)
    pkg = str(p.get("pkg") or "")
    if not _PKG.match(pkg):
        raise ValueError("pkg must be a package name")
    # Refuse up front when the repo has nothing newer, rather than running a
    # no-op apt and reporting success. qbittorrent-nox on stock Debian is
    # exactly this case: the dashboard sees a newer upstream release that
    # Debian has not packaged, so there is genuinely nothing apt can do.
    pol = run(f"pct exec {cid} -- bash -lc 'apt-get update -qq >/dev/null 2>&1; "
              f"apt-cache policy {sh(pkg)}'", timeout=180)
    inst = re.search(r"Installed:\s*(\S+)", pol)
    cand = re.search(r"Candidate:\s*(\S+)", pol)
    if inst and cand and inst.group(1) == cand.group(1):
        raise ValueError(
            f"{pkg} is already at the newest version this container's repositories "
            f"offer ({inst.group(1)}). The newer upstream release has not been "
            f"packaged for it, so there is no apt upgrade path.")
    env = "DEBIAN_FRONTEND=noninteractive"
    return [
        ("refresh", f"pct exec {cid} -- bash -lc '{env} apt-get update'"),
        ("upgrade", f"pct exec {cid} -- bash -lc "
                    f"'{env} apt-get install -y --only-upgrade {sh(pkg)}'"),
    ]


# The *arr apps are plain tarballs unpacked into /opt, so an update is a
# download-and-swap. Keyed by the service name the collector reports.
ARR = {
    "prowlarr": {"dir": "Prowlarr", "svc": "prowlarr", "branch": "master"},
    "radarr":   {"dir": "Radarr",   "svc": "radarr",   "branch": "master"},
    "sonarr":   {"dir": "Sonarr",   "svc": "sonarr",   "branch": "main"},
}


def act_update_arr(p):
    cid = need_ct(p)
    app = need_slug(p, "app")
    if app not in ARR:
        raise ValueError(f"{app} is not one of the *arr applications")
    a = ARR[app]
    url = (f"https://{a['svc']}.servarr.com/v1/update/{a['branch']}/updatefile"
           f"?os=linux&runtime=netcore&arch=x64")
    tmp = f"/tmp/{a['dir']}.tar.gz"
    keep = f"/opt/{a['dir']}.prev"
    # Keep the previous tree next to the new one. These upgrades occasionally
    # need a rollback and re-downloading the old build is not always possible.
    return [
        ("download", f"pct exec {cid} -- bash -lc "
                     f"'curl -fsSL {sh(url)} -o {sh(tmp)}'"),
        ("stop", f"pct exec {cid} -- systemctl stop {sh(a['svc'])}"),
        ("keep previous", f"pct exec {cid} -- bash -lc "
                          f"'rm -rf {sh(keep)}; cp -a /opt/{a['dir']} {sh(keep)}'"),
        ("unpack", f"pct exec {cid} -- bash -lc "
                   f"'rm -rf /opt/{a['dir']} && tar -xzf {sh(tmp)} -C /opt'"),
        ("own", f"pct exec {cid} -- bash -lc "
                f"'chown -R media:media /opt/{a['dir']}'"),
        ("start", f"pct exec {cid} -- systemctl start {sh(a['svc'])}"),
        ("tidy", f"pct exec {cid} -- rm -f {sh(tmp)}"),
    ]


def act_update_host(p):
    return [
        ("refresh", "apt-get update"),
        ("upgrade", "DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade"),
    ]


def free_resources():
    """What the host can actually still hand out, for deploy preflight."""
    mem = run("free -m | awk '/^Mem:/{print $7}'", timeout=15)
    try:
        free_mb = int(mem)
    except ValueError:
        free_mb = 0
    store = {}
    for line in run("pvesm status", timeout=20).splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[2] == "active":
            try:
                store[f[0]] = int(f[5]) // (1024 * 1024)   # KiB -> GiB
            except ValueError:
                pass
    return free_mb, store


def act_deploy_script(p):
    """Create a new LXC from a community-scripts helper script.

    These scripts are interactive by default. build.func exposes a documented
    unattended mode (MODE=default plus pre-seeded var_*), which is what makes
    a one-click deploy possible at all; without it the script would block on a
    whiptail menu with nobody to answer it.
    """
    slug = need_slug(p, "slug")
    cat = load_catalog()
    # Prefer the container-creating entry: a repo may carry a vm/ script of the
    # same name, and only the LXC one can run unattended.
    cands = [a for a in cat.get("apps", []) if a["slug"] == slug]
    entry = next((a for a in cands if a.get("target") == "ct"), None) or \
        (cands[0] if cands else None)
    if not entry:
        raise ValueError(f"{slug} is not in the helper-script catalog")
    if not entry.get("unattended", False):
        # vm/ and tools/ scripts are whiptail wizards with no non-interactive
        # path. Running one here would block on a menu nobody can answer until
        # the job timed out an hour later, so refuse plainly instead.
        raise ValueError(
            f"'{entry['name']}' is a {entry.get('kindlabel', 'script')} and only "
            f"runs interactively - it asks questions this runner cannot answer. "
            f"Run it yourself from a shell on the host.")

    cpu = int(p.get("cpu") or entry.get("cpu") or 1)
    ram = int(p.get("ram") or entry.get("ram") or 1024)
    disk = int(p.get("disk") or entry.get("disk") or 4)
    if not (1 <= cpu <= 32 and 256 <= ram <= 65536 and 2 <= disk <= 2048):
        raise ValueError("requested cpu/ram/disk are outside sane bounds")

    free_mb, store = free_resources()
    tstore = need_slug(p, "template_storage") if p.get("template_storage") else "local"
    cstore = need_slug(p, "container_storage") if p.get("container_storage") else "local-lvm"
    for name in (tstore, cstore):
        if name not in store:
            raise ValueError(f"storage '{name}' is not active on this host")
    # Refuse rather than let the host OOM or fill a thin pool mid-build.
    if ram > free_mb:
        raise ValueError(f"needs {ram}MB RAM but only {free_mb}MB is available")
    if disk > store.get(cstore, 0):
        raise ValueError(f"needs {disk}GB but {cstore} has only "
                         f"{store.get(cstore, 0)}GB free")

    ctid = p.get("ctid")
    if ctid is not None:
        try:
            ctid = int(ctid)
        except (TypeError, ValueError):
            raise ValueError("ctid must be a number")
        if ctid in lxc_ids():
            raise ValueError(f"container id {ctid} is already in use")
    else:
        ctid = int(run("pvesh get /cluster/nextid", timeout=20) or 0) or None

    env = {
        "MODE": "default",          # documented unattended path in core.func
        "var_cpu": cpu, "var_ram": ram, "var_disk": disk,
        "var_template_storage": tstore, "var_container_storage": cstore,
        "var_brg": p.get("bridge") or "vmbr0",
        "var_net": "dhcp", "var_ipv6_method": "none",
        "var_unprivileged": "1", "var_verbose": "yes",
    }
    if ctid:
        env["var_ctid"] = ctid
    if p.get("hostname"):
        env["var_hostname"] = need_slug(p, "hostname")
    prefix = " ".join(f"{k}={sh(v)}" for k, v in env.items())

    # Pin to the commit the catalog was built from. "main" could have moved
    # since the operator read the description they are agreeing to run.
    # Each entry carries the repo and the exact commit its metadata came from,
    # so adding a custom source cannot redirect a stock script somewhere else,
    # and the branch moving after the operator read the description does not
    # change what actually runs.
    repo = entry.get("repo") or CT_REPO
    ref = entry.get("ref") or cat.get("commit") or "main"
    path = entry.get("path") or ("ct/" + slug + ".sh")
    if not _REPO_RE.match(repo) or not _REF_RE.match(ref) or not _PATH_RE.match(path):
        raise ValueError("this catalogue entry has an unusable source reference")
    url = f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"
    return [("deploy", f"{prefix} bash -c \"$(curl -fsSL {sh(url)})\"")]


def act_deploy_compose(p):
    """Bring up a curated compose stack inside an existing container."""
    cid = need_ct(p)
    slug = need_slug(p, "slug")
    cat = load_catalog()
    tpl = next((t for t in cat.get("compose", []) if t["slug"] == slug), None)
    if not tpl:
        raise ValueError(f"{slug} is not in the compose catalog")
    if run(f"pct exec {cid} -- bash -lc 'command -v docker >/dev/null && echo ok'",
           timeout=20) != "ok":
        raise ValueError(f"container {cid} has no docker installed")

    d = f"{COMPOSE_ROOT}/{slug}"
    if run(f"pct exec {cid} -- test -e {sh(d)} && echo ok", timeout=20) == "ok":
        raise ValueError(f"{d} already exists in container {cid} - "
                         f"refusing to overwrite an existing stack")
    body = tpl["compose"]
    # Hand the file over on stdin; it never passes through a shell word.
    return [
        ("create", f"pct exec {cid} -- mkdir -p {sh(d)}"),
        ("write compose", f"pct exec {cid} -- tee {sh(d)}/docker-compose.yml",
         body),
        ("start", f"pct exec {cid} -- bash -lc 'cd {sh(d)} && docker compose up -d'"),
    ]


OPS = {"start", "stop", "restart"}


def need_op(p):
    op = str(p.get("op") or "")
    if op not in OPS:
        raise ValueError("op must be start, stop or restart")
    return op


def act_service_systemd(p):
    cid = need_ct(p)
    unit = need_slug(p, "unit")
    op = need_op(p)
    # systemctl exits 0 for a stop that was already stopped, so the status
    # afterwards is what actually tells the operator where they ended up.
    return [
        (op, f"pct exec {cid} -- systemctl {op} {sh(unit)}"),
        ("status", f"pct exec {cid} -- bash -lc "
                   f"'systemctl --no-pager --lines=12 status {sh(unit)} || true'"),
    ]


def act_service_docker(p):
    cid = need_ct(p)
    d = need_dir(cid, p)
    op = need_op(p)
    return [
        (op, f"pct exec {cid} -- bash -lc 'cd {sh(d)} && docker compose {op}'"),
        ("status", f"pct exec {cid} -- bash -lc 'cd {sh(d)} && docker compose ps'"),
    ]


def act_service_ct(p):
    """Start or stop a whole container.

    need_ct() insists the target is already running, which is wrong here - a
    container we are about to start is by definition not - so the check is
    done directly.
    """
    try:
        cid = int(p.get("cid"))
    except (TypeError, ValueError):
        raise ValueError("cid must be a container id")
    if cid not in lxc_ids():
        raise ValueError(f"container {cid} does not exist on this host")
    op = need_op(p)
    verb = {"start": "start", "stop": "shutdown", "restart": "reboot"}[op]
    # 'pct shutdown' asks the guest politely and waits; 'pct stop' pulls the
    # power. Always prefer the former - a torn filesystem is not worth the
    # few seconds saved.
    extra = " --timeout 90" if verb in ("shutdown", "reboot") else ""
    return [
        (op, f"pct {verb} {cid}{extra}"),
        ("status", f"pct status {cid}"),
    ]


def act_catalog_refresh(p):
    """Rebuild the catalogue now instead of waiting for the hourly sweep.

    Handled directly in execute() rather than as a shell step, because the work
    is this process's own Python - shelling out to a second interpreter just to
    call a function in this file would be silly.
    """
    return []



# ---- cloudflare tunnel ingress
#
# The web UI sends route parameters, never YAML and never a command. The file
# is rendered here, cloudflared validates it, and activation only happens if
# that validation passed - a bad rule set therefore cannot reach the running
# tunnel. Note cloudflared treats SIGHUP as shutdown, so this restarts rather
# than reloads.

_CF_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                         r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_CF_SVC_RE = re.compile(r"^(https?|tcp|ssh|rdp)://[a-z0-9][a-z0-9.-]*:[0-9]{1,5}$")
CF_CONFIG = "/etc/cloudflared/config.yml"
CF_MAX_RULES = 100


def _cf_tunnel_id(cid):
    """Tunnel id read from the container's own token, never from parameters."""
    out = run(
        f"pct exec {cid} -- python3 -c \""
        f"import base64,json;"
        f"raw=open('/etc/cloudflared/token').read().strip();"
        f"print(json.loads(base64.b64decode(raw+'='*(-len(raw)%4)))['t'])\"",
        timeout=25)
    tid = (out or "").strip()
    if not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    tid):
        raise ValueError("could not read the tunnel id from the container's token")
    return tid


def _cf_metrics(cid):
    """The metrics address to keep in the rewritten config.

    Preserved from the config the connector is already running with, so a
    rewrite never silently moves the endpoint the Routing tab reads from. When
    there is nothing to preserve it is derived from the container's own
    address, which is what a fresh install wants.
    """
    cur = run(f"pct exec {cid} -- grep -oP '(?<=^metrics:)\\s*\\S+' {CF_CONFIG} "
              f"2>/dev/null", timeout=15)
    if cur and cur.strip():
        return cur.strip()
    ip = run(f"pct exec {cid} -- hostname -I", timeout=15).split()
    return f"{ip[0]}:20241" if ip else "127.0.0.1:20241"


def _cf_render(tunnel_id, rules, metrics):
    lines = [
        "# Cloudflare Tunnel ingress - written by the dashboard Routing tab.",
        "# Validated with: cloudflared tunnel --config %s ingress validate" % CF_CONFIG,
        "",
        "tunnel: %s" % tunnel_id,
        "credentials-file: /etc/cloudflared/credentials.json",
        "metrics: %s" % metrics,
        "no-autoupdate: true",
        "",
        "ingress:",
    ]
    for r in rules:
        lines.append("  - hostname: %s" % r["hostname"])
        lines.append("    service: %s" % r["service"])
        if r.get("no_tls_verify"):
            lines.append("    originRequest:")
            lines.append("      noTLSVerify: true")
    lines.append("  - service: http_status:404")
    lines.append("")
    return "\n".join(lines)


def act_tunnel_ingress(p):
    cid = need_ct(p)
    raw = p.get("rules")
    if not isinstance(raw, list) or not raw:
        raise ValueError("rules must be a non-empty list")
    if len(raw) > CF_MAX_RULES:
        raise ValueError("too many rules (limit %d)" % CF_MAX_RULES)

    rules, seen = [], set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each rule must be an object")
        host = str(item.get("hostname") or "").strip().lower().rstrip(".")
        svc = str(item.get("service") or "").strip()
        if not _CF_HOST_RE.match(host):
            raise ValueError("invalid hostname %r" % host)
        if not _CF_SVC_RE.match(svc):
            raise ValueError("invalid service %r for %s" % (svc, host))
        if host in seen:
            raise ValueError("duplicate hostname %s" % host)
        seen.add(host)
        rules.append({"hostname": host, "service": svc,
                      "no_tls_verify": bool(item.get("no_tls_verify"))})

    body = _cf_render(_cf_tunnel_id(cid), rules, _cf_metrics(cid))
    b64 = base64.b64encode(body.encode()).decode()
    cand = CF_CONFIG + ".new"
    return [
        ("write candidate",
         f"pct exec {cid} -- bash -c {sh('printf %s ' + sh(b64) + ' | base64 -d > ' + cand)}"),
        ("cloudflared validates it",
         f"pct exec {cid} -- cloudflared tunnel --config {cand} ingress validate"),
        ("keep a copy of the previous config",
         f"pct exec {cid} -- bash -c {sh('test -f ' + CF_CONFIG + ' && cp ' + CF_CONFIG + ' ' + CF_CONFIG + '.prev || true')}"),
        ("activate",
         f"pct exec {cid} -- mv {cand} {CF_CONFIG}"),
        ("restart the connector",
         f"pct exec {cid} -- systemctl restart cloudflared"),
        ("confirm it came back",
         f"pct exec {cid} -- bash -c {sh('for i in $(seq 1 15); do sleep 2; curl -sf --max-time 3 http://127.0.0.1:20241/ready && exit 0; done; echo "connector did not report ready"; exit 1')}"),
    ]


# ---- package catalogues
#
# Two catalogues are browsable from the app store: apt, on the host and inside
# every running container, and the Proxmox appliance (LXC template) catalogue
# on the host. Browsing them needs pct, which the web UI deliberately cannot
# reach, so lookups arrive here as queries and installs arrive as jobs.
#
# Nothing below ever puts a caller's string into a command unquoted, and the
# read-only half is genuinely read-only: every query builder runs apt-cache,
# dpkg-query, apt list, apt-get -s or pveam and nothing else.

_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,99}$")
# apt-cache takes a regex, so the punctuation it would act on is kept out.
_SEARCH_RE = re.compile(r"^[A-Za-z0-9 +._:@/-]{2,80}$")
_TEMPLATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.tar\.(gz|xz|zst)$")
_STORAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,64}$")
_QID_RE = re.compile(r"^[0-9]{10}-[0-9a-f]{8}$")

MAX_PKGS = 20                   # packages one job may name
MAX_SEARCH = 600                # search rows handed back to the browser
MAX_CASUALTIES = 60             # a removal cascade larger than this is a mistake
APT_ENV = "DEBIAN_FRONTEND=noninteractive"

# Packages whose removal would take this box or one of its services down.
# apt's own Essential/Priority flags catch the generic ones and are checked
# against the simulated removal; these are the ones specific to this host,
# which apt has no way to know matter.
PROTECTED_PKGS = {
    "proxmox-ve", "pve-manager", "pve-container", "pve-cluster", "pve-firewall",
    "pve-ha-manager", "qemu-server", "lxc-pve", "pve-qemu-kvm", "novnc-pve",
    "proxmox-kernel-helper", "zfsutils-linux", "grub-pc", "grub-efi-amd64",
    "ifupdown2", "openssh-server", "sudo", "systemd", "systemd-sysv",
    "python3", "python3-minimal", "ca-certificates", "unattended-upgrades",
    "jellyfin", "jellyfin-server", "jellyfin-web", "qbittorrent-nox",
    "grafana", "influxdb2", "cloudflared",
    "docker-ce", "docker-ce-cli", "docker.io", "containerd.io", "docker-compose-plugin",
}


def need_pkgs(p, key="names"):
    raw = p.get(key)
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raise ValueError("name at least one package")
    if len(raw) > MAX_PKGS:
        raise ValueError(f"at most {MAX_PKGS} packages at a time")
    out = []
    for n in raw:
        n = str(n or "").strip()
        if not _PKG_RE.match(n):
            raise ValueError(f"{n!r} is not a package name")
        if n not in out:
            out.append(n)
    return out


def _rank(name, q):
    """Order search hits the way someone typing a name expects them."""
    if name == q:
        return (0, name)
    if name.startswith(q):
        return (1, name)
    if q in name:
        return (2, name)
    return (3, name)                       # matched on the description only


def q_apt_search(p):
    cid = need_target(p)
    q = str(p.get("q") or "").strip()
    if not _SEARCH_RE.match(q):
        raise ValueError("search for 2-80 characters of plain text")
    flag = "--names-only " if p.get("names_only") else ""
    out = run(in_target(cid, f"apt-cache search {flag}-- {sh(q)}"), timeout=60)
    rows = []
    for line in out.splitlines():
        name, _, desc = line.partition(" - ")
        name = name.strip()
        if _PKG_RE.match(name):
            rows.append({"name": name, "desc": desc.strip()[:200]})
    rows.sort(key=lambda r: _rank(r["name"], q.lower()))
    return {"rows": rows[:MAX_SEARCH], "total": len(rows)}


def _parse_policy(text):
    """apt-cache policy for several packages, as {name: {installed, candidate}}."""
    out, cur = {}, None
    for line in text.splitlines():
        if not line.startswith(" ") and line.endswith(":"):
            cur = line[:-1].strip()
            if _PKG_RE.match(cur):
                out[cur] = {"installed": "", "candidate": ""}
            else:
                cur = None
        elif cur and cur in out:
            m = re.match(r"\s+(Installed|Candidate):\s*(\S+)", line)
            if m:
                v = "" if m.group(2) == "(none)" else m.group(2)
                out[cur][m.group(1).lower()] = v
    return out


def q_apt_policy(p):
    """Installed and candidate versions for the slice of results on screen."""
    cid = need_target(p)
    names = need_pkgs(p, "names")
    joined = " ".join(sh(n) for n in names)
    return {"policy": _parse_policy(
        run(in_target(cid, f"apt-cache policy -- {joined}"), timeout=60))}


def q_apt_show(p):
    cid = need_target(p)
    name = need_pkgs(p, "names")[0]
    raw = run(in_target(cid, f"apt-cache show -- {sh(name)}"), timeout=45)
    # Several versions may be published; the first stanza is the candidate.
    stanza, fields, key = raw.split("\n\n", 1)[0], {}, None
    for line in stanza.splitlines():
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line.strip()
        else:
            k, _, v = line.partition(":")
            key = k.strip()
            fields[key] = v.strip()
    pol = _parse_policy(run(in_target(cid, f"apt-cache policy -- {sh(name)}"),
                            timeout=45)).get(name, {})
    desc = fields.get("Description-en") or fields.get("Description") or ""
    head, _, body = desc.partition("\n")
    return {
        "name": name,
        "summary": head,
        "description": "\n".join(
            "" if l.strip() == "." else l for l in body.splitlines()),
        "section": fields.get("Section", ""),
        "priority": fields.get("Priority", ""),
        "homepage": fields.get("Homepage", ""),
        "maintainer": fields.get("Maintainer", ""),
        "size": fields.get("Size", ""),
        "installed_size": fields.get("Installed-Size", ""),
        "depends": fields.get("Depends", ""),
        "installed": pol.get("installed", ""),
        "candidate": pol.get("candidate", ""),
        "protected": name in PROTECTED_PKGS,
    }


def q_apt_list(p):
    """Installed, hand-installed or upgradable packages on one target."""
    cid = need_target(p)
    mode = str(p.get("mode") or "installed")
    if mode not in ("installed", "manual", "upgradable"):
        raise ValueError("mode must be installed, manual or upgradable")

    if mode == "upgradable":
        raw = run(in_target(cid, "apt list --upgradable 2>/dev/null"), timeout=90)
        rows = []
        for line in raw.splitlines():
            m = re.match(r"^([a-z0-9][a-z0-9+._-]*)/\S+\s+(\S+)\s+\S+"
                         r"(?:\s+\[upgradable from:\s*([^\]]+)\])?", line)
            if m:
                rows.append({"name": m.group(1), "version": (m.group(3) or "").strip(),
                             "candidate": m.group(2), "desc": ""})
        return {"rows": rows[:MAX_SEARCH], "total": len(rows), "mode": mode}

    fmt = r"${binary:Package}\t${Version}\t${Installed-Size}\t${binary:Summary}\n"
    raw = run(in_target(cid, "dpkg-query -W -f=" + sh(fmt)
                        + " 2>/dev/null | sort"), timeout=90)
    manual = set()
    if mode == "manual":
        manual = {l.strip() for l in
                  run(in_target(cid, "apt-mark showmanual"), timeout=60).splitlines()
                  if _PKG_RE.match(l.strip())}
    rows = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not _PKG_RE.match(parts[0]):
            continue
        if mode == "manual" and parts[0] not in manual:
            continue
        rows.append({"name": parts[0], "version": parts[1],
                     "kb": parts[2], "desc": parts[3][:200]})
    return {"rows": rows[:MAX_SEARCH], "total": len(rows), "mode": mode}


def _parse_plan(text):
    """What apt says it would do, out of an `apt-get -s` transcript."""
    plan = {"install": [], "remove": [], "upgrade": [], "summary": "",
            "download": "", "space": ""}
    for line in text.splitlines():
        m = re.match(r"^(Inst|Remv|Conf)\s+(\S+)(?:\s+\[([^\]]*)\])?"
                     r"(?:\s+\(([^)]*)\))?", line)
        if m and m.group(1) != "Conf":
            was, to = m.group(3), (m.group(4) or "").split(" ")[0]
            row = {"name": m.group(2), "from": was or "", "to": to}
            plan["upgrade" if (m.group(1) == "Inst" and was)
                 else ("install" if m.group(1) == "Inst" else "remove")].append(row)
        elif line.startswith("Need to get"):
            plan["download"] = line.strip()
        elif "disk space" in line:
            plan["space"] = line.strip()
        elif re.match(r"^\d+ upgraded, ", line):
            plan["summary"] = line.strip()
    return plan


def q_apt_plan(p):
    """Dry-run an install or removal so the UI can show it before it happens."""
    cid = need_target(p)
    op = str(p.get("op") or "")
    if op not in ("install", "remove", "purge", "upgrade"):
        raise ValueError("op must be install, remove, purge or upgrade")
    names = need_pkgs(p)
    joined = " ".join(sh(n) for n in names)
    verb = "install" if op == "upgrade" else op
    raw = run(in_target(cid, f"{APT_ENV} apt-get -s {verb} -- {joined} 2>&1"),
              timeout=120)
    plan = _parse_plan(raw)
    plan["raw"] = raw[-8000:]
    plan["blocked"] = _removal_objections(cid, op, plan["remove"]) if plan["remove"] else []
    return plan


def _removal_objections(cid, op, removals):
    """Reasons this removal should not be allowed to run.

    Checked against the *simulated* transaction rather than the packages named,
    because the damage from a removal is nearly always something apt decided to
    take with it rather than the thing that was asked for.
    """
    names = [r["name"] for r in removals]
    out = []
    if len(names) > MAX_CASUALTIES:
        out.append(f"apt wants to remove {len(names)} packages - that is a "
                   f"cascade, not a removal, so it is refused")
        return out
    hit = sorted(set(names) & PROTECTED_PKGS)
    if hit:
        out.append("this would remove " + ", ".join(hit)
                   + ", which this host or one of its services is built on")
    if names:
        joined = " ".join(sh(n) for n in names[:MAX_CASUALTIES])
        fmt = r"${binary:Package}\t${Essential}\t${Priority}\n"
        raw = run(in_target(cid, "dpkg-query -W -f=" + sh(fmt) + f" -- {joined}"
                            " 2>/dev/null"), timeout=60)
        for line in raw.splitlines():
            f = line.split("\t")
            if len(f) >= 3 and (f[1] == "yes" or f[2] == "required"):
                out.append(f"{f[0]} is marked "
                           + ("essential" if f[1] == "yes" else "required")
                           + " by the distribution")
    return out


def q_pveam_catalog(p):
    """The Proxmox appliance catalogue, plus what is already downloaded."""
    stores, cur = [], None
    for line in run("pvesm status --content vztmpl", timeout=30).splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and _STORAGE_RE.match(f[0]):
            stores.append({"name": f[0], "free_gb": round(int(f[5]) / 1048576, 1)
                           if f[5].isdigit() else 0, "active": f[2] == "active"})
    have = set()
    for s in stores:
        for line in run(f"pveam list {sh(s['name'])}", timeout=30).splitlines()[1:]:
            f = line.split()
            if f:
                have.add(f[0].split("/")[-1])
    rows = []
    for line in run("pveam available", timeout=60).splitlines():
        f = line.split()
        if len(f) >= 2 and _TEMPLATE_RE.match(f[1]):
            rows.append({"section": f[0], "template": f[1],
                         "downloaded": f[1] in have})
    rows.sort(key=lambda r: (r["section"], r["template"]))
    return {"rows": rows, "storages": stores, "total": len(rows)}


QUERIES = {
    "apt.search": q_apt_search,
    "apt.policy": q_apt_policy,
    "apt.show":   q_apt_show,
    "apt.list":   q_apt_list,
    "apt.plan":   q_apt_plan,
    "pveam.catalog": q_pveam_catalog,
}


def serve_queries():
    """Answer any spooled read-only lookups. Called between job sweeps."""
    try:
        names = sorted(n for n in os.listdir(QUERY_DIR) if n.endswith(".json"))
    except OSError:
        return
    for n in names:
        path = os.path.join(QUERY_DIR, n)
        try:
            with open(path) as f:
                q = json.load(f)
        except Exception:
            q = None
        # Consumed before it is served, so a lookup that wedges this process
        # cannot be replayed on every sweep for the rest of the day.
        try:
            os.unlink(path)
        except OSError:
            pass
        if not isinstance(q, dict):
            continue
        qid = str(q.get("id") or "")
        if not _QID_RE.match(qid):
            continue
        fn = QUERIES.get(str(q.get("kind") or ""))
        try:
            if not fn:
                raise ValueError("unknown query")
            ans = {"ok": True, "data": fn(q.get("params") or {})}
        except ValueError as e:
            ans = {"ok": False, "error": str(e)}
        except Exception as e:
            ans = {"ok": False, "error": f"lookup failed: {e}"}
        out = os.path.join(QUERY_DIR, qid + ".out")
        try:
            with open(out + ".tmp", "w") as f:
                json.dump(ans, f)
            shutil.move(out + ".tmp", out)
        except OSError:
            pass


def act_pkg_install(p):
    cid = need_target(p)
    names = need_pkgs(p)
    joined = " ".join(sh(n) for n in names)
    # The lists are refreshed first: an install against a stale index fails on
    # a 404 for a version the mirror has already rotated out.
    return [
        ("refresh package lists", in_target(cid, f"{APT_ENV} apt-get update")),
        (f"what apt intends to do on {target_label(cid)}",
         in_target(cid, f"{APT_ENV} apt-get -s install -- {joined}")),
        ("install", in_target(cid, f"{APT_ENV} apt-get install -y -- {joined}")),
    ]


def act_pkg_remove(p):
    cid = need_target(p)
    names = need_pkgs(p)
    purge = bool(p.get("purge"))
    for n in names:
        if n in PROTECTED_PKGS:
            raise ValueError(
                f"{n} is part of what this host runs on, so the dashboard will "
                f"not remove it. Do that from a shell if you really mean it.")
    op = "purge" if purge else "remove"
    joined = " ".join(sh(n) for n in names)
    # Simulated here as well as in the UI: the plan the operator approved may be
    # minutes old, and apt is entitled to have changed its mind since.
    sim = run(in_target(cid, f"{APT_ENV} apt-get -s {op} -- {joined} 2>&1"),
              timeout=120)
    objections = _removal_objections(cid, op, _parse_plan(sim)["remove"])
    if objections:
        raise ValueError("; ".join(objections))
    return [
        (f"what apt intends to do on {target_label(cid)}",
         in_target(cid, f"{APT_ENV} apt-get -s {op} -- {joined}")),
        (op, in_target(cid, f"{APT_ENV} apt-get {op} -y -- {joined}")),
    ]


def act_pkg_refresh(p):
    cid = need_target(p)
    return [("refresh package lists", in_target(cid, f"{APT_ENV} apt-get update")),
            ("what is upgradable now",
             in_target(cid, "apt list --upgradable 2>/dev/null"))]


def act_template_download(p):
    """Pull an LXC template from the Proxmox appliance catalogue."""
    tpl = str(p.get("template") or "")
    store = str(p.get("storage") or "local")
    if not _TEMPLATE_RE.match(tpl):
        raise ValueError("that is not a template file name")
    if not _STORAGE_RE.match(store):
        raise ValueError("that is not a storage name")
    # Validated against the live catalogue, so only something Proxmox itself
    # offers can be asked for - the name never becomes an arbitrary download.
    avail = [l.split()[1] for l in run("pveam available", timeout=60).splitlines()
             if len(l.split()) >= 2]
    if tpl not in avail:
        raise ValueError(f"{tpl} is not in the Proxmox appliance catalogue")
    if store not in [l.split()[0] for l in
                     run("pvesm status --content vztmpl", timeout=30).splitlines()[1:]
                     if l.split()]:
        raise ValueError(f"{store} does not hold container templates")
    return [("download", f"pveam download {sh(store)} {sh(tpl)}"),
            ("what is on that storage now", f"pveam list {sh(store)}")]


ACTIONS = {
    "catalog.refresh": act_catalog_refresh,
    "pkg.install":    act_pkg_install,
    "pkg.remove":     act_pkg_remove,
    "pkg.refresh":    act_pkg_refresh,
    "template.download": act_template_download,
    "service.systemd": act_service_systemd,
    "tunnel.ingress":  act_tunnel_ingress,
    "service.docker":  act_service_docker,
    "service.ct":      act_service_ct,
    "update.docker":  act_update_docker,
    "update.apt":     act_update_apt,
    "update.arr":     act_update_arr,
    "update.host":    act_update_host,
    "deploy.script":  act_deploy_script,
    "deploy.compose": act_deploy_compose,
}


# ---- catalog

def _parse_header(text):
    """Pull the var_* block out of a community ct/*.sh script.

    Their website used to publish this as JSON, but that moved to
    community-scripts.org and the old json path 404s. The script headers are
    the durable source - they are what the scripts themselves read.
    """
    def g(key, default=None):
        m = re.search(rf'^{key}="\$\{{{key}:-([^}}]*)\}}"', text, re.M)
        if m:
            return m.group(1)
        m = re.search(rf'^{key}="([^"]*)"', text, re.M)
        return m.group(1) if m else default

    app = g("APP")
    if not app:
        return None
    def num(key, default):
        v = g(key, "")
        return int(v) if str(v).isdigit() else default
    src = re.search(r"^# Source:\s*(\S+)", text, re.M)
    return {
        "name": app,
        "cpu": num("var_cpu", 1),
        "ram": num("var_ram", 1024),
        "disk": num("var_disk", 4),
        "os": g("var_os", "debian"),
        "os_version": g("var_version", ""),
        "tags": [t for t in (g("var_tags", "") or "").split(";") if t],
        "source": src.group(1) if src else "",
    }


ICON_INDEX = os.path.join(STATE_DIR, "icons.json")
ICON_REPO = "selfhst/icons"

# Slugs whose icon is published under a different name. Only the ones that
# actually occur in the helper-script catalogue - there is no value in
# maintaining a general alias table.
ICON_ALIAS = {
    "adguard": "adguard-home",
    "actualbudget": "actual-budget",
    "agentdvr": "agent-dvr",
    "pbs": "proxmox-backup-server",
    "pve": "proxmox",
    "qbittorrent": "qbittorrent",
    "emby": "emby",
    "the-lounge": "thelounge",
}


def icon_for(slug, have):
    """Best matching icon name for a catalogue slug, or None.

    Tried in order because the helper-script slugs and the icon set are
    maintained by different projects and only mostly agree.
    """
    for cand in (slug,
                 ICON_ALIAS.get(slug),
                 slug[7:] if slug.startswith("alpine-") else None,
                 slug.replace("-", ""),
                 slug + "-home"):
        if cand and cand in have:
            return cand
    return None


def refresh_icons():
    """Index which icons exist upstream, so the UI never requests a missing one.

    One git-tree call returns all 7000-odd names; the images themselves are
    fetched lazily by the web layer only when a card is actually shown.
    """
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{ICON_REPO}/git/trees/main?recursive=1",
            headers={"User-Agent": "media-dashboard"})
        with urllib.request.urlopen(req, timeout=60) as r:
            tree = json.load(r)
    except Exception as e:
        log_line(f"icon index failed: {e}")
        return set()
    have = {p["path"][4:-4] for p in tree.get("tree", [])
            if p.get("path", "").startswith("svg/") and p["path"].endswith(".svg")}
    tmp = ICON_INDEX + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"fetched": int(time.time()), "icons": sorted(have)}, f)
    shutil.move(tmp, ICON_INDEX)
    log_line(f"icon index refreshed: {len(have)} icons")
    return have


def _pretty(slug):
    words = slug.replace("_", "-").split("-")
    caps = {"vm", "lxc", "pve", "os", "db", "ai", "dns", "ha", "nvr", "tv", "id"}
    return " ".join(w.upper() if w in caps else w.capitalize() for w in words)


def _fetch_tarball(repo, ref, dest):
    """One tarball beats hundreds of API calls.

    The contents API would burn the unauthenticated hourly quota several times
    over for a repo this size; codeload is not rate limited the same way.
    """
    try:
        with urllib.request.urlopen(repo_tarball(repo, ref), timeout=180) as r, \
                open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
        return True
    except Exception as e:
        log_line(f"fetch {repo}@{ref} failed: {e}")
        return False


def _pin(repo, ref):
    """Resolve a branch to the exact commit the catalogue was built from.

    Deploys use this rather than the branch name, so what an operator agreed to
    run is what runs even if the branch moves a minute later.
    """
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/commits/{ref}",
            headers={"User-Agent": "media-dashboard",
                     "Accept": "application/vnd.github.sha"})
        with urllib.request.urlopen(req, timeout=30) as r:
            m = re.search(r"([0-9a-f]{40})", r.read(64).decode("ascii", "replace"))
            if m:
                return m.group(1)
    except Exception as e:
        log_line(f"commit pin for {repo} failed: {e}")
    return ref


def _scan_helpers(src, tarpath, have):
    """Pull script metadata out of one helper-script repository."""
    bydir = {s["dir"]: s for s in (src.get("sets") or [])}
    apps = []
    with tarfile.open(tarpath) as t:
        for m in t.getmembers():
            if not m.isfile() or not m.name.endswith(".sh"):
                continue
            parts = m.name.split("/")[1:]              # drop the tarball prefix
            d, fn = "/".join(parts[:-1]), parts[-1]
            spec = bydir.get(d)
            if not spec:
                continue
            try:
                data = t.extractfile(m).read(8192).decode("utf-8", "replace")
            except Exception:
                continue
            slug = fn[:-3]
            info = _parse_header(data)
            if not info:
                # vm/ and tools/ carry no var_* block, so there is nothing to
                # read - name them from the filename and leave the resource
                # figures at zero rather than inventing numbers.
                s = re.search(r"^# (?:Source|Author):\s*(\S+)", data, re.M)
                info = {"name": _pretty(slug), "cpu": 0, "ram": 0, "disk": 0,
                        "os": "", "os_version": "", "tags": [],
                        "source": s.group(1) if s and
                        s.group(1).startswith("http") else ""}
            # Read the capability off the script rather than trusting the
            # source config: sourcing build.func is what actually provides the
            # documented MODE=default path, and it is the same test that showed
            # 589/589 ct scripts have it against 0/16 under vm. A custom repo
            # therefore configures itself, and cannot claim an unattended mode
            # it does not have.
            unattended = "build.func" in data
            info.update({
                "slug": slug, "target": spec["target"],
                "unattended": unattended,
                "kindlabel": spec.get("label", ""),
                "path": d + "/" + fn,
                "src": src["id"], "srcname": src.get("name") or src["id"],
                "repo": src["repo"],
            })
            ic = icon_for(slug, have)
            if ic:
                info["icon"] = ic
            apps.append(info)
    return apps


def _scan_compose(src, tarpath, have):
    """Every directory holding a compose file becomes one deployable stack."""
    root = (src.get("path") or "").strip("/")
    out = []
    with tarfile.open(tarpath) as t:
        for m in t.getmembers():
            if not m.isfile():
                continue
            parts = m.name.split("/")[1:]
            if not parts or parts[-1] not in ("docker-compose.yml",
                                              "docker-compose.yaml",
                                              "compose.yml", "compose.yaml"):
                continue
            d = "/".join(parts[:-1])
            if root and not d.startswith(root + "/") and d != root:
                continue
            slug = (parts[-2] if len(parts) >= 2 else "").lower()
            if not _SLUG.match(slug or ""):
                continue
            if m.size > 256 * 1024:
                continue
            try:
                body = t.extractfile(m).read(256 * 1024).decode("utf-8", "replace")
            except Exception:
                continue
            port = ""
            pm = re.search(r"^\s*-\s*[\"']?(\d{2,5}):\d{2,5}", body, re.M)
            if pm:
                port = pm.group(1)
            row = {"slug": slug, "name": _pretty(slug), "port": port,
                   "blurb": f"Compose stack from {src.get('name') or src['id']}.",
                   "compose": body, "src": src["id"],
                   "srcname": src.get("name") or src["id"]}
            ic = icon_for(slug, have)
            if ic:
                row["icon"] = ic
            out.append(row)
    return out


def refresh_catalog(force=False):
    """Rebuild the catalogue from every enabled source.

    A source that fails to fetch is skipped with a log line rather than taking
    the whole catalogue down with it - one unreachable third-party repo should
    not empty the app store.
    """
    try:
        cur = load_catalog()
        if not force and time.time() - cur.get("fetched", 0) < CATALOG_TTL:
            return cur
    except Exception:
        pass

    have = set()
    try:
        with open(ICON_INDEX) as f:
            have = set(json.load(f).get("icons", []))
    except Exception:
        pass
    if not have:
        have = refresh_icons()

    sources = load_sources()
    apps, compose, meta, pins = [], [], [], {}
    seen_app, seen_stack = set(), set()

    for src in sources["helpers"]:
        if not src.get("enabled", True):
            meta.append({"id": src["id"], "name": src.get("name"), "kind": "helpers",
                         "enabled": False, "count": 0,
                         "builtin": bool(src.get("builtin"))})
            continue
        tmp = f"/tmp/src-{re.sub(r'[^a-z0-9]+', '-', src['id'].lower())}.tar.gz"
        ok = _fetch_tarball(src["repo"], src.get("ref", "main"), tmp)
        rows = []
        if ok:
            try:
                rows = _scan_helpers(src, tmp, have)
            except Exception as e:
                log_line(f"parse {src['id']} failed: {e}")
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            pins[src["id"]] = _pin(src["repo"], src.get("ref", "main"))
        # First source to claim a slug keeps it, so a custom repo cannot
        # silently shadow a stock script an operator thought they were running.
        kept = []
        for r in rows:
            key = (r["target"], r["slug"])
            if key in seen_app:
                continue
            seen_app.add(key)
            r["ref"] = pins.get(src["id"], src.get("ref", "main"))
            kept.append(r)
        apps.extend(kept)
        meta.append({"id": src["id"], "name": src.get("name"), "kind": "helpers",
                     "enabled": True, "count": len(kept), "repo": src.get("repo"),
                     "ref": src.get("ref", "main"), "pin": pins.get(src["id"], ""),
                     "ok": ok, "builtin": bool(src.get("builtin")),
                     "skipped": len(rows) - len(kept)})

    for src in sources["compose"]:
        if not src.get("enabled", True):
            meta.append({"id": src["id"], "name": src.get("name"), "kind": "compose",
                         "enabled": False, "count": 0,
                         "builtin": bool(src.get("builtin"))})
            continue
        if src.get("builtin"):
            rows = []
            for t in COMPOSE_TEMPLATES:
                t = dict(t)
                t["src"] = src["id"]
                t["srcname"] = src.get("name") or src["id"]
                ic = icon_for(t["slug"], have)
                if ic:
                    t["icon"] = ic
                rows.append(t)
            ok = True
        else:
            tmp = f"/tmp/src-{re.sub(r'[^a-z0-9]+', '-', src['id'].lower())}.tar.gz"
            ok = _fetch_tarball(src["repo"], src.get("ref", "main"), tmp)
            rows = []
            if ok:
                try:
                    rows = _scan_compose(src, tmp, have)
                except Exception as e:
                    log_line(f"parse {src['id']} failed: {e}")
                finally:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
        kept = []
        for r in rows:
            if r["slug"] in seen_stack:
                continue
            seen_stack.add(r["slug"])
            kept.append(r)
        compose.extend(kept)
        meta.append({"id": src["id"], "name": src.get("name"), "kind": "compose",
                     "enabled": True, "count": len(kept), "repo": src.get("repo"),
                     "ref": src.get("ref", "main"), "ok": ok,
                     "builtin": bool(src.get("builtin")),
                     "skipped": len(rows) - len(kept)})

    if not apps and not compose:
        log_line("catalog refresh produced nothing - keeping the previous one")
        return load_catalog()

    apps.sort(key=lambda a: a["name"].lower())
    compose.sort(key=lambda a: a["name"].lower())
    out = {
        "fetched": int(time.time()),
        # Kept for the stock repo because the UI shows it, but each app now
        # carries its own pinned ref in "ref".
        "commit": pins.get("community-scripts", "main"),
        "apps": apps,
        "compose": compose,
        "sources": meta,
    }
    tmpf = CATALOG_FILE + ".tmp"
    with open(tmpf, "w") as f:
        json.dump(out, f)
    shutil.move(tmpf, CATALOG_FILE)
    log_line(f"catalog refreshed: {len(apps)} scripts, {len(compose)} stacks "
             f"from {len([m for m in meta if m['enabled']])} sources")
    return out


HOSTS_FILE = os.path.join(STATE_DIR, "hosts.json")


def refresh_hosts():
    """Publish which containers can host a compose stack.

    The web UI cannot run pct, so it cannot work this out for itself. Written
    here on the hourly sweep and read straight off disk by the app store.
    """
    rows = []
    for cid in lxc_ids():
        if not running_ct(cid):
            continue
        name = run(f"pct config {cid} | sed -n 's/^hostname: //p'", timeout=15)
        has_docker = run(f"pct exec {cid} -- bash -lc "
                         f"'command -v docker >/dev/null && echo ok'",
                         timeout=25) == "ok"
        stacks = []
        if has_docker:
            found = run(f"pct exec {cid} -- bash -lc "
                        f"'ls -d {COMPOSE_ROOT}/*/docker-compose.yml 2>/dev/null'",
                        timeout=25)
            stacks = [os.path.dirname(l.strip())
                      for l in found.splitlines() if l.strip()]
        rows.append({"cid": cid, "name": name or str(cid),
                     "docker": has_docker, "stacks": stacks})
    # Capacity is published from here rather than measured in the web process:
    # under ProtectSystem=strict the LVM tooling pvesm shells out to cannot take
    # its locks, so local-lvm silently vanished from the listing and the app
    # store understated free disk by 106GB.
    free_mb, store = free_resources()
    tmp = HOSTS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"fetched": int(time.time()), "hosts": rows,
                   "capacity": {"ram_mb": free_mb, "storage": store}}, f)
    shutil.move(tmp, HOSTS_FILE)
    log_line(f"hosts refreshed: {sum(1 for r in rows if r['docker'])} docker-capable")


def load_catalog():
    try:
        with open(CATALOG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"fetched": 0, "apps": [], "compose": COMPOSE_TEMPLATES}


# A small hand-picked set, kept deliberately short. These go into an existing
# container, so they are the low-risk half of the app store.
COMPOSE_TEMPLATES = [
    {"slug": "uptime-kuma", "name": "Uptime Kuma", "port": 3001,
     "blurb": "Self-hosted uptime monitoring with status pages and alerting.",
     "compose": "services:\n  uptime-kuma:\n    image: louislam/uptime-kuma:1\n"
                "    container_name: uptime-kuma\n    restart: unless-stopped\n"
                "    ports:\n      - 3001:3001\n    volumes:\n"
                "      - ./data:/app/data\n"},
    {"slug": "vaultwarden", "name": "Vaultwarden", "port": 8222,
     "blurb": "Lightweight Bitwarden-compatible password manager server.",
     "compose": "services:\n  vaultwarden:\n    image: vaultwarden/server:latest\n"
                "    container_name: vaultwarden\n    restart: unless-stopped\n"
                "    environment:\n      - WEBSOCKET_ENABLED=true\n"
                "    ports:\n      - 8222:80\n    volumes:\n"
                "      - ./data:/data\n"},
    {"slug": "paperless-ngx", "name": "Paperless-ngx", "port": 8010,
     "blurb": "Scan, index and archive documents with full-text search.",
     "compose": "services:\n  broker:\n    image: redis:7\n    restart: unless-stopped\n"
                "  db:\n    image: postgres:16\n    restart: unless-stopped\n"
                "    environment:\n      POSTGRES_DB: paperless\n"
                "      POSTGRES_USER: paperless\n      POSTGRES_PASSWORD: paperless\n"
                "    volumes:\n      - ./db:/var/lib/postgresql/data\n"
                "  webserver:\n    image: ghcr.io/paperless-ngx/paperless-ngx:latest\n"
                "    restart: unless-stopped\n    depends_on:\n      - db\n      - broker\n"
                "    ports:\n      - 8010:8000\n    environment:\n"
                "      PAPERLESS_REDIS: redis://broker:6379\n"
                "      PAPERLESS_DBHOST: db\n    volumes:\n"
                "      - ./data:/usr/src/paperless/data\n"
                "      - ./media:/usr/src/paperless/media\n"},
    {"slug": "homepage", "name": "Homepage", "port": 3000,
     "blurb": "Configurable start page with service widgets and bookmarks.",
     "compose": "services:\n  homepage:\n    image: ghcr.io/gethomepage/homepage:latest\n"
                "    container_name: homepage\n    restart: unless-stopped\n"
                "    ports:\n      - 3000:3000\n    volumes:\n"
                "      - ./config:/app/config\n"
                "      - /var/run/docker.sock:/var/run/docker.sock:ro\n"},
    {"slug": "n8n", "name": "n8n", "port": 5678,
     "blurb": "Workflow automation with a visual node editor.",
     "compose": "services:\n  n8n:\n    image: docker.n8n.io/n8nio/n8n:latest\n"
                "    container_name: n8n\n    restart: unless-stopped\n"
                "    ports:\n      - 5678:5678\n    environment:\n"
                "      - N8N_SECURE_COOKIE=false\n    volumes:\n"
                "      - ./data:/home/node/.n8n\n"},
]


# ---- job execution

def log_line(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def write_job(path, job):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(job, f)
    shutil.move(tmp, path)


def execute(path, job):
    jid = job["id"]
    logf = os.path.join(JOB_DIR, f"{jid}.log")
    builder = ACTIONS.get(job.get("action", ""))

    job["status"] = "running"
    job["started"] = int(time.time())
    write_job(path, job)

    with open(logf, "a", buffering=1) as out:
        def emit(s):
            if out.tell() < LOG_CAP:
                out.write(s)

        if not builder:
            emit(f"unknown action: {job.get('action')}\n")
            job.update(status="failed", rc=64, finished=int(time.time()),
                       error="unknown action")
            return write_job(path, job)
        try:
            steps = builder(job.get("params") or {})
        except ValueError as e:
            # Validation failures are the operator's answer, not a crash.
            emit(f"cannot run this job: {e}\n")
            job.update(status="failed", rc=65, finished=int(time.time()),
                       error=str(e))
            return write_job(path, job)
        except Exception as e:
            emit(f"internal error preparing job: {e}\n")
            job.update(status="failed", rc=70, finished=int(time.time()),
                       error=str(e))
            return write_job(path, job)

        emit(f"=== {job['action']} requested by {job.get('user', '?')} "
             f"at {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

        if job["action"] == "catalog.refresh":
            try:
                refresh_icons()
                cat = refresh_catalog(force=True)
                refresh_hosts()
                for s in cat.get("sources", []):
                    emit(f"{s.get('name') or s['id']}: "
                         + ("disabled" if not s.get("enabled")
                            else f"{s.get('count', 0)} entries"
                                 + ("" if s.get("ok", True) else " (fetch FAILED)"))
                         + "\n")
                emit(f"\ntotal: {len(cat.get('apps', []))} scripts, "
                     f"{len(cat.get('compose', []))} stacks\n")
                rc = 0
                bad = [s for s in cat.get("sources", [])
                       if s.get("enabled") and not s.get("ok", True)]
                if bad:
                    emit("\none or more sources could not be fetched - the rest "
                         "of the catalogue was still rebuilt\n")
                    rc = 75
            except Exception as e:
                emit(f"refresh failed: {e}\n")
                rc = 70
            emit(f"\n=== finished rc={rc} ===\n")
            job.update(status="done" if rc == 0 else "failed", rc=rc,
                       finished=int(time.time()))
            write_job(path, job)
            return

        rc = 0
        deadline = time.time() + JOB_TIMEOUT
        for step in steps:
            label, cmd = step[0], step[1]
            stdin_data = step[2] if len(step) > 2 else None
            emit(f"\n--- {label} ---\n")
            left = max(1, int(deadline - time.time()))
            try:
                pr = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT,
                                      stdin=subprocess.PIPE if stdin_data else None,
                                      text=True, bufsize=1)
                if stdin_data:
                    pr.stdin.write(stdin_data)
                    pr.stdin.close()
                for line in pr.stdout:
                    emit(line)
                rc = pr.wait(timeout=left)
            except subprocess.TimeoutExpired:
                pr.kill()
                emit(f"\n[timed out after {JOB_TIMEOUT}s]\n")
                rc = 124
            except Exception as e:
                emit(f"\n[failed to run step: {e}]\n")
                rc = 71
            if rc != 0:
                emit(f"\n[step '{label}' exited {rc}]\n")
                break
        emit(f"\n=== finished rc={rc} ===\n")

    job.update(status="done" if rc == 0 else "failed", rc=rc,
               finished=int(time.time()))
    write_job(path, job)
    audit(job.get("user", "?"),
          f"JOB {job['action']} {json.dumps(job.get('params') or {})} -> rc={rc}")
    log_line(f"job {jid} {job['action']} rc={rc}")


def sweep_old():
    now = time.time()
    for n in os.listdir(JOB_DIR):
        p = os.path.join(JOB_DIR, n)
        try:
            if now - os.path.getmtime(p) > JOB_RETENTION:
                os.unlink(p)
        except OSError:
            pass
    # Answers nobody came back for - a browser tab closed mid-search.
    for n in os.listdir(QUERY_DIR):
        p = os.path.join(QUERY_DIR, n)
        try:
            if now - os.path.getmtime(p) > QUERY_TTL:
                os.unlink(p)
        except OSError:
            pass


def query_loop():
    """Serve read-only lookups, on a thread of their own.

    Deliberately not folded into the main loop: jobs are serialised there and
    one of them can legitimately run for half an hour, which would leave anyone
    browsing a package catalogue watching a spinner until the container had
    finished building. Queries touch nothing a job touches - they read apt and
    pveam and write one answer file each - so serving them alongside is safe.
    """
    while True:
        try:
            serve_queries()
        except Exception as e:
            log_line(f"query error: {e}")
        time.sleep(QUERY_POLL)


def main():
    os.makedirs(JOB_DIR, exist_ok=True)
    os.makedirs(QUERY_DIR, exist_ok=True)
    threading.Thread(target=query_loop, daemon=True).start()
    log_line("runner started")
    last_sweep = 0.0
    while True:
        try:
            for n in sorted(os.listdir(JOB_DIR)):
                if not n.endswith(".json"):
                    continue
                p = os.path.join(JOB_DIR, n)
                try:
                    with open(p) as f:
                        job = json.load(f)
                except Exception:
                    continue
                if job.get("status") == "queued":
                    execute(p, job)
            if time.time() - last_sweep > 3600:
                sweep_old()
                refresh_catalog()
                refresh_hosts()
                last_sweep = time.time()
        except Exception as e:
            log_line(f"loop error: {e}")
        time.sleep(POLL)


if __name__ == "__main__":
    main()
