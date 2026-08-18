"""Admin-only user provisioning: one account list, pushed out to the services.

The dashboard's own account store (/etc/media-dashboard/auth.json) is the source
of truth. For each dashboard user the admin ticks which services that person
should exist in, and a sync pushes the username, password and role out through
each service's own admin API. People then sign in to Jellyfin, Immich, Grafana
and the rest with the same credentials they use here.

This is provisioning, not single sign-on. There is no shared session: each
service still authenticates on its own, it just ends up holding the same
username and password. Real SSO would mean running an OIDC provider and would
still leave the single-account services below out in the cold.

Wiring (in media-dashboard-web.py):

    import mdash_usersync

    # in do_GET, after the session check:
    if mdash_usersync.handle_get(self, path, qs):
        return

    # at the top of do_POST (it checks the session itself):
    if mdash_usersync.handle_post(self, p):
        return

    # in nav(), inside the `if admin:` block:
    out += a("/usersync", "User sync")

Why passwords only flow on write. Nothing here stores a recoverable password -
auth.json keeps scrypt hashes, exactly as before. The plaintext exists only for
the length of the request in which an admin types it, which is the one moment it
can be handed to the other services. So creating a user, or changing a password,
syncs on the spot; ticking a new service for an existing user has to ask for the
password again, because by then nobody has it. That is a deliberate trade: the
alternative is a reversibly-encrypted password vault on a box that already keeps
its credentials in a plaintext file, and a stolen auth.json would then be every
account on the stack rather than just this one.

Password drift is tracked with a counter rather than a hash comparison. Each
user carries `pwv`, bumped on every password change; each service link records
the `pwv` it last pushed. Lower means that service still holds the old password.

Unticking a service disables the remote account by default rather than deleting
it - Jellyfin holds watch state, Immich holds photos, and an unticked box is a
cheap mistake to make. Deletion is a separate, explicit action.

Services that cannot take part, and why:

    Radarr, Sonarr, Prowlarr   one shared login for the whole application
    qBittorrent                 one WebUI account, set in its config
    Threadfin                   single auth toggle, no user list

These are not missing adapters, they are applications without a concept of more
than one user. They are listed in the UI so it is clear they were considered.
"""
import base64
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, "/usr/local/lib/mdash")
import mdash_site as site                              # noqa: E402

CONF_FILE = "/etc/media-dashboard/usersync.json"
JELLYFIN_KEY_FILE = "/root/.jellyfin-key"
TIMEOUT = 12
MAX_BODY = 64 * 1024

# Some services (Immich, RomM, Grafana) insist on an email address. Dashboard
# accounts are usernames only, so one is synthesised per user unless the admin
# sets a real one. .lan is reserved for exactly this - it can never collide with
# a real mailbox, and no service will manage to send mail to it.
DEFAULT_EMAIL_DOMAIN = "tower.lan"

_conf_lock = threading.Lock()


def _main_attr(name, default=None):
    """Borrow nav()/audit()/load_auth() from the dashboard without importing it."""
    return getattr(sys.modules.get("__main__"), name, default)


def _audit(user, msg):
    fn = _main_attr("audit")
    if fn:
        try:
            fn(user, msg)
        except Exception:
            pass


# ---------------------------------------------------------------- http
class ApiError(Exception):
    """A service said no. Carries enough to show the admin what went wrong."""

    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


def http(method, url, headers=None, json_body=None, form=None, basic=None,
         timeout=TIMEOUT):
    """One request. Returns parsed JSON, or text when the reply is not JSON."""
    h = dict(headers or {})
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        h.setdefault("Content-Type", "application/json")
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    if basic:
        tok = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        h["Authorization"] = "Basic " + tok
    h.setdefault("Accept", "application/json")

    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(2048).decode("utf-8", "replace")
        except Exception:
            pass
        raise ApiError(f"HTTP {e.code}: {_snippet(body) or e.reason}", e.code)
    except urllib.error.URLError as e:
        raise ApiError(f"unreachable: {getattr(e, 'reason', e)}")
    except Exception as e:                                   # socket timeouts
        raise ApiError(str(e)[:200])
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return raw.decode("utf-8", "replace")


def _snippet(body):
    """Pull the useful sentence out of an error body instead of dumping HTML."""
    body = (body or "").strip()
    if not body:
        return ""
    try:
        d = json.loads(body)
        for k in ("message", "detail", "error", "Error"):
            v = d.get(k) if isinstance(d, dict) else None
            if isinstance(v, str) and v:
                return v[:200]
            if isinstance(v, list) and v:
                return str(v[0])[:200]
        if isinstance(d, dict):
            # DRF returns {"field": ["msg"]} for validation failures.
            for k, v in d.items():
                if isinstance(v, list) and v:
                    return f"{k}: {str(v[0])[:160]}"
        return json.dumps(d)[:200]
    except Exception:
        return body[:200]


# ---------------------------------------------------------------- config
def _defaults():
    return {
        "email_domain": DEFAULT_EMAIL_DOMAIN,
        # What an unticked box does to the account that is already out there.
        # "disable" is reversible; "delete" is not, and Jellyfin watch state and
        # Immich libraries both live behind these accounts.
        "on_untick": "disable",
        # Services a brand new dashboard user is ticked for by default.
        "default_targets": ["jellyfin", "jellyseerr"],
        "services": {},
    }


def load_conf():
    conf = _defaults()
    try:
        with open(CONF_FILE) as f:
            disk = json.load(f)
        if isinstance(disk, dict):
            svc = disk.pop("services", None)
            conf.update(disk)
            if isinstance(svc, dict):
                conf["services"] = svc
    except FileNotFoundError:
        pass
    except Exception:
        pass
    for key in ADAPTERS:
        conf["services"].setdefault(key, {})
    return conf


def save_conf(conf):
    with _conf_lock:
        os.makedirs(os.path.dirname(CONF_FILE), mode=0o700, exist_ok=True)
        tmp = CONF_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(conf, f, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONF_FILE)


def email_for(name, user, conf):
    return (user.get("email") or "").strip() or \
        f"{name}@{conf.get('email_domain') or DEFAULT_EMAIL_DOMAIN}"


# ---------------------------------------------------------------- adapters
class Adapter:
    """One service. Subclasses implement the five verbs against its admin API.

    `ready()` returns (ok, reason). A service that needs a credential we do not
    have yet is not an error - it shows in the UI as needing configuration, and
    every other service still syncs.
    """
    KEY = ""
    LABEL = ""
    URL = ""
    # Which config fields the admin has to supply before this can be used.
    NEEDS = ()
    NEEDS_HELP = ""
    CAN_PASSWORD = True
    CAN_DISABLE = True
    CAN_DELETE = True
    NOTE = ""

    def __init__(self, cfg, conf):
        self.cfg = cfg or {}
        self.conf = conf

    # Where a service lives is a fact about this host, so it is detected
    # rather than declared - every adapter's LABEL is the name detection
    # reports for it. An explicit url in the adapter's config still wins, for
    # the case where a service answers somewhere the host cannot see.
    URL = ""

    @property
    def base(self):
        return (self.cfg.get("url") or site.base_url(self.LABEL)
                or self.URL).rstrip("/")

    def ready(self):
        missing = [f for f in self.NEEDS if not (self.cfg.get(f) or "").strip()]
        if missing:
            return False, "needs " + ", ".join(missing)
        return True, ""

    # -- verbs ------------------------------------------------------------
    def list_users(self):
        raise NotImplementedError

    def create(self, name, password, email, admin):
        raise NotImplementedError

    def set_password(self, uid, password):
        raise NotImplementedError

    def set_enabled(self, uid, enabled):
        raise NotImplementedError

    def delete(self, uid):
        raise NotImplementedError

    # -- shared -----------------------------------------------------------
    def find(self, name, email=None):
        """Match an existing remote account to a dashboard user, by name then
        email. This is what lets the stack's current accounts be adopted rather
        than duplicated on first sync."""
        want = name.lower()
        users = self.list_users()
        for u in users:
            if (u.get("name") or "").lower() == want:
                return u
        if email:
            for u in users:
                if (u.get("email") or "").lower() == email.lower():
                    return u
        return None


class Jellyfin(Adapter):
    KEY, LABEL = "jellyfin", "Jellyfin"
    NEEDS = ("api_key",)
    NEEDS_HELP = ("Jellyfin > Dashboard > API Keys. Picked up automatically from "
                  f"{JELLYFIN_KEY_FILE} when that exists.")
    NOTE = "Films, series and live TV. Jellyseerr rides on these accounts."

    def _key(self):
        k = (self.cfg.get("api_key") or "").strip()
        if k:
            return k
        try:
            with open(JELLYFIN_KEY_FILE) as f:
                return f.read().strip()
        except Exception:
            return ""

    def ready(self):
        if not self._key():
            return False, f"needs an API key ({JELLYFIN_KEY_FILE} is missing)"
        return True, ""

    def _h(self):
        return {"X-Emby-Token": self._key()}

    def _get(self, path):
        return http("GET", self.base + path, headers=self._h())

    def list_users(self):
        out = []
        for u in self._get("/Users") or []:
            pol = u.get("Policy") or {}
            out.append({"id": u["Id"], "name": u.get("Name"),
                        "email": None,
                        "enabled": not pol.get("IsDisabled"),
                        "admin": bool(pol.get("IsAdministrator"))})
        return out

    def create(self, name, password, email, admin):
        u = http("POST", self.base + "/Users/New", headers=self._h(),
                 json_body={"Name": name, "Password": password})
        uid = (u or {}).get("Id")
        if not uid:
            raise ApiError("Jellyfin did not return a user id")
        if admin:
            self.set_admin(uid, True)
        return uid

    def set_password(self, uid, password):
        # As an API key holder we are acting for the server, so CurrentPw is not
        # required - but the field has to be present or older builds 400.
        http("POST", f"{self.base}/Users/{uid}/Password", headers=self._h(),
             json_body={"CurrentPw": "", "NewPw": password, "ResetPassword": False})

    def set_admin(self, uid, admin):
        pol = self._get(f"/Users/{uid}") or {}
        policy = pol.get("Policy") or {}
        policy["IsAdministrator"] = bool(admin)
        http("POST", f"{self.base}/Users/{uid}/Policy", headers=self._h(),
             json_body=policy)

    def set_enabled(self, uid, enabled):
        pol = self._get(f"/Users/{uid}") or {}
        policy = pol.get("Policy") or {}
        policy["IsDisabled"] = not enabled
        http("POST", f"{self.base}/Users/{uid}/Policy", headers=self._h(),
             json_body=policy)

    def delete(self, uid):
        http("DELETE", f"{self.base}/Users/{uid}", headers=self._h())


class Jellyseerr(Adapter):
    KEY, LABEL = "jellyseerr", "Jellyseerr"
    NEEDS = ("api_key",)
    NEEDS_HELP = ("Jellyseerr > Settings > General > API Key. Read automatically "
                  "from the container when this process is allowed to run "
                  "`pct exec` - the web service's sandbox is not.")
    CAN_PASSWORD = False
    CAN_DISABLE = False
    NOTE = ("Imports the Jellyfin account - people sign in with their Jellyfin "
            "password, so there is no separate one to push.")

    def _key(self):
        k = (self.cfg.get("api_key") or "").strip()
        if k:
            return k
        # Convenience path for anything running outside the web service's
        # sandbox (the setup script, the shell): Jellyseerr keeps its API key in
        # the container's settings.json, so the admin need not copy it by hand.
        # Under the unit's ProtectSystem=strict this fails on /run/lxc and the
        # configured key above is used instead.
        try:
            svc = site.find("Jellyseerr") or {}
            if not svc.get("container"):
                return ""
            out = subprocess.run(
                ["pct", "exec", str(svc["cid"]), "--", "docker", "exec",
                 svc["container"], "cat", "/app/config/settings.json"],
                capture_output=True, text=True, timeout=15)
            if out.returncode == 0:
                return (json.loads(out.stdout).get("main") or {}).get("apiKey", "")
        except Exception:
            pass
        return ""

    def ready(self):
        if not self._key():
            return False, "needs an API key"
        return True, ""

    def _h(self):
        return {"X-Api-Key": self._key()}

    def list_users(self):
        d = http("GET", self.base + "/api/v1/user?take=200", headers=self._h())
        out = []
        for u in (d or {}).get("results", []):
            out.append({"id": str(u.get("id")),
                        "name": u.get("jellyfinUsername") or u.get("username")
                        or u.get("displayName"),
                        "email": u.get("email"),
                        "enabled": True, "admin": u.get("permissions") == 2})
        return out

    def create(self, name, password, email, admin, jellyfin_id=None):
        """Import from Jellyfin rather than creating a local account, so the
        password stays Jellyfin's. Needs the Jellyfin user to exist first, which
        is why the sync order puts Jellyfin ahead of this."""
        if not jellyfin_id:
            raise ApiError("needs the Jellyfin account first - tick Jellyfin too")
        http("POST", self.base + "/api/v1/user/import-from-jellyfin",
             headers=self._h(), json_body={"jellyfinUserIds": [jellyfin_id]})
        found = self.find(name)
        if not found:
            raise ApiError("import reported success but the user did not appear")
        return found["id"]

    def delete(self, uid):
        http("DELETE", f"{self.base}/api/v1/user/{uid}", headers=self._h())


class Grafana(Adapter):
    KEY, LABEL = "grafana", "Grafana"
    NEEDS = ("admin_user", "admin_password")
    NEEDS_HELP = "Grafana admin login (see the Credentials page)."
    NOTE = "Metrics dashboards for the host and containers."

    def _basic(self):
        return (self.cfg.get("admin_user", ""), self.cfg.get("admin_password", ""))

    def list_users(self):
        d = http("GET", self.base + "/api/users?perpage=500", basic=self._basic())
        out = []
        for u in d or []:
            out.append({"id": str(u.get("id")), "name": u.get("login"),
                        "email": u.get("email"),
                        "enabled": not u.get("isDisabled"),
                        "admin": bool(u.get("isAdmin"))})
        return out

    def create(self, name, password, email, admin):
        d = http("POST", self.base + "/api/admin/users", basic=self._basic(),
                 json_body={"name": name, "email": email, "login": name,
                            "password": password})
        uid = str((d or {}).get("id") or "")
        if not uid:
            raise ApiError("Grafana did not return a user id")
        self._role(uid, admin)
        return uid

    def _role(self, uid, admin):
        # Org role controls what they can do; the server-admin flag is separate
        # and deliberately left alone - it grants the Grafana admin API itself.
        try:
            http("PATCH", f"{self.base}/api/org/users/{uid}", basic=self._basic(),
                 json_body={"role": "Admin" if admin else "Viewer"})
        except ApiError:
            pass

    def set_password(self, uid, password):
        http("PUT", f"{self.base}/api/admin/users/{uid}/password",
             basic=self._basic(), json_body={"password": password})

    def set_enabled(self, uid, enabled):
        verb = "enable" if enabled else "disable"
        http("POST", f"{self.base}/api/admin/users/{uid}/{verb}", basic=self._basic(),
             json_body={})

    def delete(self, uid):
        http("DELETE", f"{self.base}/api/admin/users/{uid}", basic=self._basic())


class Dispatcharr(Adapter):
    KEY, LABEL = "dispatcharr", "Dispatcharr"
    NEEDS = ("admin_user", "admin_password")
    NEEDS_HELP = "Dispatcharr superuser login (see the Credentials page)."
    NOTE = "IPTV channel manager."

    # Dispatcharr rate-limits its token endpoint hard - a sync that minted a
    # fresh JWT per call ran into HTTP 429 after a handful of users. One token
    # is cached per process and reused until it is nearly expired.
    _tok_cache = {"header": None, "until": 0}
    _tok_lock = threading.Lock()

    def _token(self, force=False):
        with Dispatcharr._tok_lock:
            c = Dispatcharr._tok_cache
            if not force and c["header"] and time.time() < c["until"]:
                return c["header"]
            d = http("POST", self.base + "/api/accounts/token/",
                     json_body={"username": self.cfg.get("admin_user", ""),
                                "password": self.cfg.get("admin_password", "")})
            tok = (d or {}).get("access")
            if not tok:
                raise ApiError("no access token returned - check the superuser login")
            c["header"] = {"Authorization": "Bearer " + tok}
            # Access tokens are short-lived; 4 minutes is well inside the
            # default and still saves every call within one sync run.
            c["until"] = time.time() + 240
            return c["header"]

    def _call(self, method, path, **kw):
        """Retry once on 401 in case the cached token expired mid-run."""
        try:
            return http(method, self.base + path, headers=self._token(), **kw)
        except ApiError as e:
            if e.status != 401:
                raise
            return http(method, self.base + path, headers=self._token(True), **kw)

    def list_users(self):
        d = self._call("GET", "/api/accounts/users/")
        rows = d if isinstance(d, list) else (d or {}).get("results", [])
        out = []
        for u in rows:
            out.append({"id": str(u.get("id")), "name": u.get("username"),
                        "email": u.get("email"),
                        "enabled": u.get("is_active", True),
                        "admin": bool(u.get("is_superuser"))})
        return out

    def create(self, name, password, email, admin):
        d = self._call("POST", "/api/accounts/users/",
                       json_body={"username": name, "password": password,
                                  "email": email, "user_level": 10 if admin else 0})
        uid = str((d or {}).get("id") or "")
        if not uid:
            raise ApiError("Dispatcharr did not return a user id")
        return uid

    def set_password(self, uid, password):
        self._call("PATCH", f"/api/accounts/users/{uid}/",
                   json_body={"password": password})

    def set_enabled(self, uid, enabled):
        self._call("PATCH", f"/api/accounts/users/{uid}/",
                   json_body={"is_active": bool(enabled)})

    def delete(self, uid):
        self._call("DELETE", f"/api/accounts/users/{uid}/")


class Immich(Adapter):
    KEY, LABEL = "immich", "Immich"
    NEEDS = ("api_key",)
    NEEDS_HELP = ("An admin API key from Immich: Account settings > API Keys > "
                  "New API Key.")
    CAN_DISABLE = False
    NOTE = "Photo library. Each account gets its own private library."

    def _h(self):
        return {"x-api-key": self.cfg.get("api_key", "")}

    def list_users(self):
        d = http("GET", self.base + "/api/admin/users", headers=self._h())
        out = []
        for u in d or []:
            out.append({"id": u.get("id"), "name": u.get("name"),
                        "email": u.get("email"),
                        "enabled": not u.get("deletedAt"),
                        "admin": bool(u.get("isAdmin"))})
        return out

    def find(self, name, email=None):
        # Immich logins are email addresses, so match on that first - the
        # display name is free text and routinely duplicated.
        users = self.list_users()
        if email:
            for u in users:
                if (u.get("email") or "").lower() == email.lower():
                    return u
        for u in users:
            if (u.get("name") or "").lower() == name.lower():
                return u
        return None

    def create(self, name, password, email, admin):
        d = http("POST", self.base + "/api/admin/users", headers=self._h(),
                 json_body={"email": email, "password": password, "name": name,
                            "shouldChangePassword": False, "notify": False})
        uid = (d or {}).get("id")
        if not uid:
            raise ApiError("Immich did not return a user id")
        return uid

    def set_password(self, uid, password):
        http("PUT", f"{self.base}/api/admin/users/{uid}", headers=self._h(),
             json_body={"password": password, "shouldChangePassword": False})

    def delete(self, uid):
        # Immich soft-deletes; the account and its library come back if restored
        # inside the configured window.
        http("DELETE", f"{self.base}/api/admin/users/{uid}", headers=self._h(),
             json_body={"force": False})


class Romm(Adapter):
    KEY, LABEL = "romm", "RomM"
    NEEDS = ("admin_user", "admin_password")
    NEEDS_HELP = ("A RomM admin login. If RomM still shows its setup wizard, "
                  "finish that first - the first account cannot be made over "
                  "the API.")
    NOTE = "Retro game library."

    def _basic(self):
        return (self.cfg.get("admin_user", ""), self.cfg.get("admin_password", ""))

    def list_users(self):
        d = http("GET", self.base + "/api/users", basic=self._basic())
        out = []
        for u in d or []:
            out.append({"id": str(u.get("id")), "name": u.get("username"),
                        "email": u.get("email"),
                        "enabled": u.get("enabled", True),
                        "admin": (u.get("role") == "admin")})
        return out

    def create(self, name, password, email, admin):
        d = http("POST", self.base + "/api/users", basic=self._basic(),
                 json_body={"username": name, "email": email, "password": password,
                            "role": "admin" if admin else "user"})
        uid = str((d or {}).get("id") or "")
        if not uid:
            raise ApiError("RomM did not return a user id")
        return uid

    def set_password(self, uid, password):
        http("PUT", f"{self.base}/api/users/{uid}", basic=self._basic(),
             form={"password": password})

    def set_enabled(self, uid, enabled):
        http("PUT", f"{self.base}/api/users/{uid}", basic=self._basic(),
             form={"enabled": "true" if enabled else "false"})

    def delete(self, uid):
        http("DELETE", f"{self.base}/api/users/{uid}", basic=self._basic())


class Gameyfin(Adapter):
    """Gameyfin has no REST API and no API keys - the UI talks to Vaadin Hilla
    endpoints at /connect/<Endpoint>/<method> behind a Spring Security form
    login. So this adapter logs in as an admin, keeps the session cookie, and
    calls the same endpoints the UI does.

    Creating a user is two steps because Gameyfin has no direct create: an admin
    mints an invitation, then the invitation token is redeemed with the username
    and password we want. That is the flow its own sign-up uses.
    """
    KEY, LABEL = "gameyfin", "Gameyfin"
    NEEDS = ("admin_user", "admin_password")
    NEEDS_HELP = ("A Gameyfin admin login. Untested against a live server - "
                  "no admin credentials for it were recorded on this host.")
    NOTE = "Game library. Experimental: driven through Gameyfin's internal API."

    def _session(self):
        """Form-login, returning the cookie header for subsequent calls."""
        import http.cookiejar
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPRedirectHandler())
        page = opener.open(self.base + "/login", timeout=TIMEOUT).read().decode(
            "utf-8", "replace")
        csrf = ""
        m = page.find('name="_csrf"')
        if m != -1:
            v = page.find('value="', m)
            if v != -1:
                csrf = page[v + 7:page.find('"', v + 7)]
        body = urllib.parse.urlencode({
            "username": self.cfg.get("admin_user", ""),
            "password": self.cfg.get("admin_password", ""),
            "_csrf": csrf}).encode()
        r = opener.open(urllib.request.Request(
            self.base + "/login", data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"}),
            timeout=TIMEOUT)
        if "/login?error" in r.geturl():
            raise ApiError("login rejected - check the Gameyfin admin password")
        return opener, csrf

    def _call(self, opener, csrf, endpoint, method, params):
        req = urllib.request.Request(
            f"{self.base}/connect/{endpoint}/{method}",
            data=json.dumps(params).encode(),
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
            method="POST")
        try:
            with opener.open(req, timeout=TIMEOUT) as r:
                raw = r.read(1024 * 1024)
        except urllib.error.HTTPError as e:
            raise ApiError(f"HTTP {e.code}: {_snippet(e.read(1024).decode('utf-8', 'replace'))}",
                           e.code)
        except Exception as e:
            raise ApiError(str(e)[:200])
        return json.loads(raw) if raw else None

    def list_users(self):
        opener, csrf = self._session()
        rows = self._call(opener, csrf, "UserEndpoint", "getAllUsers", {}) or []
        out = []
        for u in rows:
            out.append({"id": u.get("username") or str(u.get("id")),
                        "name": u.get("username"), "email": u.get("email"),
                        "enabled": u.get("enabled", True),
                        "admin": "ADMIN" in json.dumps(u.get("roles") or [])})
        return out

    def create(self, name, password, email, admin):
        opener, csrf = self._session()
        inv = self._call(opener, csrf, "RegistrationEndpoint", "createInvitation",
                         {"email": email})
        token = inv if isinstance(inv, str) else (inv or {}).get("token")
        if not token:
            raise ApiError("Gameyfin did not return an invitation token")
        self._call(opener, csrf, "RegistrationEndpoint", "registerUser",
                   {"token": token, "username": name, "password": password,
                    "email": email})
        return name

    def set_password(self, uid, password):
        opener, csrf = self._session()
        self._call(opener, csrf, "UserEndpoint", "updateUserByName",
                   {"username": uid, "updates": {"password": password}})

    def set_enabled(self, uid, enabled):
        opener, csrf = self._session()
        self._call(opener, csrf, "UserEndpoint", "setUserEnabled",
                   {"username": uid, "enabled": bool(enabled)})

    def delete(self, uid):
        opener, csrf = self._session()
        self._call(opener, csrf, "UserEndpoint", "deleteUserByName",
                   {"username": uid})


# Sync order matters in one place: Jellyseerr imports the Jellyfin account, so
# Jellyfin has to be provisioned first. Dict order is the sync order.
ADAPTERS = {a.KEY: a for a in
            (Jellyfin, Jellyseerr, Immich, Grafana, Romm, Dispatcharr, Gameyfin)}

# Applications with exactly one login for everybody. Listed so the UI can say
# why they are absent instead of leaving a gap the admin has to wonder about.
SINGLE_ACCOUNT = [
    ("Radarr", "one shared login for the whole application"),
    ("Sonarr", "one shared login for the whole application"),
    ("Prowlarr", "one shared login for the whole application"),
    ("qBittorrent", "single WebUI account, set in its own config"),
    ("Threadfin", "single auth toggle, no user list"),
]


def adapter(key, conf=None):
    conf = conf or load_conf()
    cls = ADAPTERS.get(key)
    if not cls:
        return None
    return cls(conf["services"].get(key) or {}, conf)


# ---------------------------------------------------------------- account store
# auth.json is the dashboard's own user file. It is read and written through the
# main module so there is exactly one implementation of the scrypt format, with
# a local fallback purely so this file can be exercised from the command line.
_auth_lock = threading.Lock()
AUTH_FILE = "/etc/media-dashboard/auth.json"


def load_auth():
    fn = _main_attr("load_auth")
    if fn:
        return fn()
    with open(AUTH_FILE) as f:
        return json.load(f)


def save_auth(a):
    fn = _main_attr("save_auth")
    if fn:
        return fn(a)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(a, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)


def bump_pwv(user):
    """Record that this account's password changed. Every service link that
    still shows the old number is then known to be holding a stale password."""
    user["pwv"] = int(user.get("pwv") or 0) + 1
    return user["pwv"]


def links_of(user):
    s = user.get("services")
    return s if isinstance(s, dict) else {}


# A link that was adopted rather than created carries this instead of a version
# number: the account is ours to manage, but its password was set by somebody
# else and there is no way to tell whether it matches the dashboard's.
PWV_UNKNOWN = -1


def status_of(user, key, link, ready):
    """One cell of the matrix: what this user's state is on this service."""
    want = bool(link.get("want"))
    uid = link.get("id")
    if link.get("err"):
        return "error"
    if not ready:
        return "unavailable" if want else "off"
    if want and not uid:
        return "missing"
    if want and uid:
        if link.get("off"):
            return "disabled"
        if not ADAPTERS[key].CAN_PASSWORD:
            return "ready"
        lpwv = int(link.get("pwv", PWV_UNKNOWN))
        if lpwv == PWV_UNKNOWN:
            return "adopted"
        if lpwv < int(user.get("pwv") or 0):
            return "stale"
        return "ready"
    if uid:
        return "orphan"
    return "off"


def state(conf=None):
    """Everything the page needs: services, users, and the status of each cell."""
    conf = conf or load_conf()
    auth = load_auth()
    services = []
    ready_map = {}
    for key, cls in ADAPTERS.items():
        a = cls(conf["services"].get(key) or {}, conf)
        ok, why = a.ready()
        ready_map[key] = ok
        services.append({
            "key": key, "label": cls.LABEL, "url": a.base, "note": cls.NOTE,
            "ready": ok, "why": why, "needs": list(cls.NEEDS),
            "needs_help": cls.NEEDS_HELP,
            "can_password": cls.CAN_PASSWORD, "can_disable": cls.CAN_DISABLE,
            "configured": {f: bool((conf["services"].get(key) or {}).get(f))
                           for f in cls.NEEDS},
        })

    users = []
    for name in sorted(auth.get("users") or {}):
        u = auth["users"][name]
        links = links_of(u)
        cells = {}
        for key in ADAPTERS:
            link = links.get(key) or {}
            cells[key] = {"want": bool(link.get("want")), "id": link.get("id"),
                          "status": status_of(u, key, link, ready_map[key]),
                          "err": link.get("err"), "at": link.get("at")}
        users.append({"name": name, "role": u.get("role", "user"),
                      "email": u.get("email") or "",
                      "email_effective": email_for(name, u, conf),
                      "pwv": int(u.get("pwv") or 0), "cells": cells})

    return {"services": services, "users": users,
            "single_account": [{"label": l, "why": w} for l, w in SINGLE_ACCOUNT],
            "on_untick": conf.get("on_untick", "disable"),
            "email_domain": conf.get("email_domain", DEFAULT_EMAIL_DOMAIN),
            "default_targets": conf.get("default_targets", [])}


def set_targets(name, targets, actor="?"):
    """Store which services this user should exist in. Ticking a box does not
    touch the service - it only says what the next sync should make true."""
    with _auth_lock:
        auth = load_auth()
        u = (auth.get("users") or {}).get(name)
        if not u:
            return False, "no such user"
        links = u.setdefault("services", {})
        for key in ADAPTERS:
            link = links.setdefault(key, {})
            link["want"] = bool(targets.get(key))
        save_auth(auth)
    _audit(actor, "USERSYNC targets " + name + " -> " +
           ",".join(k for k in ADAPTERS if targets.get(k)) or "(none)")
    return True, ""


def set_email(name, email, actor="?"):
    with _auth_lock:
        auth = load_auth()
        u = (auth.get("users") or {}).get(name)
        if not u:
            return False, "no such user"
        email = (email or "").strip()
        if email and ("@" not in email or " " in email or len(email) > 190):
            return False, "that does not look like an email address"
        if email:
            u["email"] = email
        else:
            u.pop("email", None)
        save_auth(auth)
    _audit(actor, f"USERSYNC email {name} -> {email or '(default)'}")
    return True, ""


def _record(name, key, **fields):
    """Persist the outcome of one service action against one user."""
    with _auth_lock:
        auth = load_auth()
        u = (auth.get("users") or {}).get(name)
        if not u:
            return
        link = u.setdefault("services", {}).setdefault(key, {})
        link.update(fields)
        link["at"] = int(time.time())
        save_auth(auth)


def plan(name, password_available, conf=None, cache=None):
    """What a sync would do, without doing it. Drives the confirm dialog.

    `cache` holds one user listing per service so that planning a sync for
    everyone does not re-list every service once per person. Pass a dict in and
    reuse it across calls.
    """
    conf = conf or load_conf()
    cache = {} if cache is None else cache
    auth = load_auth()
    u = (auth.get("users") or {}).get(name)
    if not u:
        return []
    links = links_of(u)
    pwv = int(u.get("pwv") or 0)
    email = email_for(name, u, conf)
    on_untick = conf.get("on_untick", "disable")
    out = []

    def existing(key, a):
        """Is there already an account there we would adopt rather than create?
        Worth the lookup: adoption needs no password, and saying otherwise sends
        the admin hunting for one they do not need."""
        if key not in cache:
            try:
                cache[key] = a.list_users()
            except ApiError:
                cache[key] = None
        rows = cache[key]
        if rows is None:
            return None
        want = name.lower()
        for r in rows:
            if (r.get("name") or "").lower() == want:
                return r
            if email and (r.get("email") or "").lower() == email.lower():
                return r
        return None

    for key, cls in ADAPTERS.items():
        a = cls(conf["services"].get(key) or {}, conf)
        ok, why = a.ready()
        link = links.get(key) or {}
        want, uid = bool(link.get("want")), link.get("id")
        if want and not ok:
            out.append({"service": key, "label": cls.LABEL, "action": "skip",
                        "detail": why})
            continue
        if want and not uid:
            found = existing(key, a)
            if found:
                out.append({"service": key, "label": cls.LABEL, "action": "adopt",
                            "detail": f"link to the existing account "
                                      f"'{found.get('name') or found.get('email')}'"})
            elif password_available or not cls.CAN_PASSWORD:
                out.append({"service": key, "label": cls.LABEL, "action": "create",
                            "detail": "create the account"})
            else:
                out.append({"service": key, "label": cls.LABEL, "action": "needpw",
                            "detail": "needs the password to create the account"})
        elif want and uid:
            row = existing(key, a) if link.get("off") else None
            if link.get("off") or (row is not None and row.get("enabled") is False):
                out.append({"service": key, "label": cls.LABEL, "action": "enable",
                            "detail": "re-enable the account there"})
            if not cls.CAN_PASSWORD:
                continue
            lpwv = int(link.get("pwv", PWV_UNKNOWN))
            if lpwv >= pwv:
                continue
            what = ("this account was adopted - its password was set elsewhere"
                    if lpwv == PWV_UNKNOWN else "password here is out of date")
            if password_available:
                out.append({"service": key, "label": cls.LABEL, "action": "password",
                            "detail": "push the current password"})
            else:
                out.append({"service": key, "label": cls.LABEL, "action": "needpw",
                            "detail": what})
        elif not want and uid and ok:
            verb = "delete" if on_untick == "delete" else "disable"
            if verb == "disable" and not cls.CAN_DISABLE:
                verb = "delete"
            out.append({"service": key, "label": cls.LABEL, "action": verb,
                        "detail": f"{verb} the account there"})
    return out


def sync_user(name, password=None, actor="?", conf=None, only=None, cache=None):
    """Make each ticked service match this dashboard account.

    `password` is the plaintext, available only when the admin has just typed
    it. Without it, accounts that already exist are still adopted, linked and
    enabled - only creating an account and changing a password need it.

    `cache` holds one user listing per service. Syncing everyone reuses it, so
    the cost is one listing per service rather than one per person. It is
    dropped for a service as soon as this run changes anything there.
    """
    conf = conf or load_conf()
    cache = {} if cache is None else cache
    auth = load_auth()
    u = (auth.get("users") or {}).get(name)
    if not u:
        # Every result carries an action - the page formats on it unconditionally.
        return [{"service": "-", "label": "-", "ok": False, "action": "error",
                 "detail": "no such user"}]

    email = email_for(name, u, conf)
    is_admin = u.get("role") == "admin"
    pwv = int(u.get("pwv") or 0)
    on_untick = conf.get("on_untick", "disable")
    results = []
    jellyfin_id = None

    def rows_for(key, a):
        """Current accounts on one service, listed at most once per run."""
        if key not in cache:
            try:
                cache[key] = a.list_users()
            except ApiError:
                cache[key] = None
        return cache[key]

    for key, cls in ADAPTERS.items():
        if only and key not in only:
            continue
        link = links_of(u).get(key) or {}
        want, uid = bool(link.get("want")), link.get("id")
        if not want and not uid:
            continue

        a = cls(conf["services"].get(key) or {}, conf)
        ok, why = a.ready()
        if not ok:
            if want:
                results.append({"service": key, "label": cls.LABEL, "ok": False,
                                "action": "skip", "detail": why})
            continue

        try:
            if want:
                rows = rows_for(key, a)
                if uid and rows is not None and not any(
                        str(r.get("id")) == str(uid) for r in rows):
                    # Removed at the service since we linked it. Drop the stale
                    # link so the code below can adopt or recreate.
                    uid = None
                    _record(name, key, id=None, pwv=PWV_UNKNOWN)
                    results.append({"service": key, "label": cls.LABEL, "ok": True,
                                    "action": "relink",
                                    "detail": "the account was gone there - "
                                              "recreating it"})
                if not uid:
                    # Adopt an account that is already there before making a
                    # second one - this is how the existing admin logins get
                    # picked up instead of duplicated.
                    found = a.find(name, email)
                    if found:
                        uid = found["id"]
                        # Adopted, not created: somebody else set that password,
                        # so it is recorded as unknown until one is pushed.
                        _record(name, key, id=uid, err=None,
                                pwv=PWV_UNKNOWN if cls.CAN_PASSWORD else pwv)
                        results.append({"service": key, "label": cls.LABEL,
                                        "ok": True, "action": "adopt",
                                        "detail": f"linked to existing account "
                                                  f"'{found.get('name')}'"})
                    elif cls.CAN_PASSWORD and not password:
                        results.append({"service": key, "label": cls.LABEL,
                                        "ok": False, "action": "needpw",
                                        "detail": "needs the password to create "
                                                  "this account"})
                        continue
                    else:
                        if key == "jellyseerr":
                            uid = a.create(name, password, email, is_admin,
                                           jellyfin_id=jellyfin_id)
                        else:
                            uid = a.create(name, password, email, is_admin)
                        cache.pop(key, None)         # listing is now out of date
                        _record(name, key, id=uid, err=None, off=False,
                                pwv=pwv if cls.CAN_PASSWORD else pwv)
                        results.append({"service": key, "label": cls.LABEL,
                                        "ok": True, "action": "create",
                                        "detail": "account created"})
                if key == "jellyfin":
                    jellyfin_id = uid

                # Push the password if this service is behind and we have one.
                fresh = (load_auth()["users"][name].get("services", {})
                         .get(key) or {})
                if (cls.CAN_PASSWORD and password
                        and int(fresh.get("pwv", PWV_UNKNOWN)) < pwv):
                    a.set_password(uid, password)
                    _record(name, key, pwv=pwv, err=None)
                    results.append({"service": key, "label": cls.LABEL, "ok": True,
                                    "action": "password", "detail": "password set"})
                # Re-enable only when the account is actually disabled - either
                # because a previous untick disabled it, or because somebody
                # disabled it at the service. Checking first keeps a no-op sync
                # from writing to every service on every run.
                if cls.CAN_DISABLE:
                    row = next((r for r in (rows_for(key, a) or [])
                                if str(r.get("id")) == str(uid)), None)
                    disabled = (row is not None and row.get("enabled") is False)
                    if disabled or (row is None and link.get("off")):
                        a.set_enabled(uid, True)
                        cache.pop(key, None)
                        _record(name, key, off=False, err=None)
                        results.append({"service": key, "label": cls.LABEL,
                                        "ok": True, "action": "enable",
                                        "detail": "account re-enabled"})
            else:
                verb = on_untick
                if verb == "disable" and not cls.CAN_DISABLE:
                    verb = "delete"
                if verb == "delete":
                    a.delete(uid)
                    cache.pop(key, None)
                    _record(name, key, id=None, pwv=PWV_UNKNOWN, off=False, err=None)
                    results.append({"service": key, "label": cls.LABEL, "ok": True,
                                    "action": "delete", "detail": "account deleted"})
                else:
                    a.set_enabled(uid, False)
                    cache.pop(key, None)
                    _record(name, key, off=True, err=None)
                    results.append({"service": key, "label": cls.LABEL, "ok": True,
                                    "action": "disable",
                                    "detail": "account disabled (still there, "
                                              "untick-safe)"})
        except ApiError as e:
            _record(name, key, err=str(e)[:300])
            results.append({"service": key, "label": cls.LABEL, "ok": False,
                            "action": "error", "detail": str(e)[:300]})
        except Exception as e:                                # adapter bug, not API
            _record(name, key, err=f"{type(e).__name__}: {e}"[:300])
            results.append({"service": key, "label": cls.LABEL, "ok": False,
                            "action": "error",
                            "detail": f"{type(e).__name__}: {e}"[:300]})

    done = sum(1 for r in results if r["ok"])
    _audit(actor, f"USERSYNC sync {name}: {done}/{len(results)} ok " +
           ";".join(f"{r['service']}={r['action']}" for r in results))
    return results


def on_account_created(name, password, actor="?"):
    """Called when /users adds an account: tick the default services and push."""
    conf = load_conf()
    with _auth_lock:
        auth = load_auth()
        u = (auth.get("users") or {}).get(name)
        if not u:
            return []
        u["pwv"] = int(u.get("pwv") or 0) or 1
        links = u.setdefault("services", {})
        for key in ADAPTERS:
            links.setdefault(key, {})["want"] = key in (conf.get("default_targets") or [])
        save_auth(auth)
    return sync_user(name, password, actor, conf)


def on_password_changed(name, password, actor="?"):
    """Called when /users changes a password: bump the counter and push it."""
    with _auth_lock:
        auth = load_auth()
        u = (auth.get("users") or {}).get(name)
        if not u:
            return []
        bump_pwv(u)
        save_auth(auth)
    return sync_user(name, password, actor)


def on_account_deleted(name, actor="?"):
    """Called when /users deletes an account. The remote accounts are left
    alone deliberately - they may hold watch history or a photo library, and
    this is the one action that cannot be undone from here. The links are
    reported so the admin can clean up on purpose."""
    left = []
    auth = load_auth()
    u = (auth.get("users") or {}).get(name) or {}
    for key, link in links_of(u).items():
        if link.get("id"):
            left.append(ADAPTERS[key].LABEL if key in ADAPTERS else key)
    if left:
        _audit(actor, f"USERSYNC {name} deleted here; still present in "
                      f"{', '.join(left)}")
    return left


# ---------------------------------------------------------------- page
CSS = """
.us-grid{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r);
background:var(--card);box-shadow:var(--shadow)}
.us-grid table{border-collapse:collapse;width:100%;font-size:13px}
.us-grid th,.us-grid td{padding:9px 11px;border-bottom:1px solid var(--line);
text-align:left;white-space:nowrap}
.us-grid tr:last-child td{border-bottom:none}
.us-grid th{font-weight:600;font-size:12px;color:var(--muted);
background:color-mix(in srgb,var(--card) 60%,var(--bg))}
.us-grid th.svc{text-align:center;min-width:104px}
.us-grid td.cell{text-align:center}
.us-user{font-weight:600}
.us-mail{color:var(--muted);font-size:12px;font-weight:400}
.us-cell{display:inline-flex;flex-direction:column;align-items:center;gap:3px;
cursor:pointer}
.us-cell input{width:16px;height:16px;accent-color:var(--accent);cursor:pointer}
.us-cell.off input{cursor:not-allowed}
.us-tag{font-size:10.5px;letter-spacing:.02em;text-transform:uppercase;
color:var(--muted)}
.us-tag.ready{color:var(--ok)} .us-tag.stale{color:var(--warn)}
.us-tag.missing{color:var(--accent)} .us-tag.error{color:var(--bad)}
.us-tag.adopted{color:var(--warn)} .us-tag.disabled{color:var(--warn)}
.us-tag.orphan{color:var(--warn)} .us-tag.unavailable{color:var(--muted)}
.us-actions{display:flex;gap:6px;justify-content:flex-end}
.us-svc{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));
gap:var(--gap)}
.us-card{border:1px solid var(--line);border-radius:var(--r);background:var(--card);
padding:14px;box-shadow:var(--shadow)}
.us-card h3{margin:0 0 2px;font-size:14px;display:flex;align-items:center;gap:8px}
.us-card .note{color:var(--muted);font-size:12px;margin:0 0 10px}
.us-card label{display:block;font-size:12px;color:var(--muted);margin:8px 0 3px}
.us-card input{width:100%}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
.dot.on{background:var(--ok)} .dot.no{background:var(--muted)}
.us-log{font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
white-space:pre-wrap;background:var(--card);border:1px solid var(--line);
border-radius:var(--r);padding:12px;max-height:340px;overflow:auto}
.us-modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;
align-items:center;justify-content:center;z-index:80;padding:16px}
.us-modal.on{display:flex}
.us-box{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
padding:18px;max-width:560px;width:100%;box-shadow:var(--shadow)}
.us-box h3{margin:0 0 10px;font-size:16px}
.us-plan{font-size:13px;margin:0 0 12px;padding-left:18px}
.us-plan li{margin:3px 0}
@media (max-width:640px){.us-grid th,.us-grid td{padding:7px 8px}}
"""

PAGE = """<!doctype html><meta charset="utf-8"><title>User sync</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>__CSS__</style>
__NAV__
<h1>User sync</h1>
<div class="sub">Dashboard accounts are the source of truth. Tick the services
each person should have an account on, then sync to push their username and
password out. People sign in to each service separately, with the same
credentials they use here.</div>

<div class="sec">Who goes where</div>
<div class="us-grid"><table id="grid"><tbody><tr><td>loading…</td></tr></tbody></table></div>
<div class="us-actions" style="margin-top:10px">
  <button class="fb" id="syncall">Sync everyone</button>
</div>
<div id="out" style="margin-top:14px"></div>

<div class="sec">Services</div>
<div class="us-svc" id="svc"></div>

<div class="sec">Settings</div>
<div class="us-card" style="max-width:520px">
  <label>When a box is unticked</label>
  <select class="fi" id="untick">
    <option value="disable">disable the account there (reversible)</option>
    <option value="delete">delete the account there (permanent)</option>
  </select>
  <label>Email domain for accounts with no real address</label>
  <input class="fi" id="edomain">
  <div style="margin-top:12px"><button class="fb" id="savecfg">Save settings</button></div>
</div>

<div class="sec">Services that cannot take part</div>
<div class="us-grid"><table id="single"></table></div>

<div class="us-modal" id="modal"><div class="us-box">
  <h3 id="mtitle">Sync</h3>
  <ul class="us-plan" id="mplan"></ul>
  <div id="mpwwrap" style="display:none">
    <label style="font-size:12px;color:var(--muted)">Password
      <span id="mpwwhy"></span></label>
    <input class="fi" id="mpw" type="password" style="width:100%"
           autocomplete="new-password" placeholder="current dashboard password">
    <div class="sub" style="margin:6px 0 0">Nothing here can read the stored
      password - it is a scrypt hash. Type it once and it goes to the services
      selected above, then it is discarded.</div>
  </div>
  <div class="us-actions" style="margin-top:14px">
    <button class="fb" id="mcancel">Cancel</button>
    <button class="fb" id="mgo">Sync</button>
  </div>
</div></div>
<script>__JS__</script>
"""

JS = r"""
const $ = s => document.querySelector(s);
let ST = null, PEND = null;

const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} : {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)});
  const d = await r.json().catch(() => ({error: "bad response"}));
  if (!r.ok || d.error) throw new Error(d.error || ("HTTP " + r.status));
  return d;
}

const TAG = {ready: "synced", stale: "old pw", missing: "not yet", off: "",
             orphan: "remove", error: "failed", unavailable: "n/a",
             adopted: "set pw", disabled: "disabled"};

function render() {
  const svcs = ST.services;
  let h = "<thead><tr><th>User</th>";
  for (const s of svcs)
    h += `<th class="svc" title="${esc(s.url)}">${esc(s.label)}` +
         (s.ready ? "" : `<br><span class="us-tag unavailable">not set up</span>`) +
         "</th>";
  h += "<th></th></tr></thead><tbody>";
  for (const u of ST.users) {
    h += `<tr data-user="${esc(u.name)}"><td><div class="us-user">${esc(u.name)}` +
         (u.role === "admin" ? ' <span class="pill">admin</span>' : "") +
         `</div><div class="us-mail">${esc(u.email_effective)}</div></td>`;
    for (const s of svcs) {
      const c = u.cells[s.key];
      const cls = c.status;
      h += `<td class="cell"><label class="us-cell" title="${esc(c.err || s.note)}">` +
           `<input type="checkbox" data-svc="${s.key}"${c.want ? " checked" : ""}` +
           `${s.ready ? "" : " disabled"}>` +
           `<span class="us-tag ${cls}">${TAG[cls] || ""}</span></label></td>`;
    }
    h += `<td><div class="us-actions">` +
         `<button class="fb save">Save</button>` +
         `<button class="fb sync">Sync</button></div></td></tr>`;
  }
  $("#grid").innerHTML = h + "</tbody>";

  let sv = "";
  for (const s of svcs) {
    sv += `<div class="us-card"><h3><span class="dot ${s.ready ? "on" : "no"}"></span>` +
          `${esc(s.label)}</h3><p class="note">${esc(s.note)}</p>` +
          `<div class="sub" style="margin:0 0 6px">${esc(s.url)}</div>`;
    if (!s.ready) sv += `<div class="warnbox" style="font-size:12px">${esc(s.why)}` +
          (s.needs_help ? "<br>" + esc(s.needs_help) : "") + "</div>";
    if (s.needs.length) {
      sv += `<form data-svc="${s.key}">`;
      for (const f of s.needs)
        sv += `<label>${esc(f.replace(/_/g, " "))}</label>` +
              `<input class="fi" name="${f}" type="${f.includes("pass") || f.includes("key") ? "password" : "text"}" ` +
              `placeholder="${s.configured[f] ? "•••••• (saved)" : ""}" autocomplete="off">`;
      sv += `<div style="margin-top:10px"><button class="fb">Save</button></div></form>`;
    } else {
      sv += `<div class="sub" style="margin:0">No configuration needed.</div>`;
    }
    sv += "</div>";
  }
  $("#svc").innerHTML = sv;

  let sg = '<tr class="hd"><th>Service</th><th>Why not</th></tr>';
  for (const s of ST.single_account)
    sg += `<tr><td><b>${esc(s.label)}</b></td><td>${esc(s.why)}</td></tr>`;
  $("#single").innerHTML = sg;

  $("#untick").value = ST.on_untick;
  $("#edomain").value = ST.email_domain;
}

function targetsOf(row) {
  const t = {};
  row.querySelectorAll("input[data-svc]").forEach(i => t[i.dataset.svc] = i.checked);
  return t;
}

function show(results) {
  let txt = "";
  for (const r of results)
    txt += (r.ok ? "  ok   " : "  FAIL ") + (r.label || r.service).padEnd(13) +
           r.action.padEnd(10) + r.detail + "\n";
  $("#out").innerHTML = '<div class="sec">Last sync</div><div class="us-log">' +
    esc(txt || "nothing to do") + "</div>";
}

async function refresh() { ST = await api("/api/usersync/state"); render(); }

async function askAndSync(users) {
  const plans = await api("/api/usersync/plan", {users});
  PEND = {users, plan: plans};
  const needpw = plans.some(p => p.action === "needpw");
  $("#mtitle").textContent = users.length === 1 ? "Sync " + users[0] : "Sync everyone";
  $("#mplan").innerHTML = plans.length
    ? plans.map(p => `<li><b>${esc(p.user)}</b> → ${esc(p.label)}: ${esc(p.detail)}</li>`).join("")
    : "<li>Everything is already in sync.</li>";
  $("#mpwwrap").style.display = needpw ? "" : "none";
  $("#mpwwhy").textContent = needpw && users.length > 1
    ? "(only applies to the one user you name below - sync users one at a time to set passwords)"
    : "";
  $("#mpw").value = "";
  $("#modal").classList.add("on");
  if (needpw) $("#mpw").focus();
}

document.addEventListener("click", async e => {
  const row = e.target.closest("tr[data-user]");
  if (e.target.classList.contains("save") && row) {
    e.target.disabled = true;
    try {
      await api("/api/usersync/targets",
                {user: row.dataset.user, targets: targetsOf(row)});
      await refresh();
    } catch (err) { alert(err.message); e.target.disabled = false; }
    return;
  }
  if (e.target.classList.contains("sync") && row) {
    // Save the ticks first so what the admin sees is what gets synced.
    try {
      await api("/api/usersync/targets",
                {user: row.dataset.user, targets: targetsOf(row)});
      await refresh();
      await askAndSync([row.dataset.user]);
    } catch (err) { alert(err.message); }
    return;
  }
  if (e.target.id === "syncall") { askAndSync(ST.users.map(u => u.name)); return; }
  if (e.target.id === "mcancel") { $("#modal").classList.remove("on"); return; }
  if (e.target.id === "mgo") {
    e.target.disabled = true;
    try {
      const d = await api("/api/usersync/sync",
        {users: PEND.users, password: $("#mpw").value || null});
      $("#modal").classList.remove("on");
      show(d.results);
      await refresh();
    } catch (err) { alert(err.message); }
    e.target.disabled = false;
    return;
  }
  if (e.target.id === "savecfg") {
    e.target.disabled = true;
    try {
      await api("/api/usersync/settings",
        {on_untick: $("#untick").value, email_domain: $("#edomain").value});
      await refresh();
    } catch (err) { alert(err.message); }
    e.target.disabled = false;
  }
});

document.addEventListener("submit", async e => {
  const f = e.target.closest("form[data-svc]");
  if (!f) return;
  e.preventDefault();
  const fields = {};
  f.querySelectorAll("input[name]").forEach(i => { if (i.value) fields[i.name] = i.value; });
  try {
    await api("/api/usersync/service", {key: f.dataset.svc, fields});
    await refresh();
  } catch (err) { alert(err.message); }
});

refresh().catch(e => $("#grid").innerHTML = "<tr><td>" + esc(e.message) + "</td></tr>");
"""


# ---------------------------------------------------------------- routes
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


def handle_get(h, path, qs):
    """Handle a user-sync route. Returns True when it took the request.

    The caller has already checked the session; the admin role is checked here,
    per request, because this page provisions accounts across the whole stack.
    """
    if path not in ("/usersync", "/api/usersync/state"):
        return False
    if not h.is_admin():
        if path.startswith("/api/"):
            _json(h, {"error": "forbidden"}, 403)
        else:
            h.send_body("<h1>403</h1><p>Admins only.</p>", 403)
        return True

    if path == "/usersync":
        nav = _main_attr("nav")
        page = PAGE.replace("__CSS__", _main_attr("CSS", "") + CSS)
        page = page.replace("__NAV__", nav("/usersync", h.current_user(), True)
                            if nav else "")
        page = page.replace("__JS__", JS)
        h.send_body(page)
        return True

    _json(h, state())
    return True


def handle_post(h, path):
    """Handle a user-sync POST. Returns True when it took the request."""
    if not path.startswith("/api/usersync/"):
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
    me = h.current_user() or "?"
    conf = load_conf()
    known = set((load_auth().get("users") or {}))

    if path == "/api/usersync/targets":
        name = str(body.get("user") or "")
        if name not in known:
            _json(h, {"error": "no such user"}, 400)
            return True
        ok, why = set_targets(name, body.get("targets") or {}, me)
        _json(h, {"ok": ok} if ok else {"error": why}, 200 if ok else 400)
        return True

    if path == "/api/usersync/email":
        name = str(body.get("user") or "")
        if name not in known:
            _json(h, {"error": "no such user"}, 400)
            return True
        ok, why = set_email(name, body.get("email"), me)
        _json(h, {"ok": ok} if ok else {"error": why}, 200 if ok else 400)
        return True

    if path == "/api/usersync/plan":
        users = [u for u in (body.get("users") or []) if u in known]
        out = []
        cache = {}
        for name in users:
            for step in plan(name, False, conf, cache):
                step["user"] = name
                out.append(step)
        _json(h, out)
        return True

    if path == "/api/usersync/sync":
        users = [u for u in (body.get("users") or []) if u in known]
        if not users:
            _json(h, {"error": "no such user"}, 400)
            return True
        password = body.get("password") or None
        results = []
        cache = {}
        for name in users:
            # A password only ever belongs to the one account it was typed for.
            pw = password if len(users) == 1 else None
            for r in sync_user(name, pw, me, conf, cache=cache):
                r["user"] = name
                results.append(r)
        _json(h, {"ok": True, "results": results})
        return True

    if path == "/api/usersync/service":
        key = str(body.get("key") or "")
        if key not in ADAPTERS:
            _json(h, {"error": "unknown service"}, 400)
            return True
        fields = body.get("fields") or {}
        allowed = set(ADAPTERS[key].NEEDS) | {"url", "api_key"}
        svc = conf["services"].setdefault(key, {})
        for k, v in fields.items():
            if k in allowed and isinstance(v, str):
                svc[k] = v.strip()
        save_conf(conf)
        # Say straight away whether the new credentials actually work, rather
        # than leaving it to fail during a sync.
        a = adapter(key, conf)
        ok, why = a.ready()
        if ok:
            try:
                a.list_users()
            except ApiError as e:
                ok, why = False, str(e)[:200]
        _audit(me, f"USERSYNC config {key} ({'ok' if ok else why})")
        _json(h, {"ok": True, "reachable": ok, "why": why})
        return True

    if path == "/api/usersync/settings":
        if body.get("on_untick") in ("disable", "delete"):
            conf["on_untick"] = body["on_untick"]
        dom = str(body.get("email_domain") or "").strip()
        if dom:
            conf["email_domain"] = dom
        if isinstance(body.get("default_targets"), list):
            conf["default_targets"] = [k for k in body["default_targets"]
                                       if k in ADAPTERS]
        save_conf(conf)
        _audit(me, f"USERSYNC settings on_untick={conf['on_untick']}")
        _json(h, {"ok": True})
        return True

    _json(h, {"error": "unknown action"}, 404)
    return True
