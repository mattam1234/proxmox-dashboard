# Proxmox stack dashboard

A single web dashboard for a Proxmox VE host and everything running on it —
status, topology graph, app store, file browser, user provisioning, Cloudflare
Tunnel route editor, and a fleet view that puts several hosts on one screen.

**There is no configuration file describing your stack.** It works out what the
host is on every run — containers, addresses, ports, storage, what service is in
which container and how it was installed — so the same code runs unmodified on
any Proxmox box.

---

## Install

On any Proxmox VE host:

```bash
git clone https://github.com/YOU/proxmox-dashboard.git
cd proxmox-dashboard
sudo ./install.sh
```

It checks it is really on Proxmox, installs the program files, modules and
systemd units, creates an admin account, detects the host, and starts
everything. It prints the URL and login when it finishes.

Re-running it upgrades in place — it never touches `/etc/media-dashboard`, so
accounts, tokens and overrides survive. That is also how you push an update:

```bash
git pull && sudo ./install.sh
```

Uninstall with `sudo ./install.sh --uninstall` (leaves your data behind).

### Onto another host, in one command

From a host that already runs it:

```bash
media-dashboard-deploy.sh root@10.20.0.1 --federate
```

Bundles the current code, copies it over SSH, installs it there, and with
`--federate` adds the new host to this dashboard's Fleet tab. Needs root SSH to
the target; it reuses one connection so password auth is typed once.

`media-dashboard-bundle.sh` produces the same tarball on its own if you would
rather move it by hand — the bundle has the same layout as this repo, so a
tarball and a clone install identically.

### Requirements

Proxmox VE, Python 3.9+, `curl`. Optional: `smartmontools` for disk health,
`iproute2` (`ss`) inside guests for port discovery. Neither is fatal — their
absence degrades one feature rather than breaking the page. No Python packages,
no database, no container.

---

## What you get

| Tab | What it does |
|---|---|
| **Status** | Host, guests, services with live versions, disks with SMART verdicts |
| **Topology** | Interactive graph of hosts, guests, services, storage and the links between them — every edge probed, never assumed |
| **Fleet** | Several Proxmox hosts on one page, led by the union of everything wrong on any of them |
| **Catalog** | Your Jellyfin library, browsable and searchable |
| **App store** | Deploy helper scripts and Docker stacks; browse and install apt packages on the host or in any container |
| **Files** | Browse and download from the storage this host shares into its guests |
| **Users / User sync** | One account list, provisioned out to Jellyfin, Jellyseerr, Grafana, Immich and others |
| **Routing** | Read and edit Cloudflare Tunnel routes, with each route shown as the service it publishes |
| **Terminal / Claude / Usage** | Admin tmux terminal, an assistant pane, and resource history |

---

## How it knows what your stack is

The design splits two kinds of knowledge that are usually tangled together
(`lib/mdash_site.py`):

**Portable knowledge** — the `APPS` table. How to recognise Jellyfin, where its
version lives, which repo publishes its releases, which icon is its. True on
every host, ships with the code.

**Site facts** — which container Jellyfin is in, what address it answers on,
which compose directory it came from, what hostname the tunnel gives it. True
only on your host, detected on every run, written down nowhere.

Detection reads, in order of how much each source knows:

| Source | Gives |
|---|---|
| `pvesh get /cluster/resources` | every guest, its name and state |
| `pct config` / QEMU guest agent | each guest's address; bind mounts |
| `docker ps` labels | image, published ports, **compose working directory** |
| `systemctl list-units` | running service units |
| `ss -lntpH` | anything else holding a port, and the process holding it |
| the tunnel connector's `/config` | public hostname per origin, and the zone |
| `ip addr` + default route | which bridge is uplink and which is internal |

From that it derives the service list, their versions and icons, their update
recipes (a compose stack updates by pulling in its own working directory, an
\*arr through its own API, anything else through apt in its container), the
storage roots, the trusted proxy and the address to bind to.

An app not in the `APPS` table still appears — found by its listening port,
drawn with a placeholder icon, reported as found rather than as broken. The
table only makes the result prettier and the version checks sharper.

### Teaching it a new app

One table entry, no code:

```python
"Bazarr": {
    "match": {"unit": ["bazarr"], "proc": ["bazarr"], "image": ["bazarr"]},
    "icon": "bazarr", "repo": "morpheus65535/bazarr",
    "version": {"http": "/api/system/status", "field": "version"},
    "role": "subtitles",
},
```

`match` is how an instance is recognised; any one hit identifies it. Version
recipes are `http` (+ `field`, optional `join`/`strip`), `arr`, `dpkg`,
`docker`, `exec` (+ `re`), `jar` or `threadfin`. Nothing about your host goes in
here.

### Overriding detection

Detection writes `/var/lib/media-dashboard/site.json` every run — that file is a
cache, so editing it achieves nothing. Put just the key you want changed in
`/etc/media-dashboard/site.json` and it is merged over the detected picture:

```json
{
  "bridges": { "internal": { "ip": "10.10.10.1" } },
  "storage": { "bulk_roots": ["/mnt/tank"] }
}
```

---

## Several hosts, one dashboard

Install on each host, then point one at the others from its **Fleet** tab. On
each host you want watched:

```bash
media-dashboard-fleet-token
```

Paste that plus the host's URL into the watching dashboard. It polls every 60
seconds and reports a bad URL or token immediately rather than silently.

The Fleet page leads with the **roll-up** — unreachable hosts, then every issue,
then every available update, each tagged with the host it came from. That union
is the point of one page instead of *n* tabs; per-host cards sit underneath.

**This is federation, not a cluster.** Every host keeps running its own
dashboard and executing its own jobs. The only addition is a read-only export
that the collector writes to a file and the web service serves to a bearer
token.

- **Read-only by design.** A peer token reads one JSON file. It cannot spool a
  job, read credentials, open a terminal or change a route. Losing one is an
  information disclosure, not a compromise. To *act* on another host, follow the
  "open ›" link on its card and sign in there — the host that owns the container
  is the host that runs the job, and it applies its own checks.
- **Why not reach in directly?** `pct exec` is local: what actually runs inside
  a container cannot be detected remotely through the Proxmox API. The useful
  unit to share is each host's finished picture, not its credentials.
- **Peers stay independent.** A host that is down shows as stale and keeps its
  last known card. No shared database, no leader election.
- **Nothing sensitive is published.** Host stats, guests, service names,
  versions and health, disk usage, issues. No keys, no credentials, no job
  history, no compose contents.

Tokens live in `/etc/media-dashboard/fleet-token` and peer tokens in
`peers.json`, both `0600` and never sent to a browser.

---

## Security model

Three units, split by privilege — this is the part worth understanding before
you expose it anywhere:

- **`media-dashboard.timer`** → the collector, every 2 minutes. Detects, probes
  versions, renders the status page and topology snapshot.
- **`media-dashboard-web.service`** → the UI. Runs under `ProtectSystem=strict`
  and **can never touch `pct`**. It only ever *describes* privileged work.
- **`media-dashboard-runner.service`** → carries that work out, re-validating
  every parameter against the live host before building a command.

The browser posts a service *name* — never a container, package, unit or
directory. Recipes are resolved server-side from detected facts, so a client
cannot choose what gets updated or restarted.

The login is session-cookie based with scrypt password hashes, per-IP lockout
after repeated failures, and a forwarded-for header believed only from the
tunnel connector's own address. Publishing any of this to the internet without
an auth layer in front is your call, not the dashboard's.

---

## Layout

```
install.sh          install / upgrade / uninstall
bin/                programs installed to /usr/local/bin
lib/                modules installed to /usr/local/lib/mdash
docs/DESIGN.md      longer design notes
```

State on an installed host:

```
/etc/media-dashboard/       accounts, tokens, overrides  (0600, never in git)
/var/lib/media-dashboard/   detected facts, caches, job spool, fleet cache
/var/www/dashboard/         the generated status page
```

---

## Origin

Written for a single six-container Proxmox media host, then generalised: the
service list, addresses and container ids that were once spelled out in five
files are now all detected. Contributions that re-introduce a hardcoded address
or a per-host service list will be politely declined.

## License

MIT — see [LICENSE](LICENSE).
