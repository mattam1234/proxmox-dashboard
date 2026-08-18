# Proxmox stack dashboard

A status page, topology graph, app store, file browser, user provisioner and
Cloudflare Tunnel route editor for a Proxmox VE host and its guests.

It has no configuration file describing your stack. It works out what the host
is on every collector run, so the same files run unmodified on any Proxmox box.

## Install

**From a host that already runs it, onto another Proxmox box — one command:**

```
media-dashboard-deploy.sh root@10.20.0.1 --federate
```

That bundles the current code, copies it over SSH, installs it, and (with
`--federate`) pulls the new host's fleet token back and adds it as a peer, so
it appears on this dashboard's Fleet tab immediately. It needs root SSH access
to the target and reuses one connection, so password auth is typed once.

**By hand**, if you would rather not give this host SSH access to that one:

```
media-dashboard-bundle.sh                     # on a host that has it
scp media-dashboard-*.tar.gz root@target:/tmp/
ssh root@target 'cd /tmp && tar -xzf media-dashboard-*.tar.gz \
    && cd media-dashboard && ./media-dashboard-install.sh'
```

The installer checks for `pct`/`pvesh`, lays down the program files, modules and
systemd units, creates an admin account if there is no account store yet, runs
detection once, and starts everything. It prints the URL and login when done.
Re-running it upgrades in place and never overwrites anything under
`/etc/media-dashboard`, so it is also how you push an update to a host later.

With a terminal it prompts for the admin password; without one (a scripted or
piped install) it generates one and prints it rather than hanging on a prompt.

The bundle carries code only — no accounts, tokens or host facts. Uninstall with
`./media-dashboard-install.sh --uninstall`, which leaves `/etc/media-dashboard`
and `/var/lib/media-dashboard` alone.

## How it knows what your stack is

The split that makes this portable is in `mdash_site.py`:

**Portable knowledge** — the `APPS` table. How to recognise Jellyfin, where its
version lives, which repo publishes its releases, which icon belongs to it.
True on every host, ships with the code.

**Site facts** — which container Jellyfin is in, what address it answers on,
which compose directory it came from, what public hostname the tunnel gives it.
True only on your host, detected on every run, written down nowhere.

Detection reads, in order of how much each source knows:

| Source | Gives |
|---|---|
| `pvesh get /cluster/resources` | every guest, its name and state |
| `pct config` / guest agent | each guest's address; bind mounts |
| `docker ps` labels | container image, published ports, **compose working dir** |
| `systemctl list-units` | running service units |
| `ss -lntpH` | anything else holding a port, and the process holding it |
| the tunnel connector's `/config` | public hostname per origin, and the zone |
| `ip addr` + default route | which bridge is uplink and which is internal |

From that it derives everything the old code had hardcoded: the service list,
their versions, their icons, their update recipes (a compose stack updates by
pulling in its own working directory, an \*arr through its own API, anything
else through apt in its own container), the storage roots, the trusted proxy,
and the address the web UI binds to.

An app that is not in the `APPS` table still shows up — discovered by its
listening port, drawn with a placeholder icon, and reported as found rather
than as broken. The table only makes the result prettier and the version checks
sharper.

### Adding an app to the table

One entry, no code:

```python
"Bazarr": {
    "match": {"unit": ["bazarr"], "proc": ["bazarr"], "image": ["bazarr"]},
    "icon": "bazarr", "repo": "morpheus65535/bazarr",
    "version": {"http": "/api/system/status", "field": "version"},
    "role": "subtitles",
},
```

`match` is how an instance is recognised; any one hit identifies it. `version`
recipes are `http` (+`field`, optional `join`/`strip`), `arr`, `dpkg`, `docker`,
`exec` (+`re`), `jar` or `threadfin`. `note` and `warn` are shown in the update
and stop confirmations. Nothing about your host goes in here.

## Overriding detection

Detection writes `/var/lib/media-dashboard/site.json` on every run. That file is
a cache — edit it and the next run overwrites you.

To change something permanently, put just that key in
`/etc/media-dashboard/site.json`. It is merged over the detected picture, key by
key, and nothing else is affected:

```json
{
  "bridges": { "internal": { "ip": "10.10.10.1" } },
  "storage": { "bulk_roots": ["/mnt/tank"] }
}
```

Common reasons to need this: a guest with no address in its config that is also
not running, a service that answers on an address the host cannot reach, or
storage you want browsable that is not bind-mounted into any guest.

The Cloudflare account and tunnel ids cannot be read off the host — they belong
to a Cloudflare account. Put them in `/etc/media-dashboard/cloudflare.json` if
you use the Routing tab to *create* routes; reading and editing existing ones
needs nothing, because the connector reports its own config. The zone is
inferred from the hostnames already being served.

## Several hosts, one dashboard

Install the dashboard on each Proxmox host as above. Then pick one to be the
place you look, and point it at the others — the **Fleet** tab shows every host
on one screen.

On each host you want watched:

```
media-dashboard-fleet-token
```

Paste that into the watching dashboard's Fleet tab, along with the host's URL.
It polls every 60 seconds and appears immediately (a typo in the URL or token
is reported there and then, not silently on the next sweep).

The Fleet page leads with the **roll-up** — unreachable hosts, then every issue,
then every available update, each labelled with which host it came from. That
union is the reason to have one page instead of *n* tabs. Per-host cards sit
underneath with memory, disks, guests and services.

### How federation works, and what it does not do

Each host keeps running its own dashboard, detecting itself, and executing its
own privileged jobs. The only thing added is a read-only export
(`/api/fleet/export`) that the collector writes to a file and the web service
serves to a bearer token.

- **Read-only, by design.** A peer token reads one JSON file. It cannot spool a
  job, read the credentials page, open a terminal or change a route. Losing one
  is an information disclosure, not a compromise. To *act* on another host, use
  the "open ›" link on its card and sign in there — the host that owns the
  container is the host that runs the job, and it applies its own checks.
- **`pct exec` is local.** Detecting what actually runs inside a container
  cannot be done remotely through the Proxmox API, which is why the useful unit
  to share is each host's finished picture rather than its credentials.
- **Peers stay independent.** A host that is down shows as stale, keeps its last
  known card, and changes nothing else. No shared database, no leader.
- **Nothing sensitive is published.** The export carries host stats, guests,
  service names/versions/health, disk usage and issues. No API keys, no
  credentials, no job history, no compose contents.

The token lives in `/etc/media-dashboard/fleet-token` (0600) and is created on
first use, so a host that is never federated never has one. Peers and their
tokens live in `/etc/media-dashboard/peers.json` (0600) and are never sent to a
browser. `media-dashboard-fleet-token --rotate` replaces the token; every
dashboard federating that host then needs the new one.

Hosts reached over HTTPS with a self-signed certificate need the "accept a
self-signed certificate" box ticked when adding them — it is per-peer and off
by default.

## What runs where

Three units, split by privilege:

- **`media-dashboard.timer`** → `media-dashboard.py`, every 2 minutes. Detects,
  probes versions, renders the status page and the topology snapshot.
- **`media-dashboard-web.service`** → the UI. Runs under `ProtectSystem=strict`
  and **may never touch `pct`**. It only ever *describes* privileged work.
- **`media-dashboard-runner.service`** → executes that work, re-validating every
  parameter against the live host before building a command.

That split is the security model, and it is why update and start/stop recipes
are resolved server-side from detected facts rather than accepted from the
browser: a client posts a service *name*, never a container, package, unit or
directory.

## Requirements

Proxmox VE, Python 3.9+, `curl`. `smartmontools` for disk health, `ss` (iproute2)
inside guests for port discovery — both optional, and their absence degrades one
feature rather than breaking the page.
