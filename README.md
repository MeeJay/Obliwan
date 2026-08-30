<p align="center">
  <img src="client/public/logo.svg" alt="ObliWAN" height="80">
</p>

<h3 align="center">Multi-vendor WAN fleet manager &amp; TR-069 ACS</h3>

<p align="center">
  Inventory, configuration templates, semantic drift detection, safe change
  rollouts and SNMP telemetry for MikroTik, DrayTek, Zyxel and SonicWall sites
  reached through an L2TP concentrator.
  <br>
  Part of the <a href="https://obli.tools"><strong>obli.tools</strong></a> ecosystem.
</p>

---

> ### Status — feature-complete, entering production
>
> **What is built:** milestones M1 through M12 and features F1 through F8. The
> inventory and credential vault, the four vendor drivers, the five transports,
> SNMP telemetry, the Normalized Config Model, snapshots and semantic drift,
> templates and inherited variables, plan compilation, safe apply with an
> on-device dead-man rollback, the Management-Path Guard, waved rollouts, syslog
> ingestion and drift attribution, the Fleet Query DSL, the TR-069 ACS, the
> intent compiler, template mining, and the eight evidence and operations
> features described below. 30 migrations, 37 pages, the full deployment chain.
>
> **What is not done:** milestone M13, the translation of the sixteen locales.
> Every milestone after M1 left its new interface keys behind in English. That
> was a deliberate deferral, not an oversight, and the product is usable in
> English today.
>
> **How it was built:** every driver, parser and safety guard was developed
> against protocol-level fakes and recorded fixtures, then put through five
> adversarial audits that found and closed 24 critical defects. Roll it out the
> way it rolls out changes — a few standalone devices first, then the fleet
> behind the concentrator.

---

## What ObliWAN is

A tool for whoever operates a few hundred customer sites behind an L2TP
concentrator, with routers from four different vendors and no two configured
quite the same way.

The core idea is the **NCM — Normalized Config Model**. ObliWAN does not diff
configuration *text*. It parses each vendor's configuration into one semantic
model (interfaces, routes, firewall rules, NAT, DHCP scopes, IPsec peers, local
users, services, QoS) and works on that. Text diffing does not survive four
vendors: a DrayTek's configuration is not even text.

Everything else follows from that model:

- **Inventory & credential vault** — sites, devices, one transport record per
  channel (RouterOS API, SSH, SNMP, SonicOS REST, TR-069), secrets stored
  AES-256-GCM under a dedicated key.
- **Presence from the concentrator** — the CHR's `/ppp/active` is the source of
  truth for whether a site is up, not ping. A device whose PPP session is down
  is never dialled.
- **Config collection & drift** — periodic snapshots, gzip + deduplicated by
  NCM hash, compared against the intended configuration; findings are semantic
  (`missing` / `extra` / `changed` / `moved`), not line noise.
- **Templates** — Nunjucks with inheritance, variables resolved through the
  global → tenant → group chain → device hierarchy, immutable published
  revisions with partials pinned at publication time. Rendering runs in a worker
  thread with resource limits, a pure-JSON context and a 5 s timeout: the
  process that evaluates a template holds the whole fleet's credentials.
- **Safe change** — nothing is written to a device outside the `change_jobs`
  queue: one job in flight per device, a mandatory pre-change backup, a dead-man
  rollback armed *on the device itself*, confirmation over a channel independent
  from the one that pushed, and disarm only after a soak period.
- **Management-Path Guard** — before any push, a small forwarding engine runs a
  synthetic packet (concentrator → management IP) against the *target* config
  and refuses the plan if the path turns from ACCEPT into DROP or no-route. An
  indeterminate verdict is a refusal, never an approval.
- **Waved rollouts** — 1 device, then 5%, 25%, the rest, with measured health
  gates between waves and automatic pause and rollback. A wave cannot be queued
  without a health baseline captured before it, and a concentrator can never
  share an active rollout with its own children — both enforced by the database
  rather than by a controller.
- **Fleet Query** — a typed DSL compiled to SQL over the indexed NCM, so "who
  still has an any/any inbound rule on the WAN" is a three-minute answer instead
  of a three-week audit.
- **SNMP & time series** — v2c/v3, IF-MIB discovery keyed on `(device, ifName)`
  because `ifIndex` is not stable, 64-bit counters, partitioned tables with
  1m/5m/1h rollups.
- **Intent compiler** — one site intent, four dialects, and a compilation that
  fails *before* any socket, session or credential when the hardware cannot do
  what the intent asks.
- **Audit** — hash-chained append-only audit log, plus a record of every command
  ever sent to a device with secrets redacted.

### Evidence and operations

- **Justified drift exceptions** — an exception requires a justification and a
  review date, enforced by CHECK constraints rather than by validation. Expiry
  is derived, so a stale exception hands its drift back instead of hiding it
  forever.
- **Signed compliance attestations** — verifiable, over a snapshot set.
- **Intervention mode** — brackets a human's work so the drift it produces is
  attributed to it instead of surfacing as an anomaly. An open intervention is
  *not* a permission to write.
- **Change aftermath** — correlates a change against the telemetry a week later.
- **Operator weather** — one site switching to LTE is a flap; twelve sites on
  the same ASN within ten minutes is an operator incident. The whole feature is
  the quorum. It reasons on the public address the *concentrator* observed in
  the PPP caller-id, never one a device claims for itself.
- **Hardware replacement detection** — a serial that moves is a box that was
  swapped, and the previous snapshot stops being a trustworthy baseline. It is
  signalled, never silently corrected.
- **Computed SLA** — distinguishes "the site was down" from "we lost the
  tunnel". A management-plane outage is never billed against a customer, and the
  report states how much time was excluded and why.
- **End-of-life inventory** — "end of support unknown" is an honest answer;
  "supported" for a model absent from the catalogue is not.

## TR-069 / ACS — read this before you plan around it

ObliWAN includes its own minimal ACS (Inform, GetParameterValues,
SetParameterValues, Download, Reboot) on a dedicated listener on 7547, outside
nginx. That is structural, not an oversight: a reverse proxy that rewrites the
request line invalidates HTTP Digest, and proxy buffering cuts CWMP sessions in
the middle.

**It does not cover the whole fleet, and it cannot.** RouterOS has no TR-069
client. SonicOS has no TR-069 client. Those two vendors are managed over their
own APIs and SSH — TR-069 is only one transport out of five in ObliWAN, never
the foundation.

In practice the ACS covers **DrayTek and Zyxel CPE only**. That coverage ships
as data rather than as prose, and the UI states it per vendor instead of
implying uniform support.

Also deliberately out of scope: Connection Request over UDP/STUN (Annex G) and
XMPP (Annex K). Their success rate in the field is poor and NAT bindings expire
in 30–120 s. The honest fallback is a reduced `PeriodicInformInterval`, and the
UI says so.

## Requirements

- Docker + Docker Compose v2
- PostgreSQL 16 (bundled, or bring your own)
- **A route from the Docker host to the L2TP tunnel subnet.** ObliWAN reaches
  the fleet through that tunnel; without the route every device is simply
  unreachable. If the tunnel terminates on another box, add the static route on
  the host. This is documented at the top of `docker-compose.yml`.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/MeeJay/Obliwan/main/install.sh | sh
```

Or manually:

```sh
curl -fsSLO https://raw.githubusercontent.com/MeeJay/Obliwan/main/docker-compose.yml
curl -fsSL  https://raw.githubusercontent.com/MeeJay/Obliwan/main/.env.example -o .env
# edit .env — at minimum SESSION_SECRET, DB_PASSWORD and OBLIWAN_ENCRYPTION_KEY
docker compose up -d
```

Then open **http://localhost:3004** (3000–3003, 3020 and 3100 are used by the
other Obli\* products).

Outside development the server refuses to start on a placeholder or short
`SESSION_SECRET`, and the session cookie is marked `Secure` unconditionally — a
production instance served over plain HTTP will not hold a session. That is the
intended reading of "fail closed", and the fix is TLS, not a flag.

### Back up `OBLIWAN_ENCRYPTION_KEY`

That single key encrypts every device credential ObliWAN stores: RouterOS
logins, SSH keys, SNMPv3 secrets, SonicOS accounts, TR-069 digest passwords.
Lose it or change it and **every stored credential becomes permanently
unreadable** — the server starts fine, logs no error, and simply fails to
connect to anything. Generate it with `openssl rand -hex 32`, and keep a copy
somewhere other than this host.

It is deliberately separate from `SESSION_SECRET` so that rotating a session
secret can never destroy the vault.

## Ports

| Port | Proto | Published | Role |
|---|---|---|---|
| **3004** | TCP | yes | Web UI (nginx) |
| 3001 | TCP | no | API + Socket.io, internal to the compose network |
| **7547** | TCP | yes | TR-069 / CWMP ACS — dedicated listener, not behind nginx |
| 7548 | TCP | optional | CWMP over permissive TLS for legacy CPE |
| **162** | UDP | yes | SNMP traps |
| **514** | UDP+TCP | yes | Device syslog |
| 5432 | TCP | no | PostgreSQL (published in the dev compose only) |

Publishing ports on the `server` service is the **one deviation** from the Obli\*
suite topology, where only the nginx client is ever published. Devices in the
field have to reach the ACS, the trap receiver and the syslog receiver inbound.

Consequence of using the Docker bridge: NAT rewrites the source address of
inbound UDP, so an SNMP trap appears to come from the bridge gateway. ObliWAN
never identifies a device from a trap's source IP (identity is
`ppp_username` + `system_identity` + `serial`). If you genuinely need the real
source address, `docker-compose.host.yml` runs the server on the host network —
read its header for the trade-offs.

## Compose files

| File | Use |
|---|---|
| `docker-compose.yml` | Standard deployment, prebuilt images |
| `docker-compose.build.yml` | Same topology, built from source |
| `docker-compose.dev.yml` | Overlay: live reload, Vite on 5173, Postgres published |
| `docker-compose.external-db.yml` | No bundled Postgres — bring your own `DATABASE_URL` |
| `docker-compose.host.yml` | Fallback: server on the host network, real trap source IPs |

## Development

```sh
npm install
npm run dev          # docker compose build + dev overlay
npm run typecheck    # shared build, then tsc --noEmit on server and client
```

Monorepo, npm workspaces: `shared/` (types, capabilities, the NCM contract),
`server/` (Express + Knex + Socket.io), `client/` (React + Vite + Tailwind +
Zustand). `shared/` must be built before the server compiles.

`OBLIWAN_ROLE` selects what a process does: `web` (HTTP only), `worker`
(pollers, job queue, drift runs) or `all`. Several `web` replicas can run side
by side; background duties are held by a single leader elected through a
PostgreSQL advisory lock.

## Roadmap

| Milestone | Content | Status |
|---|---|---|
| M1 | Monorepo, API skeleton, migration `001`, Obligate SSO, app shell, Docker | **done** |
| M2 | Inventory, credential vault, transports, CHR discovery, PPP presence | **done** |
| M3 | SNMP sessions, IF-MIB discovery, time series, rollups, thresholds | **done** |
| M4 | MikroTik NCM, snapshots, read-only drift | **done** |
| M5 | Templates, inherited variables, plan generation | **done** |
| M6 | Safe apply (dead-man rollback) + Management-Path Guard | **done** |
| M7 | Waved rollouts with health gates — end of v1 | **done** |
| M8 | Syslog ingestion, drift attribution, reachability verdict | **done** |
| M9 | Fleet Query DSL | **done** |
| M10 | TR-069 ACS + DrayTek/Zyxel drivers | **done** |
| M11 | SonicWall driver + multi-dialect intent compiler | **done** |
| M12 | Fleet onboarding: template mining from existing configs | **done** |
| F1–F8 | Drift exceptions, attestations, intervention mode, change aftermath, operator weather, hardware replacement, computed SLA, EOL inventory | **done** |
| M13 | Internationalisation — translating the sixteen locales | planned |

Every milestone is built, reviewed and passing its own tests; M13 is the only
one still open.

Backlog after M13: time machine and config bisect, failover forensics, change
requests with approval, mass credential rotation, zero-touch provisioning,
network CI, recorded console broker, SLA reports as PDF, CVE exposure,
bidirectional Git sync, cross-suite blast radius.

## Architecture

`ARCHITECTURE.md` is the authoritative document: structural decisions, full
database schema, page inventory, milestone plan and the risk register.

## License

See `LICENSE`.
