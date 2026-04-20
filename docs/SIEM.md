# SIEM Architecture — Graylog Deployment

Deliverable #4 (Security Monitoring) of the siem-arcade-game project. This document
covers the infrastructure design for the Graylog-based SIEM: component roles, the
high-availability topology, and the rationale behind each design choice.

---

## 1. Data flow overview

```
┌──────────────┐     HTTP      ┌──────────────────┐
│  Browser     │──POST /api/──▶│  log-server.py   │
│  (arcade     │     logs      │  (Python relay)  │
│   game)      │               └────────┬─────────┘
└──────────────┘                        │
                                        ├──▶ logs/game-logs.ndjson   (archive on disk)
                                        │
                                        │  GELF HTTP (port 12201)
                                        ▼
                             ┌─────────────────────┐
                             │  Nginx LB (:9000)   │
                             └──────────┬──────────┘
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
                 ┌────────────┐                  ┌────────────┐
                 │ Graylog A  │                  │ Graylog B  │
                 └──────┬─────┘                  └──────┬─────┘
                        │                               │
        ┌───────────────┼───────────────────────────────┤
        ▼               ▼                               ▼
┌──────────────┐  ┌──────────────┐             ┌──────────────┐
│ MongoDB RS   │  │ OpenSearch   │             │  Dashboards  │
│ (3 nodes)    │  │ cluster (3)  │             │  + Alerts    │
└──────────────┘  └──────────────┘             └──────────────┘
   config,            log data,                  Security Overview
   users,             search index               Game Server Health
   dashboards,                                   Events stream
   event defs
```

The game emits ECS v8.11 JSON. The Python relay both archives to disk (NDJSON) and
forwards each event as GELF over HTTP into the Graylog cluster. Graylog's event
engine runs the correlation rules (brute-force, DoS) and surfaces detections as
event widgets on the same dashboard the operator already has open.

---

## 2. Components and their roles

| Component | Purpose | Why it matters here |
|---|---|---|
| **log-server.py** | Receives game events, archives to NDJSON, forwards to Graylog | Single ingress point — lets us authenticate, rate-limit, and capture real client IPs before anything touches the SIEM |
| **MongoDB** | Stores Graylog *configuration* — users, dashboards, streams, event definitions, role bindings | If Mongo is down, Graylog still ingests but cannot save config changes; losing it = losing dashboards/alerts |
| **OpenSearch** | Stores the actual *log messages* and powers search | Losing it = losing history. The highest-value state in the stack |
| **Graylog node** | Ingestion + stream routing + event correlation + web UI | Stateless relative to the two DBs — easy to scale horizontally behind an LB |
| **Nginx** | TLS termination and load balancing across Graylog nodes | Gives a single stable URL (`/dashboard`) that survives any one Graylog node dying |

---

## 3. Why high-availability (option B)

The assignment rubric explicitly asks for *"high availability configuration"*. Beyond
the rubric, HA matters here because a SIEM is a **security-critical dependency**:
if the SIEM goes down during an actual incident, the blue team is blind exactly
when visibility matters most. A single-node Graylog has three distinct single
points of failure — we eliminate each one.

### What each layer protects against

**MongoDB replica set (3 nodes, PSS topology)**
- One node is the primary, two are secondaries replicating the oplog.
- Tolerates loss of any one node — the remaining two elect a new primary in <10 s.
- Why three, not two: a two-node set cannot hold a majority vote if one dies, so
  failover stalls. Three is the minimum for automatic failover.
- Protects against: config corruption, disk failure on the config DB, planned
  reboots of the Mongo host.

**OpenSearch cluster (3 nodes, replica=1)**
- Each log index is sharded across nodes, and every shard has one replica copy
  on a *different* node. Losing any one node loses zero data — the replica is
  promoted instantly.
- Why three, not two: OpenSearch uses quorum-based cluster state updates
  (`discovery.zen.minimum_master_nodes = (N/2)+1`). With two nodes you get
  split-brain on network partitions; with three you don't.
- Protects against: data loss on disk failure, search unavailability during
  maintenance, index corruption on one node.

**Graylog nodes (2, stateless, behind Nginx)**
- Graylog nodes are stateless except for their local message journal. Either
  node can serve any request; the LB health-checks both.
- Why two, not three: Graylog doesn't do quorum — it just needs >1 so a rolling
  upgrade or crash doesn't take down ingestion. Two is the minimum.
- Protects against: JVM crashes, rolling upgrades, network issues on one host.

**Nginx (single node in dev, keepalived pair in prod)**
- Locally one Nginx is fine — the goal is the routing layer, not HA of the LB
  itself. In production, a keepalived pair with a floating VIP closes the gap.

### What HA does *not* protect against (and how we compensate)

- **Config mistakes** — a bad event definition replicates everywhere. Mitigated
  by keeping all Graylog config in version control as a content pack
  (`graylog/content-pack.json`) so we can roll back via git.
- **Host-level failure** (all containers on one machine die) — only true HA across
  physical hosts solves this. In production on the VPS we'd either distribute
  the stack across 2–3 hosts, or rely on the cloud provider's host-migration SLA.
- **Log flood DoS on the SIEM itself** — rate limits on `log-server.py` and
  OpenSearch index lifecycle policies cap blast radius.

---

## 4. Design decisions

### Why Graylog over ELK
Graylog ships stream routing, event correlation, and alerting as first-class
features. ELK requires bolting on Watcher (paid) or ElastAlert (community). For
a demo focused on detection scenarios, Graylog is less glue code.

### Why GELF over Beats
The Python relay already has one egress path for Logstash; adding GELF HTTP is
a dozen lines and removes the need to run Filebeat at all. Fewer moving parts
during the demo.

### Why keep the NDJSON archive
Two reasons: (1) it's the fallback if the Graylog cluster is unreachable during
ingestion — we can replay later; (2) the file is evidence-grade for post-incident
forensics, independent of whatever happens inside the SIEM.

### Why same-domain dashboards, no external notifications
The operator (one person) wants a single URL (`domain.com/dashboard`) behind a
VPN/IP allowlist. External notifications (email/Slack/PagerDuty) add
exfiltration surface and credential sprawl for no gain at this scale. Alerts
surface as event widgets on the dashboard itself.

### Why local docker-compose now, VPS later
Iterating on Graylog config is easier when Graylog is on the same host as the
editor. The same compose file deploys to the VPS unchanged — only the external
URI and TLS certs differ.

---

## 5. Deployment footprint

| Env | Containers | RAM (approx) | Purpose |
|---|---|---|---|
| **Dev (single-node)** | 3 (Graylog, Mongo, OpenSearch) | ~3 GB | Fast iteration, not used for the demo |
| **HA (this deployment)** | 9 (3 Mongo, 3 OpenSearch, 2 Graylog, 1 Nginx) | ~8 GB | Full HA topology for the demo |
| **Prod (VPS, future)** | Same 9 + TLS + IP allowlist at Nginx | ~8 GB | Same compose file, different `.env` |

---

## 6. Running the stack

### Prerequisites
- Docker 24+ with compose plugin or `docker-compose` v2.30+
- 8 GB free RAM, 10 GB free disk
- Host with `ip_forward=1` and either permissive iptables FORWARD or the provided host-networked compose file

### First-time bring-up

```bash
# 1. Secrets — edit .env (copied from docker/.env.example)
#    GRAYLOG_PASSWORD_SECRET must be >=16 chars
#    GRAYLOG_ROOT_PASSWORD_SHA2 = sha256 hex of your admin password
cat docker/.env.example   # reference
cat .env                  # edit in place

# 2. Start everything (first run pulls ~3 GB of images)
docker-compose -f docker-compose.ha.yml up -d

# 3. Watch it come healthy (takes ~3 min)
docker-compose -f docker-compose.ha.yml ps

# 4. Provision streams + event definitions + dashboards
python3 scripts/provision-graylog.py
python3 scripts/provision-dashboards.py

# 5. Start the game + forward logs to Graylog
python3 log-server.py --port 8080 --gelf http://127.0.0.1:12201/gelf
# → http://localhost:8080   (game)
# → http://localhost:9000   (Graylog UI — login admin / admin)
```

### Tear down

```bash
docker-compose -f docker-compose.ha.yml down        # keep data
docker-compose -f docker-compose.ha.yml down -v     # wipe volumes (fresh start)
```

---

## 7. Dashboards

Two dashboards are provisioned by `scripts/provision-dashboards.py`:

### Security Overview (`/dashboards/<id>`)
| Widget | Query | Visualisation |
|---|---|---|
| Auth failures (24h) | `event_action:auth_failure` | Single number |
| Successful logins (24h) | `event_action:user_login AND event_outcome:success` | Single number |
| Top offender source IPs | `event_action:auth_failure` grouped by `source_ip` | Table |
| Auth failures timeline | `event_action:auth_failure` per 1h | Bar chart |
| Recent auth events | `event_category:authentication` | Message list |
| Active alerts | `*` (filtered on the All Events stream) | Message list |

### Game Server Health (`/dashboards/<id>`)
| Widget | Query | Visualisation |
|---|---|---|
| Total events (24h) | `*` | Single number |
| Unique users (24h) | `card(user_name)` | Single number |
| Events by category | `*` grouped by `event_category` | Pie |
| Event rate over time | `*` per 30 min | Line |
| Top users | `*` grouped by `user_name` | Table |
| Gameplay actions | `event_category:gameplay` grouped by `event_action` | Bar |

Both dashboards default to the last 24 hours; zoom in with the time-range picker
at the top-right of the Graylog UI.

---

## 8. Detection rules (Event Definitions)

Defined in `scripts/provision-graylog.py`; all run in the Graylog event
processor on every Graylog leader node.

| Rule | Query | Group by | Threshold | Window |
|---|---|---|---|---|
| **Brute-force login** | `event_action:auth_failure` | `source_ip` | ≥ 5 | 60 s |
| **DoS flood** | `*` | `source_ip` | ≥ 100 | 10 s |
| **Failed-login anomaly** | `event_action:auth_failure` | — (all) | ≥ 20 | 300 s |

Each rule has a grace period equal to its window, so consecutive aggregation
runs over the same event span do not re-alert. Firing events land in the **All
events** stream and are surfaced as widgets on the Security Overview dashboard.

### Incident detection walk-through (demo)

1. **Start the pipeline** — `python3 log-server.py --port 8080 --gelf http://127.0.0.1:12201/gelf`.
2. **Open the Security Overview dashboard** and the Graylog **Alerts → Events** page side-by-side.
3. **Run the attacker simulator:**
   ```bash
   python3 scripts/simulate-bruteforce.py --attempts 10 --source-ip 198.51.100.77
   ```
4. Within ~30–60 s you'll see an event appear:
   `Brute-force login: 198.51.100.77 - count()=10.0` with priority `HIGH`.
5. The event's `fields.source_ip` is populated via the Graylog template
   engine (`${source.source_ip}`), which enables pivoting from the alert to
   the offender's other activity.
6. For a DoS demo: `python3 scripts/simulate-dos.py --requests 200 --rate 50`.

---

## 9. Automated daily reporting

`scripts/daily-report.py` pulls the last 24 hours from Graylog via the REST API
and renders a self-contained HTML report to `reports/daily-YYYY-MM-DD.html`.
The report includes:
- Summary cards (event total, unique users/IPs, auth success/fail, alert count)
- Hourly activity bar chart (embedded SVG, no JS)
- Top 10 source IPs and top 10 users
- Events by category
- Every firing alert with severity, timestamp, and key fields

### Schedule with cron

```cron
# /etc/cron.d/siem-daily-report
0 0 * * *  new_testament  cd /home/new_testament/Projects/siem-arcade-game \
           && /usr/bin/python3 scripts/daily-report.py --out reports/ >> reports/cron.log 2>&1
```

### Customisation

- Change the reporting window: `--hours 12` or `--hours 168` (7-day)
- Point at a different Graylog: `--url https://dashboard.example.com`
- Use a service account: `--user report-bot --password ...`
- Add sections: edit `HTML_TEMPLATE` and extend `render_report()` — all
  widgets/tables are composable strings

---

## 10. What's out of scope for this deliverable

- Cross-datacentre / multi-region replication
- OpenSearch snapshot lifecycle to S3 (documented, not deployed)
- SSO/LDAP integration on Graylog (local users for the demo)
- Encryption-at-rest on the volumes (relies on host disk encryption)
