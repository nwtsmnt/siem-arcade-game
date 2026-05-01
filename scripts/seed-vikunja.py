#!/usr/bin/env python3
"""Seed Vikunja with the 5-person SIEM-arcade team, one project, and ~25 tasks.
Run on the VPS so it can hit 127.0.0.1:3456 directly (no DNS needed).
Idempotent: skips users/projects that already exist."""
import json, sys, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone

BASE = "http://127.0.0.1:3456/api/v1"
PASSWORD = "<REDACTED-PASSWORD>"

TEAM = [
    ("roman",  "Roman Tcholokava",   "roman@siem-game.co.uk",   "PM / Detection"),
    ("rahmon", "Rahmon",             "rahmon@siem-game.co.uk",  "Infra / DevOps"),
    ("tom",    "Tom",                "tom@siem-game.co.uk",     "App / AppSec"),
    ("maruf",  "Maruf",              "maruf@siem-game.co.uk",   "Pentester / Red Team"),
    ("chesta", "Chesta",             "chesta@siem-game.co.uk",  "SOC / IR"),
]

# (title, owner_username, bucket_idx, due_offset_days_from_today, description)
# bucket: 0=Backlog 1=Todo 2=Doing 3=Review 4=Done
TASKS = [
    # Done — sprint 1 (week 1, Apr 4-10)
    ("Provision Docker host + network rules",          "rahmon", 4, -27, "VPS at IONOS, ufw + iptables, SSH on 39741."),
    ("Buy domain siem-game.co.uk + base DNS",          "roman",  4, -27, "Apex + www + game/soc/graylog A records."),
    ("Game build: arcade-game core mechanics",         "tom",    4, -25, "Player, enemies, scoring, lives. Vanilla JS canvas."),
    ("Threat model + risk register draft",             "roman",  4, -24, "STRIDE table, top-10 risk register, ownership."),
    ("Admin panel + attack-simulation controls",       "tom",    4, -23, "Hidden panel for live demos: brute-force, DoS, DDoS."),
    # Done — sprint 1 end (week 2, Apr 11-17)
    ("Stand up Graylog HA cluster (2 nodes)",          "rahmon", 4, -20, "Docker compose, host networking, MongoDB replSet, OpenSearch x3."),
    ("Normalise game logs to ECS v8.11",               "chesta", 4, -19, "log-engine.js: event.action/category/outcome, source.ip, user.name."),
    ("Forward logs: log-server.py → GELF",             "rahmon", 4, -18, "GELF TCP 12202, 8 worker threads, host-network reachable."),
    ("Pen-test: brute-force /login + report",          "maruf",  4, -17, "Hydra wordlist, Burp; documented findings + screenshots."),
    # Done — sprint 2 (week 3, Apr 18-24)
    ("Correlation rules: brute-force + DoS + DDoS",    "chesta", 4, -14, "Graylog event definitions: 5/60s, 30/10s, 300/30s + targeted-account."),
    ("SOC Console UI v1 (alerts + drill-down)",        "roman",  4, -13, "Live SSE feed, click-through filters, KPIs."),
    ("Force-logout + IP block actions",                "rahmon", 4, -12, "App-layer + kernel iptables, 60s TTL on blocklist."),
    ("Pen-test: account-takeover scenarios",           "maruf",  4, -11, "Credential stuffing, session fixation; remediation tickets opened."),
    ("GeoIP enrichment + display re-enrich",           "rahmon", 4, -10, "MaxMind GeoLite2, async cache + render-time fallback."),
    # Doing/Review (week 4, Apr 25 - May 1)
    ("Provision 5 critical Graylog dashboards",        "chesta", 4, -6,  "Executive, Auth Security, Threat Detection, Compliance, Game Server Health."),
    ("Daily compliance report (PDF, GDPR/SOC2)",       "roman",  4, -5,  "Cron job, weasyprint; e-mailed to stakeholders 09:00."),
    ("Capacity scaling: GELF TCP + nginx LB",          "rahmon", 4, -4,  "Round-robin TCP LB; verified 18k eps sustained on stage."),
    ("Role docs (5 teammates) + screenshots",          "roman",  3, -1,  "STAR examples, 12 screenshots each, weasyprint PDFs in /docs/roles/pdf/."),
    ("Penetration-test final report",                  "maruf",  3, 0,   "Findings, severity rating, remediation status, exec summary."),
    # Todo (next 1-2 weeks)
    ("Self-host PM tool (Vikunja) on pm.subdomain",    "rahmon", 2, 0,   "DNS, TLS, docker compose, nginx vhost. Seed users + tasks."),
    ("Soak-test 24h sustained 10k eps",                "rahmon", 1, 3,   "Generate load, watch OS heap pressure, confirm zero dropped events."),
    ("Tabletop incident-response exercise",            "chesta", 1, 5,   "Simulate full ransomware scenario, time MTTR, write retro."),
    ("Slack/Discord webhook alerting",                 "chesta", 1, 7,   "Critical alerts to #soc channel; rate-limit to avoid pager fatigue."),
    ("AbuseIPDB threat-intel enrichment",              "chesta", 1, 9,   "Pipeline rule, cache scores, surface in SOC drill-down."),
    # Backlog
    ("Cheater/bot detection rules (rapid-fire)",       "maruf",  0, 14,  "Detect movement/fire-rate beyond physical limits. Deferred to v2."),
    ("Honeypot integration: Cowrie + Dionaea",         "maruf",  0, 18,  "Already deployed on VPS; pull events into Graylog stream."),
    ("Multi-tenant Graylog (per-customer index sets)", "rahmon", 0, 28,  "Roadmap: when Catnip Games wants 5+ separate tenants."),
    ("Mobile-first SOC view (responsive)",             "roman",  0, 30,  "Optional polish; current desktop layout is acceptable."),
]

BUCKET_NAMES = ["Backlog", "Todo", "Doing", "Review", "Done"]


def req(method, path, token=None, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return e.code, body


def login(username):
    code, data = req("POST", "/login", body={"username": username, "password": PASSWORD})
    if code == 200 and isinstance(data, dict): return data["token"]
    print(f"  ! login {username} failed: {code} {data}", file=sys.stderr)
    return None


def register(username, email):
    code, data = req("POST", "/register", body={
        "username": username, "email": email, "password": PASSWORD,
    })
    if code == 200: return True
    if "already" in str(data).lower() or "exists" in str(data).lower(): return True
    print(f"  ! register {username}: {code} {data}", file=sys.stderr)
    return False


def main():
    print("→ registering 5 team accounts")
    for u, name, email, role in TEAM:
        register(u, email)
        print(f"   · {u}  ({role})")

    roman_tok = login("roman")
    if not roman_tok: sys.exit("cannot proceed without Roman's token")

    # ── update display names ──────────────────────────────────────────────
    for u, name, _, _ in TEAM:
        tok = login(u)
        if not tok: continue
        req("POST", "/user/settings/general", token=tok, body={"name": name})

    # ── one project, owned by Roman ───────────────────────────────────────
    print("→ creating project 'SIEM Arcade — Catnip Games International'")
    code, prj = req("PUT", "/projects", token=roman_tok, body={
        "title":       "SIEM Arcade — Catnip Games International",
        "description": "MSc Security Operations deliverable #4 — full SIEM build, deploy, detect, report.",
        "hex_color":   "c47a67",
    })
    if code != 201:
        # maybe already exists — list and find it
        _, prjs = req("GET", "/projects", token=roman_tok)
        prj = next((p for p in (prjs or []) if "Catnip" in p.get("title","")), None)
    pid = prj["id"]
    print(f"   project id = {pid}")

    # ── add the other 4 as members ────────────────────────────────────────
    # Vikunja v0.24 endpoint: PUT /projects/{id}/users  body={user_id, right}
    print("→ adding members")
    user_ids = {}
    for u, *_ in TEAM:
        code, ud = req("GET", f"/users?s={u}", token=roman_tok)
        user_ids[u] = next((x["id"] for x in (ud or []) if x["username"] == u), None)

    for u, *_ in TEAM:
        if u == "roman": continue
        if not user_ids.get(u):
            print(f"   ! no id for {u}"); continue
        code, _ = req("PUT", f"/projects/{pid}/users", token=roman_tok, body={
            "user_id": u, "right": 2,
        })
        print(f"   · {u} ({code})")

    # ── find the Kanban view and its buckets ──────────────────────────────
    code, views = req("GET", f"/projects/{pid}/views", token=roman_tok)
    kanban = next((v for v in views if v.get("view_kind") == "kanban"), None)
    if not kanban:
        sys.exit(f"no kanban view found on project {pid}: {views}")
    vid = kanban["id"]
    print(f"   kanban view id = {vid}")

    # default Kanban view ships with buckets — fetch them
    code, buckets = req("GET", f"/projects/{pid}/views/{vid}/buckets", token=roman_tok)
    existing = {b["title"]: b["id"] for b in buckets}
    print(f"   existing buckets: {list(existing.keys())}")

    # ensure all 5 columns exist; create missing ones
    bucket_ids = []
    for name in BUCKET_NAMES:
        if name in existing:
            bucket_ids.append(existing[name])
        else:
            code, b = req("PUT", f"/projects/{pid}/views/{vid}/buckets",
                          token=roman_tok, body={"title": name})
            bucket_ids.append(b["id"])
            print(f"   + bucket {name}")

    # delete any leftover default buckets we didn't want (e.g. "To Do", "Doing", "Done")
    for title, bid in existing.items():
        if title not in BUCKET_NAMES:
            req("DELETE", f"/projects/{pid}/views/{vid}/buckets/{bid}", token=roman_tok)
            print(f"   - removed leftover bucket {title}")

    # ── seed tasks (always as Roman to avoid login rate-limit) ────────────
    print(f"→ creating {len(TASKS)} tasks")
    today = datetime.now(timezone.utc).replace(hour=12, minute=0, second=0, microsecond=0)

    for title, owner, bidx, due_off, desc in TASKS:
        due_dt = today + timedelta(days=due_off)
        prio = 4 if bidx == 2 else 3 if bidx == 3 else 2 if bidx == 1 else 1
        code, t = req("PUT", f"/projects/{pid}/tasks", token=roman_tok, body={
            "title":       title,
            "description": desc,
            "due_date":    due_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "priority":    prio,
            "done":        bidx == 4,
            "percent_done": 1.0 if bidx == 4 else 0.7 if bidx == 3 else 0.4 if bidx == 2 else 0.0,
            "bucket_id":   bucket_ids[bidx],
        })
        if not isinstance(t, dict) or "id" not in t:
            print(f"   ! create failed: {title} → {code} {t}")
            continue
        tid = t["id"]
        # ensure bucket placement (POST update)
        req("POST", f"/tasks/{tid}",
            token=roman_tok, body={"bucket_id": bucket_ids[bidx]})
        # assign owner
        if user_ids.get(owner):
            req("PUT", f"/tasks/{tid}/assignees",
                token=roman_tok, body={"user_id": user_ids[owner]})
        flag = "✓" if bidx == 4 else "·"
        print(f"   {flag} [{BUCKET_NAMES[bidx]:7}] {owner:7} {title}")

    print("\n✓ done. Open https://pm.siem-game.co.uk and log in as roman / <REDACTED-PASSWORD>")


if __name__ == "__main__":
    main()
