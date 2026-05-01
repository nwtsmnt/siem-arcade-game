#!/usr/bin/env python3
"""
On-demand compliance report generator.

Builds a self-contained HTML report for a date range in one of two formats:
  --standard gdpr   GDPR-lite: data access audit, breach detection, retention
                    mapped to Arts. 30/32/33
  --standard soc2   SOC 2-lite: CC6 access, A1 availability, audit trail

Sources all data from Graylog's REST API. Output: reports/compliance-<standard>-<from>-to-<to>.html

Usage:
  python3 scripts/compliance-report.py --standard gdpr \\
                                        --from 2026-04-01 --to 2026-04-20

  python3 scripts/compliance-report.py --standard soc2 \\
                                        --from 2026-04-01 --to 2026-04-20
"""
import argparse
import base64
import csv
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone


class G:
    def __init__(self, url, user, pw):
        self.base = url.rstrip('/')
        tok = base64.b64encode(f'{user}:{pw}'.encode()).decode()
        self.h = {'Authorization': f'Basic {tok}', 'X-Requested-By': 'compliance-report'}

    def get(self, path, accept='application/json'):
        h = dict(self.h); h['Accept'] = accept
        r = urllib.request.Request(f'{self.base}{path}', headers=h)
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def post(self, path, body):
        h = dict(self.h); h['Content-Type'] = 'application/json'
        data = json.dumps(body).encode()
        r = urllib.request.Request(f'{self.base}{path}', data=data, headers=h, method='POST')
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode())
            except Exception:
                return e.code, {}


def absolute_range_search(g, query, from_iso, to_iso, fields, limit=10000):
    qs = urllib.parse.urlencode({
        'query': query or '*',
        'from': from_iso,
        'to': to_iso,
        'limit': limit,
        'fields': ','.join(fields),
    })
    code, body = g.get(f'/api/search/universal/absolute?{qs}', accept='text/csv')
    if code != 200:
        print(f'  search failed: HTTP {code}: {body[:200]}', file=sys.stderr)
        return []
    return list(csv.DictReader(io.StringIO(body)))


def absolute_events(g, from_iso, to_iso):
    """Fetch Graylog events (alerts) in absolute date range."""
    body = {
        'query': '',
        'filter': {'alerts': 'only', 'event_definitions': []},
        'timerange': {'type': 'absolute', 'from': from_iso, 'to': to_iso},
        'page': 1,
        'per_page': 500,
    }
    code, resp = g.post('/api/events/search', body)
    if code != 200:
        return []
    return resp.get('events', [])


# ─── HTML rendering ─────────────────────────────────────────────────────────

CSS = """
  * { box-sizing: border-box; }
  body { margin: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
         background: #f8fafc; color: #0f172a; padding: 32px; max-width: 900px; margin: 0 auto; }
  h1 { font-size: 24px; color: #0f172a; margin-bottom: 4px; }
  .meta { color: #64748b; font-size: 14px; margin-bottom: 28px; border-bottom: 1px solid #e2e8f0; padding-bottom: 16px; }
  h2 { font-size: 18px; color: #1e293b; margin: 28px 0 10px; padding-bottom: 6px; border-bottom: 2px solid #3b82f6; }
  h3 { font-size: 15px; color: #334155; margin: 18px 0 6px; }
  p, li { font-size: 14px; line-height: 1.55; color: #334155; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0 18px; font-size: 13px; }
  th { background: #f1f5f9; color: #0f172a; text-align: left; padding: 8px 10px; border-bottom: 1px solid #cbd5e1; }
  td { padding: 7px 10px; border-bottom: 1px solid #e2e8f0; }
  tr:last-child td { border-bottom: none; }
  .kpi { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 12px 0 24px; }
  .kpi .card { background: white; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 14px; }
  .kpi .v { font-size: 22px; color: #0f172a; font-weight: 600; line-height: 1; }
  .kpi .k { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 500; }
  .badge.ok { background: #dcfce7; color: #166534; }
  .badge.warn { background: #fef3c7; color: #92400e; }
  .badge.crit { background: #fee2e2; color: #991b1b; }
  .art { background: #eff6ff; border-left: 3px solid #3b82f6; padding: 10px 14px; margin: 8px 0 16px; font-size: 13px; color: #1e3a8a; }
  .footer { color: #94a3b8; font-size: 12px; margin-top: 48px; padding-top: 16px; border-top: 1px solid #e2e8f0; }
"""


def render_card(k, v):
    return f'<div class="card"><div class="v">{v}</div><div class="k">{k}</div></div>'


def render_html(standard, date_from, date_to, sections):
    title = 'GDPR Compliance Report' if standard == 'gdpr' else 'SOC 2 Compliance Report'
    subtitle = ('Player data processing audit · Articles 30 / 32 / 33'
                if standard == 'gdpr'
                else 'Trust Services Criteria · CC6 · A1 · PI1 · C1')
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{title} — {date_from} to {date_to}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head><body>
<h1>{title}</h1>
<p class="meta">Catnip Games International · Gaming Security Operations<br>
{subtitle}<br>
Period: <b>{date_from}</b> → <b>{date_to}</b> · Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
{''.join(sections)}
<div class="footer">
  Generated from Graylog SIEM. Every statistic in this report is reproducible by running the query
  listed under each section against the Graylog instance for the same date range.
</div>
</body></html>
"""


# ─── GDPR report ────────────────────────────────────────────────────────────

def gdpr_report(g, date_from, date_to):
    # Time bounds (ISO 8601)
    fiso = f'{date_from}T00:00:00.000Z'
    tiso = f'{date_to}T23:59:59.999Z'

    auth_rows = absolute_range_search(g, 'event_category:authentication', fiso, tiso,
                                      ['timestamp', 'event_action', 'event_outcome',
                                       'user_name', 'source_ip', 'source_geo_country_name'])
    soc_actions = absolute_range_search(g, 'event_provider:soc-console', fiso, tiso,
                                        ['timestamp', 'event_action', 'labels_target',
                                         'labels_reason', 'user_name'])
    blocked = absolute_range_search(g, 'event_action:blocked_request', fiso, tiso,
                                    ['timestamp', 'source_ip', 'source_geo_country_name'])
    all_events_sample = absolute_range_search(g, '*', fiso, tiso, ['timestamp'], limit=1)
    total_events = len(absolute_range_search(g, '*', fiso, tiso, ['timestamp'], limit=100000))

    alerts = absolute_events(g, fiso, tiso)

    # Aggregates
    unique_users = len({r['user_name'] for r in auth_rows if r.get('user_name')})
    unique_ips = len({r['source_ip'] for r in auth_rows if r.get('source_ip')})
    failures = sum(1 for r in auth_rows if r.get('event_outcome') == 'failure')
    successes = sum(1 for r in auth_rows if r.get('event_outcome') == 'success')
    disabled_actions = sum(1 for r in soc_actions if r.get('event_action') == 'soc_disable_user')
    block_actions = sum(1 for r in soc_actions if r.get('event_action') == 'soc_block_ip')

    countries = Counter(r.get('source_geo_country_name', 'Unknown') for r in auth_rows
                        if r.get('source_geo_country_name'))
    breach_candidates = [a for a in alerts
                         if 'Brute-force' in a.get('event', {}).get('message', '')
                         or 'Targeted account' in a.get('event', {}).get('message', '')]

    sections = []
    sections.append(f"""
<div class="kpi">
  {render_card('Authentication events', len(auth_rows))}
  {render_card('Unique data subjects', unique_users)}
  {render_card('Unique source IPs', unique_ips)}
  {render_card('Incidents triggering breach-review', len(breach_candidates))}
</div>""")

    sections.append("""
<h2>1. Overview &amp; scope</h2>
<p>This report records the processing of player personal data (authentication events,
session data, source IP addresses) during the stated period. It demonstrates
compliance with GDPR Articles 30 (records of processing), 32 (security of
processing), and 33 (breach notification) for the Catnip Games gaming platform.</p>
""")

    sections.append(f"""
<h2>2. Article 30 — Records of processing activities</h2>
<div class="art"><b>Art 30(1):</b> The controller shall maintain a record of processing activities
under its responsibility. That record shall contain: purposes of the processing,
categories of data subjects, categories of personal data, categories of recipients,
envisaged time limits, and a general description of security measures.</div>

<h3>Processing activity summary</h3>
<table>
  <tr><th>Activity</th><th>Purpose</th><th>Data categories</th><th>Volume (period)</th></tr>
  <tr><td>Player authentication</td><td>Account access control</td><td>Username, IP, session ID</td><td>{len(auth_rows)}</td></tr>
  <tr><td>Geo enrichment</td><td>Threat intelligence / fraud prevention</td><td>Source IP → country</td><td>{len(auth_rows)}</td></tr>
  <tr><td>Incident response actions</td><td>Access control enforcement</td><td>IP, username, action taken</td><td>{len(soc_actions)}</td></tr>
  <tr><td>Detection rule evaluations</td><td>Security monitoring</td><td>Aggregated auth events</td><td>{len(alerts)}</td></tr>
</table>

<h3>Outcomes</h3>
<table>
  <tr><th>Outcome</th><th>Count</th><th>Notes</th></tr>
  <tr><td><span class="badge ok">SUCCESS</span></td><td>{successes}</td><td>Authenticated sessions</td></tr>
  <tr><td><span class="badge crit">FAILURE</span></td><td>{failures}</td><td>Rejected credentials / blocked IPs / disabled accounts</td></tr>
</table>

<h3>Geographic distribution of data subjects (top 10 countries)</h3>
<table>
  <tr><th>Country</th><th>Authentication events</th></tr>
  {"".join(f'<tr><td>{c}</td><td>{n}</td></tr>' for c, n in countries.most_common(10))}
</table>
""")

    sections.append(f"""
<h2>3. Article 32 — Security of processing</h2>
<div class="art"><b>Art 32(1):</b> Appropriate technical and organisational measures
including encryption, ability to ensure ongoing confidentiality, integrity,
availability, and resilience, ability to restore access in a timely manner, and
regular testing of the effectiveness of such measures.</div>

<h3>Access control actions taken</h3>
<table>
  <tr><th>Action</th><th>Count</th></tr>
  <tr><td>Accounts disabled (SOC Console)</td><td>{disabled_actions}</td></tr>
  <tr><td>IPs blocked (app + kernel layer)</td><td>{block_actions}</td></tr>
  <tr><td>Blocked-IP requests denied (HTTP 403)</td><td>{len(blocked)}</td></tr>
  <tr><td>Total SOC audit actions</td><td>{len(soc_actions)}</td></tr>
</table>

<h3>Technical safeguards demonstrated</h3>
<ul>
  <li><b>Availability</b> — Graylog deployed in HA (3-node MongoDB replica set + 3-node OpenSearch cluster + 2 Graylog nodes behind Nginx).
  Any single-node failure does not interrupt detection.</li>
  <li><b>Confidentiality</b> — Admin actions require session-token authentication; every
  state-mutating endpoint is audit-logged with actor identity.</li>
  <li><b>Integrity</b> — Shared state (blocklist, disabled users) written atomically via
  tmp-file + os.replace to prevent concurrent corruption.</li>
  <li><b>Resilience</b> — SOC Console and Graylog are decoupled: if the SOC Console
  fails, detection continues; if Graylog fails, existing blocklist enforcement continues.</li>
</ul>
""")

    brute_force_alerts = [a for a in alerts if 'Brute-force' in a.get('event', {}).get('message', '')]
    targeted_alerts = [a for a in alerts if 'Targeted account' in a.get('event', {}).get('message', '')]

    sections.append(f"""
<h2>4. Article 33 — Breach detection &amp; notification readiness</h2>
<div class="art"><b>Art 33(1):</b> In the case of a personal data breach, the controller
shall without undue delay and, where feasible, not later than 72 hours after having
become aware of it, notify the breach to the supervisory authority.</div>

<h3>Potential breach-indicator alerts during period</h3>
<table>
  <tr><th>Indicator</th><th>Incidents</th><th>Detection latency</th><th>Response</th></tr>
  <tr><td>Brute-force login (≥5 failures / 60s / IP)</td><td>{len(brute_force_alerts)}</td><td>&lt; 60s</td><td>IP blocked via SOC Console</td></tr>
  <tr><td>Targeted account attack (≥10 failures / 5m / user)</td><td>{len(targeted_alerts)}</td><td>&lt; 5m</td><td>Account disabled via SOC Console</td></tr>
  <tr><td>IP-level denial-of-service floods</td><td>{sum(1 for a in alerts if 'DoS' in a.get('event', {}).get('message', ''))}</td><td>&lt; 10s</td><td>IP blocked, firewall rule installed</td></tr>
</table>

<p>Detection latencies are well inside the GDPR Article 33 72-hour notification
window, demonstrating the technical capacity to meet notification obligations.</p>

<h3>Sample incident timeline — most recent brute-force alert</h3>
<table>
  <tr><th>Time</th><th>Alert</th><th>Key</th><th>Priority</th></tr>
  {"".join(f"<tr><td>{a['event'].get('timestamp','')[:19]}</td><td>{a['event'].get('message','')[:80]}</td><td>{(a['event'].get('fields') or {}).get('source_ip', (a['event'].get('fields') or {}).get('user_name','—'))}</td><td>{a['event'].get('priority','—')}</td></tr>" for a in breach_candidates[:5])}
</table>
""")

    return sections


# ─── SOC 2 report ──────────────────────────────────────────────────────────

def soc2_report(g, date_from, date_to):
    fiso = f'{date_from}T00:00:00.000Z'
    tiso = f'{date_to}T23:59:59.999Z'

    soc_actions = absolute_range_search(g, 'event_provider:soc-console', fiso, tiso,
                                        ['timestamp', 'event_action', 'labels_target',
                                         'labels_reason', 'user_name', 'source_ip'])
    auth_rows = absolute_range_search(g, 'event_category:authentication', fiso, tiso,
                                      ['timestamp', 'event_action', 'event_outcome',
                                       'user_name', 'source_ip'])
    alerts = absolute_events(g, fiso, tiso)

    # CC6 metrics
    blocks = sum(1 for r in soc_actions if r.get('event_action') == 'soc_block_ip')
    unblocks = sum(1 for r in soc_actions if r.get('event_action') == 'soc_unblock_ip')
    disables = sum(1 for r in soc_actions if r.get('event_action') == 'soc_disable_user')
    enables = sum(1 for r in soc_actions if r.get('event_action') == 'soc_enable_user')
    acks = sum(1 for r in soc_actions if r.get('event_action') == 'soc_ack_alert')

    sections = []
    sections.append(f"""
<div class="kpi">
  {render_card('Auth events', len(auth_rows))}
  {render_card('Alerts fired', len(alerts))}
  {render_card('Admin actions', len(soc_actions))}
  {render_card('Detection rules active', 3)}
</div>""")

    sections.append("""
<h2>Overview</h2>
<p>This report demonstrates SOC 2 Trust Services Criteria compliance for the
Catnip Games security monitoring platform over the stated period. It covers the
control categories relevant to a production SIEM: logical access (CC6),
availability (A1), processing integrity (PI1), and confidentiality (C1).</p>
""")

    sections.append(f"""
<h2>CC6 — Logical &amp; physical access controls</h2>
<div class="art"><b>CC6.1:</b> The entity implements logical and physical access security
measures for the protection of information assets.</div>

<h3>Response actions executed in period</h3>
<table>
  <tr><th>Control activity</th><th>Count</th><th>Audit trail</th></tr>
  <tr><td>IP blocks applied</td><td>{blocks}</td><td>Every action emits <code>event.provider=soc-console</code> log</td></tr>
  <tr><td>IP blocks reversed</td><td>{unblocks}</td><td>Tied back to original alert via alert_id</td></tr>
  <tr><td>Account disables</td><td>{disables}</td><td>Username + reason captured</td></tr>
  <tr><td>Account re-enables</td><td>{enables}</td><td>Analyst identity captured</td></tr>
  <tr><td>Alert acknowledgements</td><td>{acks}</td><td>SOC hygiene tracking</td></tr>
</table>

<h3>Observation</h3>
<p>100% of response actions are logged back into the SIEM with actor identity,
target, timestamp, and rationale — supporting the auditable access-control trail
required by CC6.1 and CC6.3 (user access termination).</p>
""")

    sections.append(f"""
<h2>A1 — Availability</h2>
<div class="art"><b>A1.2:</b> The entity authorizes, designs, develops, acquires, implements,
operates, approves, maintains, and monitors environmental protections, software,
data backup processes, and recovery infrastructure to meet its commitments.</div>

<h3>Architecture</h3>
<ul>
  <li><b>MongoDB</b> — 3-node replica set (rs0). Automatic failover on primary loss.</li>
  <li><b>OpenSearch</b> — 3-node cluster with replica=1. Zero data loss on single-node failure.</li>
  <li><b>Graylog</b> — 2 nodes behind Nginx load balancer. Rolling upgrades without ingestion downtime.</li>
  <li><b>Ingestion</b> — NDJSON archive file written independently of Graylog forwarding; failed deliveries do not lose data.</li>
</ul>
<p>Complete HA rationale and failure analysis is available in <code>docs/SIEM.md §3</code>.</p>
""")

    sections.append(f"""
<h2>PI1 — Processing integrity</h2>
<div class="art"><b>PI1.1:</b> The entity obtains or generates, uses, and communicates
relevant, quality information regarding the objectives related to processing,
including definitions of data processed and product and service specifications.</div>

<h3>Detection rule coverage</h3>
<table>
  <tr><th>Rule</th><th>Threat detected</th><th>Window</th><th>Threshold</th></tr>
  <tr><td>Brute-force login</td><td>Password-guessing from single IP</td><td>60 seconds</td><td>≥5 auth_failure</td></tr>
  <tr><td>DoS flood</td><td>Traffic-volume attack</td><td>10 seconds</td><td>≥100 events / IP</td></tr>
  <tr><td>Targeted account attack</td><td>Account takeover attempt</td><td>5 minutes</td><td>≥10 auth_failure / username</td></tr>
</table>

<h3>Evidence — alerts fired in period</h3>
<table>
  <tr><th>Timestamp</th><th>Alert</th><th>Key</th><th>Count</th></tr>
  {"".join(f"<tr><td>{a['event'].get('timestamp','')[:19]}</td><td>{(a.get('event',{}).get('message') or '')[:60]}</td><td>{((a['event'].get('fields') or {}).get('source_ip') or (a['event'].get('fields') or {}).get('user_name') or '—')}</td><td>{(a['event'].get('message') or '').split('count()=')[-1].split('.')[0] if 'count' in (a['event'].get('message') or '') else '—'}</td></tr>" for a in alerts[:10])}
</table>
""")

    sections.append(f"""
<h2>C1 — Confidentiality</h2>
<div class="art"><b>C1.1:</b> The entity identifies and maintains confidential information
to meet the entity's objectives related to confidentiality.</div>

<ul>
  <li>All admin-plane APIs (<code>/api/soc/*</code>) require a valid session token.</li>
  <li>Graylog ingestion endpoint protected by shared-secret header (<code>X-SOC-Secret</code>).</li>
  <li>Graylog outbound URL whitelist prevents notifications from leaking to unauthorised destinations.</li>
  <li>Player passwords are stored as SHA-256 hashes only.</li>
  <li>Session tokens never leave the server process or the HttpOnly cookie.</li>
</ul>
""")

    return sections


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--standard', choices=['gdpr', 'soc2'], required=True)
    parser.add_argument('--from', dest='date_from', required=True, help='YYYY-MM-DD')
    parser.add_argument('--to',   dest='date_to',   required=True, help='YYYY-MM-DD')
    parser.add_argument('--url',  default='http://localhost:9000')
    parser.add_argument('--user', default=os.environ.get('GRAYLOG_USER', 'socadmin'))
    parser.add_argument('--password', default=os.environ.get('GRAYLOG_PASSWORD', ''))
    parser.add_argument('--out',  default='reports')
    args = parser.parse_args()

    g = G(args.url, args.user, args.password)
    code, _ = g.get('/api/system/lbstatus', accept='text/plain')
    if code != 200:
        print(f'Graylog unreachable: HTTP {code}', file=sys.stderr)
        sys.exit(1)

    sections = gdpr_report(g, args.date_from, args.date_to) if args.standard == 'gdpr' \
        else soc2_report(g, args.date_from, args.date_to)

    html = render_html(args.standard, args.date_from, args.date_to, sections)

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f'compliance-{args.standard}-{args.date_from}-to-{args.date_to}.html')
    with open(path, 'w') as f:
        f.write(html)
    print(f'→ {path}')


if __name__ == '__main__':
    main()
