#!/usr/bin/env python3
"""
Daily HTML security report — queries Graylog for the last 24 hours and
renders a styled HTML summary suitable for screen-sharing or attaching.

What's in the report:
  • Summary cards — total events, auth success/fail counts, unique users/IPs, alert count
  • Hourly activity bar chart (embedded SVG, no JS)
  • Top 10 source IPs + top 10 users
  • Firing events (brute-force, DoS flood, etc.) with details
  • Events-by-category pie (ASCII-style legend table)

Usage:
  python3 scripts/daily-report.py [--url http://localhost:9000] \\
                                   [--user socadmin] [--password <REDACTED-PASSWORD>] \\
                                   [--out reports/] [--hours 24]

Cron example (midnight daily):
  0 0 * * * /usr/bin/python3 /path/to/scripts/daily-report.py --out /var/log/reports
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
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta


class G:
    def __init__(self, url, user, pw):
        self.base = url.rstrip('/')
        tok = base64.b64encode(f'{user}:{pw}'.encode()).decode()
        self.h = {'Authorization': f'Basic {tok}', 'X-Requested-By': 'daily-report'}

    def _req(self, method, path, body=None, accept='application/json'):
        headers = dict(self.h)
        headers['Accept'] = accept
        if body is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(body).encode()
        else:
            data = None
        r = urllib.request.Request(f'{self.base}{path}', data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def search_csv(self, query, range_s, fields):
        qs = urllib.parse.urlencode({
            'query': query,
            'range': range_s,
            'limit': 10000,
            'fields': ','.join(fields),
        })
        code, body = self._req('GET', f'/api/search/universal/relative?{qs}', accept='text/csv')
        if code != 200:
            print(f'search_csv HTTP {code}: {body[:200]}', file=sys.stderr)
            return []
        rows = list(csv.DictReader(io.StringIO(body)))
        return rows

    def events_json(self, range_s, alerts_only=True):
        body = {
            'query': '',
            'filter': {'alerts': 'only' if alerts_only else 'include', 'event_definitions': []},
            'timerange': {'type': 'relative', 'range': range_s},
            'page': 1,
            'per_page': 500,
        }
        code, resp = self._req('POST', '/api/events/search', body=body)
        if code != 200:
            return []
        return json.loads(resp).get('events', [])


# ─── Aggregation helpers ────────────────────────────────────────────────────

def parse_ts(s):
    # Graylog returns timestamps like "2026-04-20T12:47:59.108Z"
    try:
        return datetime.fromisoformat(s.replace('Z', '+00:00'))
    except Exception:
        return None


def hourly_buckets(rows, hours):
    now = datetime.now(timezone.utc)
    buckets = [0] * hours
    for r in rows:
        t = parse_ts(r.get('timestamp', ''))
        if not t:
            continue
        delta_h = int((now - t).total_seconds() // 3600)
        if 0 <= delta_h < hours:
            buckets[hours - 1 - delta_h] += 1
    return buckets


# ─── SVG rendering ──────────────────────────────────────────────────────────

def svg_bar_chart(values, labels, title='', width=780, height=180):
    max_v = max(values) if values else 1
    if max_v == 0:
        max_v = 1
    pad_l, pad_r, pad_t, pad_b = 40, 10, 20, 30
    inner_w = width - pad_l - pad_r
    inner_h = height - pad_t - pad_b
    bar_w = inner_w / max(len(values), 1) * 0.8
    gap = inner_w / max(len(values), 1) * 0.2

    bars = []
    for i, v in enumerate(values):
        x = pad_l + i * (bar_w + gap) + gap / 2
        h = (v / max_v) * inner_h if v else 0
        y = pad_t + inner_h - h
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" fill="#5af78e"/>')
        if v > 0 and len(values) <= 24:
            bars.append(f'<text x="{x + bar_w/2:.1f}" y="{y-3:.1f}" fill="#e0e0e0" '
                        f'font-size="9" text-anchor="middle">{v}</text>')

    x_labels = []
    every = max(1, len(labels) // 12)
    for i, lab in enumerate(labels):
        if i % every == 0:
            x = pad_l + i * (bar_w + gap) + gap / 2 + bar_w / 2
            x_labels.append(f'<text x="{x:.1f}" y="{height - 8}" fill="#a0a0a0" '
                            f'font-size="10" text-anchor="middle">{lab}</text>')

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="{height}">
  <rect x="0" y="0" width="{width}" height="{height}" fill="#0d0d0d"/>
  <text x="10" y="15" fill="#5af78e" font-size="12" font-weight="bold">{title}</text>
  <line x1="{pad_l}" y1="{pad_t + inner_h}" x2="{width - pad_r}" y2="{pad_t + inner_h}" stroke="#333" stroke-width="1"/>
  {''.join(bars)}
  {''.join(x_labels)}
</svg>'''


# ─── HTML rendering ─────────────────────────────────────────────────────────

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>SIEM Daily Security Report — {date}</title>
<style>
  body {{ background: #0d0d0d; color: #e0e0e0; font-family: "Consolas", "Menlo", monospace; margin: 0; padding: 24px; }}
  h1 {{ color: #5af78e; font-size: 22px; border-bottom: 1px solid #333; padding-bottom: 6px; }}
  h2 {{ color: #5af78e; font-size: 16px; margin-top: 28px; border-bottom: 1px dashed #333; padding-bottom: 4px; }}
  .meta {{ color: #888; font-size: 12px; margin-bottom: 20px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }}
  .card {{ background: #1a1a1a; border-left: 3px solid #5af78e; padding: 12px 16px; min-width: 160px; }}
  .card.warn {{ border-left-color: #f7a85a; }}
  .card.alert {{ border-left-color: #f75a5a; }}
  .card .v {{ font-size: 26px; font-weight: bold; color: #fff; }}
  .card .k {{ font-size: 11px; text-transform: uppercase; color: #888; letter-spacing: 1px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #333; padding: 6px 10px; text-align: left; }}
  th {{ background: #1a1a1a; color: #5af78e; }}
  tr:hover {{ background: #1a1a1a; }}
  .muted {{ color: #888; }}
  .pill {{ display: inline-block; padding: 1px 8px; border-radius: 10px; background: #333; font-size: 11px; }}
  .pill.high {{ background: #7a1a1a; color: #fff; }}
  .pill.med  {{ background: #7a5a1a; color: #fff; }}
  .pill.low  {{ background: #1a7a2a; color: #fff; }}
  .footer {{ color: #666; font-size: 11px; margin-top: 40px; border-top: 1px solid #333; padding-top: 10px; }}
</style>
</head><body>
<h1>SIEM Daily Security Report</h1>
<div class="meta">
  Window: <b>{start}</b> → <b>{end}</b> ({hours}h)<br>
  Generated: {generated} · Source: Graylog @ {graylog_url}
</div>

<div class="cards">
  <div class="card"><div class="k">Total events</div><div class="v">{total_events}</div></div>
  <div class="card"><div class="k">Unique users</div><div class="v">{unique_users}</div></div>
  <div class="card"><div class="k">Unique IPs</div><div class="v">{unique_ips}</div></div>
  <div class="card"><div class="k">Auth success</div><div class="v">{auth_success}</div></div>
  <div class="card warn"><div class="k">Auth failures</div><div class="v">{auth_failure}</div></div>
  <div class="card alert"><div class="k">Alerts fired</div><div class="v">{alert_count}</div></div>
</div>

<h2>Activity — hourly events over the window</h2>
{hourly_svg}

<h2>Top 10 source IPs (by event count)</h2>
<table><thead><tr><th>Source IP</th><th>Events</th><th>Auth failures</th></tr></thead><tbody>
{top_ips_rows}
</tbody></table>

<h2>Top 10 users (by activity)</h2>
<table><thead><tr><th>User</th><th>Events</th><th>Last seen</th></tr></thead><tbody>
{top_users_rows}
</tbody></table>

<h2>Events by category</h2>
<table><thead><tr><th>Category</th><th>Events</th><th>%</th></tr></thead><tbody>
{category_rows}
</tbody></table>

<h2>Firing alerts</h2>
{alerts_html}

<div class="footer">
  Report covers the last {hours} hours. Generated by scripts/daily-report.py.
  Alert definitions, detection thresholds, and dashboard queries are version-controlled
  in this repo; see <code>docs/SIEM.md</code> for the architecture walk-through.
</div>
</body></html>
'''


def severity_pill(priority):
    if priority and priority >= 3: return '<span class="pill high">HIGH</span>'
    if priority and priority >= 2: return '<span class="pill med">MED</span>'
    return '<span class="pill low">LOW</span>'


def render_report(rows_all, rows_auth, alerts, hours, graylog_url):
    total_events = len(rows_all)
    users = Counter()
    ips = Counter()
    ip_failures = Counter()
    user_last_seen = {}
    auth_success = 0
    auth_failure = 0
    categories = Counter()

    for r in rows_all:
        u = (r.get('user_name') or '').strip()
        ip = (r.get('source_ip') or '').strip()
        cat = (r.get('event_category') or '').strip() or 'uncategorized'
        ts = r.get('timestamp') or ''
        if u:
            users[u] += 1
            if ts > user_last_seen.get(u, ''):
                user_last_seen[u] = ts
        if ip:
            ips[ip] += 1
        categories[cat] += 1

    for r in rows_auth:
        action = r.get('event_action', '')
        outcome = r.get('event_outcome', '')
        ip = (r.get('source_ip') or '').strip()
        if action == 'auth_failure' or outcome == 'failure':
            auth_failure += 1
            if ip:
                ip_failures[ip] += 1
        elif action == 'user_login' and outcome == 'success':
            auth_success += 1

    # Top tables
    top_ips_rows = '\n'.join(
        f'<tr><td>{ip}</td><td>{ips[ip]}</td><td>{ip_failures.get(ip,0)}</td></tr>'
        for ip, _ in ips.most_common(10)
    ) or '<tr><td colspan="3" class="muted">No activity</td></tr>'

    top_users_rows = '\n'.join(
        f'<tr><td>{u}</td><td>{users[u]}</td><td class="muted">{user_last_seen.get(u,"")[:19]}</td></tr>'
        for u, _ in users.most_common(10)
    ) or '<tr><td colspan="3" class="muted">No user activity</td></tr>'

    cat_total = sum(categories.values()) or 1
    category_rows = '\n'.join(
        f'<tr><td>{c}</td><td>{n}</td><td>{100*n/cat_total:.1f}%</td></tr>'
        for c, n in categories.most_common(10)
    ) or '<tr><td colspan="3" class="muted">No events</td></tr>'

    # Alerts
    if alerts:
        alert_rows = '\n'.join(
            f'<tr>'
            f'<td>{severity_pill(a.get("event",{}).get("priority"))}</td>'
            f'<td>{(a.get("event",{}).get("timestamp") or "")[:19]}</td>'
            f'<td>{a.get("event",{}).get("event_definition_id","")[:8]}</td>'
            f'<td>{a.get("event",{}).get("message","")}</td>'
            f'<td class="muted">{json.dumps(a.get("event",{}).get("fields",{}))}</td>'
            f'</tr>'
            for a in alerts
        )
        alerts_html = (
            f'<table><thead><tr><th>Severity</th><th>Time</th><th>Def</th>'
            f'<th>Message</th><th>Fields</th></tr></thead>'
            f'<tbody>{alert_rows}</tbody></table>'
        )
    else:
        alerts_html = '<p class="muted">No alerts fired in this window.</p>'

    # Hourly chart
    buckets = hourly_buckets(rows_all, hours)
    now_h = datetime.now(timezone.utc).hour
    labels = [f'{(now_h - (hours - 1 - i)) % 24:02d}:00' for i in range(hours)]
    hourly_svg = svg_bar_chart(buckets, labels,
                               title=f'Events per hour — last {hours}h (peak: {max(buckets) if buckets else 0})')

    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    return HTML_TEMPLATE.format(
        date=now.strftime('%Y-%m-%d'),
        start=start.strftime('%Y-%m-%d %H:%M UTC'),
        end=now.strftime('%Y-%m-%d %H:%M UTC'),
        hours=hours,
        generated=now.strftime('%Y-%m-%d %H:%M:%S UTC'),
        graylog_url=graylog_url,
        total_events=total_events,
        unique_users=len(users),
        unique_ips=len(ips),
        auth_success=auth_success,
        auth_failure=auth_failure,
        alert_count=len(alerts),
        hourly_svg=hourly_svg,
        top_ips_rows=top_ips_rows,
        top_users_rows=top_users_rows,
        category_rows=category_rows,
        alerts_html=alerts_html,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://localhost:9000')
    parser.add_argument('--user', default='socadmin')
    parser.add_argument('--password', default='<REDACTED-PASSWORD>')
    parser.add_argument('--out', default='reports', help='Output directory (default: reports/)')
    parser.add_argument('--hours', type=int, default=24, help='Reporting window in hours (default: 24)')
    args = parser.parse_args()

    g = G(args.url, args.user, args.password)
    range_s = args.hours * 3600

    print(f'Pulling last {args.hours}h from {args.url} ...')
    all_fields = ['timestamp', 'source', 'message', 'event_action', 'event_category',
                  'event_outcome', 'user_name', 'source_ip', 'log_level']
    rows_all = g.search_csv('*', range_s, all_fields)
    rows_auth = [r for r in rows_all if 'authentication' in (r.get('event_category') or '')
                 or r.get('event_action') in ('user_login', 'auth_failure', 'user_register')]
    alerts = g.events_json(range_s, alerts_only=True)
    print(f'  {len(rows_all)} events, {len(rows_auth)} auth-related, {len(alerts)} alerts')

    html = render_report(rows_all, rows_auth, alerts, args.hours, args.url)

    os.makedirs(args.out, exist_ok=True)
    date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    out_path = os.path.join(args.out, f'daily-{date}.html')
    with open(out_path, 'w') as f:
        f.write(html)
    print(f'\n→ {out_path}')


if __name__ == '__main__':
    main()
