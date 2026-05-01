#!/usr/bin/env python3
"""
Provision Graylog dashboards (Views) via the REST API.

Creates two dashboards:
  • Security Overview  — auth activity, top offenders, alert stream, 24h timeline
  • Game Server Health — event rate, categories, user activity, session counts

Idempotent: deletes and recreates any view with a matching title.

Usage:
  python3 scripts/provision-dashboards.py [--url http://localhost:9000] \\
                                           [--user <user>] [--password <password>]
"""
import argparse
import base64
import json
import os
import sys
import uuid
import urllib.error
import urllib.request


def uid():
    return str(uuid.uuid4())


class G:
    def __init__(self, url, user, pw):
        self.base = url.rstrip('/')
        tok = base64.b64encode(f'{user}:{pw}'.encode()).decode()
        self.h = {'Authorization': f'Basic {tok}', 'X-Requested-By': 'provision-dashboards',
                  'Content-Type': 'application/json'}

    def _req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(f'{self.base}{path}', data=data, headers=self.h, method=method)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                t = resp.read().decode()
                return resp.status, json.loads(t) if t and t[0] in '{[' else t
        except urllib.error.HTTPError as e:
            t = e.read().decode()
            try:
                return e.code, json.loads(t)
            except Exception:
                return e.code, t

    def get(self, p): return self._req('GET', p)
    def post(self, p, b): return self._req('POST', p, b)
    def delete(self, p): return self._req('DELETE', p)


# ─── Widget builders ────────────────────────────────────────────────────────

def agg_widget(title, query, series, row_pivots=None, viz='numeric', row_limit=None, timerange_s=86400):
    return {
        'id': uid(),
        'type': 'aggregation',
        'filter': None,
        'filters': [],
        'timerange': {'range': timerange_s, 'type': 'relative'},
        'query': {'type': 'elasticsearch', 'query_string': query} if query else None,
        'streams': [],
        'stream_categories': [],
        'config': {
            'row_pivots': row_pivots or [],
            'column_pivots': [],
            'series': series,
            'sort': [],
            'visualization': viz,
            'visualization_config': None,
            'formatting_settings': None,
            'rollup': True,
            'event_annotation': False,
            'units': {},
            'column_limit': None,
            'row_limit': row_limit,
        },
    }


def message_widget(title, query, fields, limit=50, timerange_s=86400):
    return {
        'id': uid(),
        'type': 'messages',
        'filter': None,
        'filters': [],
        'timerange': {'range': timerange_s, 'type': 'relative'},
        'query': {'type': 'elasticsearch', 'query_string': query} if query else None,
        'streams': [],
        'stream_categories': [],
        'config': {
            'fields': fields,
            'show_message_row': True,
            'show_summary': False,
            'decorators': [],
            'sort': [{'type': 'pivot', 'field': 'timestamp', 'direction': 'Descending'}],
        },
        '_limit': limit,  # internal marker — copied to search_type, stripped before sending widget
    }


def count_series(name='events'):
    return [{'config': {'name': name}, 'function': 'count()'}]


def values_pivot(field, limit=10):
    return [{'fields': [field], 'type': 'values', 'config': {'limit': limit}}]


_SHORTHAND_SECONDS = {'1m': 60, '5m': 300, '15m': 900, '30m': 1800, '1h': 3600, '6h': 21600, '1d': 86400}


def time_pivot(shorthand='1h'):
    """shorthand: '1m', '5m', '30m', '1h', '1d' — widget shape; converted for search shape."""
    return [{'fields': ['timestamp'], 'type': 'time',
             'config': {'interval': {'type': 'timeunit',
                                     'value': _SHORTHAND_SECONDS[shorthand],
                                     'unit': 'seconds',
                                     'shorthand': shorthand}}}]


# ─── Layout helper ──────────────────────────────────────────────────────────

def grid_positions(widget_defs, cols=2):
    """Lay widgets out in a 2-col grid. Widget ids are the keys."""
    positions = {}
    for i, w in enumerate(widget_defs):
        row = (i // cols) * 4 + 1
        col = (i % cols) * 6 + 1
        positions[w['id']] = {'col': col, 'row': row, 'height': 4, 'width': 6}
    return positions


# ─── Dashboard creation ─────────────────────────────────────────────────────

def _pivot_to_search(p):
    """Widget pivot shape -> search_type row_group shape (flat)."""
    out = {'type': p['type'], 'fields': p['fields']}
    cfg = p.get('config', {})
    if p['type'] == 'values':
        out['limit'] = cfg.get('limit', 15)
        out['skip_empty_values'] = cfg.get('skip_empty_values', False)
    elif p['type'] == 'time':
        iv = cfg.get('interval', {})
        if iv.get('type') == 'timeunit':
            out['interval'] = {'type': 'timeunit', 'timeunit': iv['shorthand']}
        else:
            out['interval'] = {'type': 'auto', 'scaling': iv.get('scaling', 1.0)}
    return out


def _series_to_search(s):
    """Widget series -> search_type series. Drop 'config', fold name into id."""
    return {
        'type': (s.get('function') or '').split('(')[0] or 'count',
        'id': s.get('config', {}).get('name') or s.get('function', 'count()'),
        'field': (s.get('function', '').split('(')[1].rstrip(')') or None) if '(' in s.get('function', '') else None,
    }


def _search_type(w):
    """Build the search_type JSON — different shape for pivot vs messages."""
    base = {
        'id': w['id'],
        'timerange': w.get('timerange'),
        'query': w.get('query'),
        'streams': [],
        'stream_categories': [],
        'filter': None,
        'filters': [],
    }
    if w['type'] == 'aggregation':
        base.update({
            'type': 'pivot',
            'row_groups': [_pivot_to_search(p) for p in w['config'].get('row_pivots', [])],
            'column_groups': [_pivot_to_search(p) for p in w['config'].get('column_pivots', [])],
            'series': [_series_to_search(s) for s in w['config'].get('series', [])],
            'sort': w['config'].get('sort', []),
            'rollup': w['config'].get('rollup', True),
        })
    else:  # messages
        base.update({
            'type': 'messages',
            'fields': w['config'].get('fields', []),
            'limit': w.get('_limit', 50),
            'sort': [{'field': 'timestamp', 'order': 'DESC'}],
        })
    return base


def delete_view_by_title(g, title):
    _, data = g.get('/api/views?per_page=500')
    for v in data.get('views', []):
        if v.get('title') == title:
            print(f'  [delete] existing view "{title}" ({v["id"]})')
            g.delete(f'/api/views/{v["id"]}')


def _strip_widget_extras(widget_defs):
    """Remove our internal keys (_limit, shorthand) so Graylog's widget schema accepts it."""
    def clean_pivot(p):
        cfg = p.get('config', {})
        iv = cfg.get('interval')
        if iv and 'shorthand' in iv:
            iv = {k: v for k, v in iv.items() if k != 'shorthand'}
            cfg = {**cfg, 'interval': iv}
        return {**p, 'config': cfg}
    out = []
    for w in widget_defs:
        w_copy = {k: v for k, v in w.items() if not k.startswith('_')}
        if w['type'] == 'aggregation':
            cfg = dict(w['config'])
            cfg['row_pivots'] = [clean_pivot(p) for p in cfg.get('row_pivots', [])]
            cfg['column_pivots'] = [clean_pivot(p) for p in cfg.get('column_pivots', [])]
            w_copy['config'] = cfg
        out.append(w_copy)
    return out


def create_dashboard(g, title, summary, description, widget_defs, titles):
    delete_view_by_title(g, title)

    query_id = uid()
    widget_ids = [w['id'] for w in widget_defs]
    widgets_clean = _strip_widget_extras(widget_defs)

    # Build a Search entity — one query containing all the widgets via
    # SearchType ids (we use each widget id as a search_type id)
    search = {
        'queries': [{
            'id': query_id,
            'timerange': {'type': 'relative', 'range': 86400},
            'query': {'type': 'elasticsearch', 'query_string': ''},
            'filter': None,
            'filters': [],
            'search_types': [_search_type(w) for w in widget_defs],
        }],
        'parameters': [],
    }
    code, sres = g.post('/api/views/search', search)
    if code >= 300:
        print(f'  [ERROR] search for "{title}": HTTP {code}: {sres}')
        return None
    search_id = sres.get('id')

    # Now build the View
    positions = grid_positions(widget_defs)
    _ = widget_ids  # (kept for debugging)
    widget_mapping = {w['id']: [w['id']] for w in widget_defs}  # widget_id -> [search_type_id]

    view = {
        'type': 'DASHBOARD',
        'title': title,
        'summary': summary,
        'description': description,
        'search_id': search_id,
        'properties': [],
        'requires': {},
        'state': {
            query_id: {
                'selected_fields': None,
                'static_message_list_id': None,
                'titles': {'widget': titles, 'tab': {'title': title}},
                'widgets': widgets_clean,
                'widget_mapping': widget_mapping,
                'positions': positions,
                'formatting': {'highlighting': []},
                'display_mode_settings': {'positions': {}},
            }
        },
    }
    code, vres = g.post('/api/views', view)
    if code >= 300:
        print(f'  [ERROR] view "{title}": HTTP {code}: {vres}')
        return None
    print(f'  [ok]  dashboard "{title}" -> {vres.get("id")}')
    return vres.get('id')


# ─── Dashboard definitions ──────────────────────────────────────────────────

def security_overview(g):
    w1 = agg_widget('Total auth failures (24h)', 'event_action:auth_failure',
                    count_series('failures'), viz='numeric')
    w2 = agg_widget('Successful logins (24h)', 'event_action:user_login AND event_outcome:success',
                    count_series('logins'), viz='numeric')
    w3 = agg_widget('Top offender source IPs (24h)', 'event_action:auth_failure',
                    count_series(), row_pivots=values_pivot('source_ip', 10),
                    viz='table', row_limit=10)
    w4 = agg_widget('Auth failures over time (24h, 1h buckets)', 'event_action:auth_failure',
                    count_series(), row_pivots=time_pivot('1h'),
                    viz='bar')
    w5 = message_widget('Recent auth events (50)', 'event_category:authentication',
                        ['timestamp', 'event_action', 'event_outcome', 'source_ip', 'user_name', 'message'])
    w6 = message_widget('Active alerts', '*',
                        ['timestamp', 'message'], limit=20)

    widgets = [w1, w2, w3, w4, w5, w6]
    titles = {
        w1['id']: 'Auth failures (24h)',
        w2['id']: 'Successful logins (24h)',
        w3['id']: 'Top offender source IPs',
        w4['id']: 'Auth failures timeline',
        w5['id']: 'Recent auth events',
        w6['id']: 'Active alerts',
    }
    return create_dashboard(
        g,
        title='Security Overview',
        summary='Authentication activity, offenders, and active alerts — last 24h',
        description='Custom SIEM dashboard: watch for brute-force, credential stuffing, and account takeover across the siem-arcade-game auth surface.',
        widget_defs=widgets, titles=titles,
    )


def soc_executive(g):
    """Dashboard #1 — SOC Executive Overview (polish).

    One screen for the CISO: what's happening right now, what's the trend,
    who are the top offenders, what's the blast radius.
    """
    w1 = agg_widget('Total events (24h)', '*', count_series(), viz='numeric')
    w2 = agg_widget('Auth failures (24h)',
                    'event_outcome:failure AND event_category:authentication',
                    count_series(), viz='numeric')
    w3 = agg_widget('Distinct source IPs (24h)', '*',
                    [{'config': {'name': 'ips'}, 'function': 'card(source_ip)'}],
                    viz='numeric')
    w4 = agg_widget('Distinct players (24h)',
                    'event_category:gameplay',
                    [{'config': {'name': 'players'}, 'function': 'card(user_name)'}],
                    viz='numeric')
    w5 = agg_widget('Event rate over time (24h, 30m)', '*',
                    count_series(), row_pivots=time_pivot('30m'),
                    viz='line')
    w6 = agg_widget('Events by outcome (24h)', '*',
                    count_series(), row_pivots=values_pivot('event_outcome', 5),
                    viz='pie', row_limit=5)
    w7 = agg_widget('Top 10 source IPs (24h)', '*',
                    count_series(), row_pivots=values_pivot('source_ip', 10),
                    viz='table', row_limit=10)
    w8 = message_widget('Recent auth failures',
                        'event_outcome:failure AND event_category:authentication',
                        fields=['timestamp', 'source_ip', 'user_name', 'message'], limit=20)

    widgets = [w1, w2, w3, w4, w5, w6, w7, w8]
    titles = {w1['id']: 'Total events', w2['id']: 'Auth failures',
              w3['id']: 'Distinct IPs', w4['id']: 'Distinct players',
              w5['id']: 'Event rate over time', w6['id']: 'Outcome mix',
              w7['id']: 'Top source IPs', w8['id']: 'Recent auth failures'}
    return create_dashboard(
        g, title='SOC Executive Overview',
        summary='One-screen CISO view: volume, trends, top offenders — last 24h',
        description='High-level posture dashboard across authentication, gameplay, and infrastructure traffic. Drill into the other dashboards for detail.',
        widget_defs=widgets, titles=titles,
    )


def auth_security(g):
    """Dashboard #2 — Authentication Security.

    Everything about who logged in, who tried to, who got blocked, and from
    where. The single most attack-surface-facing dashboard.
    """
    w1 = agg_widget('Successful logins (24h)',
                    'event_action:user_login AND event_outcome:success',
                    count_series(), viz='numeric')
    w2 = agg_widget('Failed logins (24h)',
                    'event_action:auth_failure',
                    count_series(), viz='numeric')
    w3 = agg_widget('Success vs failure over time (24h, 30m)',
                    'event_category:authentication',
                    count_series(), row_pivots=time_pivot('30m'),
                    viz='line')
    w4 = agg_widget('Top 10 targeted usernames (24h)',
                    'event_action:auth_failure',
                    count_series(), row_pivots=values_pivot('user_name', 10),
                    viz='bar', row_limit=10)
    w5 = agg_widget('Top 10 attacking IPs (24h)',
                    'event_action:auth_failure',
                    count_series(), row_pivots=values_pivot('source_ip', 10),
                    viz='bar', row_limit=10)
    w6 = agg_widget('Failed logins by country (24h)',
                    'event_action:auth_failure',
                    count_series(),
                    row_pivots=values_pivot('source_geo_country_name', 10),
                    viz='pie', row_limit=10)
    w7 = message_widget('Recent auth failures',
                        'event_action:auth_failure',
                        fields=['timestamp', 'source_ip', 'source_geo_country_name',
                                'user_name', 'message'],
                        limit=30)

    widgets = [w1, w2, w3, w4, w5, w6, w7]
    titles = {w1['id']: 'Successful logins', w2['id']: 'Failed logins',
              w3['id']: 'Success vs failure timeline',
              w4['id']: 'Top targeted usernames', w5['id']: 'Top attacking IPs',
              w6['id']: 'Failures by country', w7['id']: 'Recent failures'}
    return create_dashboard(
        g, title='Authentication Security',
        summary='Login success / failure patterns, targeted accounts, attacking IPs — last 24h',
        description='Where the SIEM earns its keep. Brute-force, credential stuffing, targeted-account attack, account takeover all show up here first.',
        widget_defs=widgets, titles=titles,
    )


def threat_detection(g):
    """Dashboard #3 — Threat Detection & Coverage.

    Are our correlation rules actually firing? At what rate? What's the
    dominant attack shape right now? Coverage map across MITRE classes.
    """
    # Message volume that each rule's query matches — proxy for "fired" alerts
    # rate since true alert events live in gl-events_* (outside message index).
    w1 = agg_widget('Brute-force candidates (5 min)',
                    'event_action:auth_failure AND NOT labels_load_test:1',
                    count_series(), viz='numeric', timerange_s=300)
    w2 = agg_widget('DoS candidates (5 min)',
                    'event_category:authentication AND NOT labels_load_test:1',
                    count_series(), viz='numeric', timerange_s=300)
    w3 = agg_widget('Targeted-account candidates (5 min)',
                    'event_action:auth_failure AND NOT labels_load_test:1',
                    [{'config': {'name': 'users'}, 'function': 'card(user_name)'}],
                    viz='numeric', timerange_s=300)
    w4 = agg_widget('Attack-type mix (24h)',
                    '_exists_:labels_attack_type AND NOT labels_load_test:1',
                    count_series(),
                    row_pivots=values_pivot('labels_attack_type', 10),
                    viz='pie', row_limit=10)
    w5 = agg_widget('Attack volume by type over time (24h, 30m)',
                    '_exists_:labels_attack_type AND NOT labels_load_test:1',
                    count_series(),
                    row_pivots=time_pivot('30m') + values_pivot('labels_attack_type', 5),
                    viz='line')
    w6 = agg_widget('Top 10 attacker IPs (24h)',
                    '_exists_:labels_attack_type AND NOT labels_load_test:1',
                    count_series(), row_pivots=values_pivot('source_ip', 10),
                    viz='bar', row_limit=10)
    w7 = message_widget('Recent attack-type events',
                        '_exists_:labels_attack_type AND NOT labels_load_test:1',
                        fields=['timestamp', 'labels_attack_type', 'source_ip',
                                'user_name', 'message'],
                        limit=30)

    widgets = [w1, w2, w3, w4, w5, w6, w7]
    titles = {w1['id']: 'Brute-force rate (5m)', w2['id']: 'DoS rate (5m)',
              w3['id']: 'Distinct targets (5m)',
              w4['id']: 'Attack-type mix', w5['id']: 'Attack volume over time',
              w6['id']: 'Top attacker IPs', w7['id']: 'Recent attack events'}
    return create_dashboard(
        g, title='Threat Detection & Coverage',
        summary='Live attack rate, rule-candidate volumes, MITRE-adjacent coverage — last 24h + 5 min gauges',
        description='Operational view of the detection layer. The 5-minute gauges match the correlation-rule windows; values near the rule thresholds mean a fire is imminent.',
        widget_defs=widgets, titles=titles,
    )


def compliance_audit(g):
    """Dashboard #5 — Compliance & Audit.

    Everything an auditor or regulator would ask for: operator actions over
    time, data-access trail, retention evidence, incident-response cadence.
    """
    w1 = agg_widget('SOC actions (24h)',
                    'event_provider:soc-console',
                    count_series(), viz='numeric')
    w2 = agg_widget('IPs blocked (24h)',
                    'event_action:soc_block_ip',
                    count_series(), viz='numeric')
    w3 = agg_widget('Users disabled (24h)',
                    'event_action:soc_disable_user',
                    count_series(), viz='numeric')
    w4 = agg_widget('Force-logouts (24h)',
                    'event_action:soc_force_logout_ip',
                    count_series(), viz='numeric')
    w5 = agg_widget('SOC action mix (24h)',
                    'event_provider:soc-console',
                    count_series(),
                    row_pivots=values_pivot('event_action', 15),
                    viz='pie', row_limit=15)
    w6 = agg_widget('SOC actions over time (24h, 30m)',
                    'event_provider:soc-console',
                    count_series(), row_pivots=time_pivot('30m'),
                    viz='line')
    w7 = message_widget('SOC action trail (GDPR Art. 30 — record of processing)',
                        'event_provider:soc-console',
                        fields=['timestamp', 'user_name', 'event_action',
                                'source_ip', 'message'],
                        limit=50)
    w8 = message_widget('Data-access trail — authentication events',
                        'event_category:authentication',
                        fields=['timestamp', 'user_name', 'event_action',
                                'event_outcome', 'source_ip'],
                        limit=30)

    widgets = [w1, w2, w3, w4, w5, w6, w7, w8]
    titles = {w1['id']: 'SOC actions', w2['id']: 'IPs blocked',
              w3['id']: 'Users disabled', w4['id']: 'Force-logouts',
              w5['id']: 'SOC action mix', w6['id']: 'SOC actions timeline',
              w7['id']: 'SOC action trail', w8['id']: 'Auth access trail'}
    return create_dashboard(
        g, title='Compliance & Audit',
        summary='Operator action trail + access events for GDPR/SOC 2 audit evidence — last 24h',
        description='What a regulator would ask for. Every SOC operator click is a log event; the trail table below is the GDPR Art. 30 record of processing activities.',
        widget_defs=widgets, titles=titles,
    )


def game_health(g):
    w1 = agg_widget('Total events (24h)', '*', count_series('events'), viz='numeric')
    w2 = agg_widget('Unique users (24h)', '*',
                    [{'config': {'name': 'users'}, 'function': 'card(user_name)'}],
                    viz='numeric')
    w3 = agg_widget('Events by category (24h)', '*',
                    count_series(), row_pivots=values_pivot('event_category', 10),
                    viz='pie', row_limit=10)
    w4 = agg_widget('Event rate over time (24h, 30min buckets)', '*',
                    count_series(), row_pivots=time_pivot('30m'),
                    viz='line')
    w5 = agg_widget('Top users by activity', '*',
                    count_series(), row_pivots=values_pivot('user_name', 10),
                    viz='table', row_limit=10)
    w6 = agg_widget('Gameplay actions (24h)', 'event_category:gameplay',
                    count_series(), row_pivots=values_pivot('event_action', 10),
                    viz='bar', row_limit=10)

    widgets = [w1, w2, w3, w4, w5, w6]
    titles = {
        w1['id']: 'Total events',
        w2['id']: 'Unique users',
        w3['id']: 'Events by category',
        w4['id']: 'Event rate over time',
        w5['id']: 'Top users',
        w6['id']: 'Gameplay actions',
    }
    return create_dashboard(
        g,
        title='Game Server Health',
        summary='Event throughput and user activity — last 24h',
        description='Operational view of game server traffic. Watch for anomalous spikes or drops.',
        widget_defs=widgets, titles=titles,
    )


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://localhost:9000')
    parser.add_argument('--user', default=os.environ.get('GRAYLOG_USER', 'socadmin'))
    parser.add_argument('--password', default=os.environ.get('GRAYLOG_PASSWORD', ''))
    args = parser.parse_args()

    g = G(args.url, args.user, args.password)
    code, _ = g.get('/api/system/lbstatus')
    if code != 200:
        print(f'Graylog not reachable: HTTP {code}', file=sys.stderr)
        sys.exit(1)
    print(f'Connected to {args.url}\n')

    print('→ Dashboards')
    soc_executive(g)
    auth_security(g)
    threat_detection(g)
    compliance_audit(g)
    game_health(g)
    security_overview(g)   # legacy, keep so old links still work
    print('\nDone.')


if __name__ == '__main__':
    main()
