#!/usr/bin/env python3
"""
Provision Graylog dashboards (Views) via the REST API.

Creates two dashboards:
  • Security Overview  — auth activity, top offenders, alert stream, 24h timeline
  • Game Server Health — event rate, categories, user activity, session counts

Idempotent: deletes and recreates any view with a matching title.

Usage:
  python3 scripts/provision-dashboards.py [--url http://localhost:9000] \\
                                           [--user admin] [--password admin]
"""
import argparse
import base64
import json
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
    parser.add_argument('--user', default='admin')
    parser.add_argument('--password', default='admin')
    args = parser.parse_args()

    g = G(args.url, args.user, args.password)
    code, _ = g.get('/api/system/lbstatus')
    if code != 200:
        print(f'Graylog not reachable: HTTP {code}', file=sys.stderr)
        sys.exit(1)
    print(f'Connected to {args.url}\n')

    print('→ Dashboards')
    security_overview(g)
    game_health(g)
    print('\nDone.')


if __name__ == '__main__':
    main()
