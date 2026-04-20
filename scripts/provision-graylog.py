#!/usr/bin/env python3
"""
Provision Graylog with the SIEM content pack:
  • Streams        — Authentication events, Gameplay events, Security alerts
  • Event defs     — Brute-force login, DoS flood, Failed-login anomaly
  • GELF HTTP inputs (creates missing ones on each Graylog node)

Idempotent: re-running skips items that already exist.

Usage:
  python3 scripts/provision-graylog.py [--url http://localhost:9000] \\
                                        [--user admin] [--password admin]
"""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.request


class GraylogClient:
    def __init__(self, base_url, user, password):
        self.base = base_url.rstrip('/')
        token = base64.b64encode(f'{user}:{password}'.encode()).decode()
        self.headers = {
            'Authorization': f'Basic {token}',
            'X-Requested-By': 'provision-graylog',
            'Content-Type': 'application/json',
        }

    def request(self, method, path, body=None):
        url = f'{self.base}{path}'
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode()
                if text and text[0] in '{[':
                    return r.status, json.loads(text)
                return r.status, text
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            try:
                return e.code, json.loads(text)
            except Exception:
                return e.code, text

    def get(self, path): return self.request('GET', path)
    def post(self, path, body): return self.request('POST', path, body)
    def put(self, path, body): return self.request('PUT', path, body)


def default_index_set_id(g):
    _, data = g.get('/api/system/indices/index_sets?limit=100')
    for s in data.get('index_sets', []):
        if s.get('default'):
            return s['id']
    raise RuntimeError('no default index set found')


def find_stream(g, title):
    _, data = g.get('/api/streams')
    for s in data.get('streams', []):
        if s['title'] == title:
            return s
    return None


def ensure_stream(g, title, description, rules, index_set_id):
    existing = find_stream(g, title)
    if existing:
        print(f'  [skip] stream "{title}" already exists ({existing["id"]})')
        return existing['id']
    payload = {
        'title': title,
        'description': description,
        'index_set_id': index_set_id,
        'remove_matches_from_default_stream': False,
        'matching_type': 'AND',
    }
    code, res = g.post('/api/streams', payload)
    if code >= 300:
        print(f'  [ERROR] stream "{title}": HTTP {code}: {res}')
        return None
    sid = res['stream_id']
    for rule in rules:
        c, r = g.post(f'/api/streams/{sid}/rules', rule)
        if c >= 300:
            print(f'    rule error: HTTP {c}: {r}')
    g.post(f'/api/streams/{sid}/resume', None)
    print(f'  [ok]  stream "{title}" -> {sid} ({len(rules)} rules)')
    return sid


def find_event_definition(g, title):
    _, data = g.get('/api/events/definitions?per_page=500')
    for d in data.get('event_definitions', []):
        if d['title'] == title:
            return d
    return None


def ensure_event_definition(g, title, description, filter_query, group_by, threshold, window_s, search_within_s=None):
    """Create an aggregation event: count events matching `filter_query`, grouped
    by `group_by`, alert when count >= threshold within `window_s`.
    """
    existing = find_event_definition(g, title)
    if existing:
        print(f'  [skip] event def "{title}" already exists ({existing["id"]})')
        return existing['id']

    search_within_ms = (search_within_s or window_s) * 1000
    execute_every_ms = min(window_s * 1000, 30000)

    payload = {
        'title': title,
        'description': description,
        'priority': 2,
        'alert': True,
        'config': {
            'type': 'aggregation-v1',
            'query': filter_query,
            'query_parameters': [],
            'streams': [],
            'filters': [],
            'group_by': group_by,
            'series': [{'id': 'count-series', 'type': 'count', 'field': None}],
            'conditions': {
                'expression': {
                    'expr': '>=',
                    'left': {'expr': 'number-ref', 'ref': 'count-series'},
                    'right': {'expr': 'number', 'value': threshold},
                },
            },
            'search_within_ms': search_within_ms,
            'execute_every_ms': execute_every_ms,
            'use_cron_scheduling': False,
            'event_limit': 100,
        },
        'field_spec': {
            f: {
                'data_type': 'string',
                'providers': [{'type': 'template-v1',
                               'template': '${source.' + f + '}',
                               'require_values': True}],
            }
            for f in group_by
        },
        'key_spec': group_by,
        # Grace period matches the search window so we don't re-alert on overlapping windows
        'notification_settings': {'grace_period_ms': window_s * 1000, 'backlog_size': 50},
        'notifications': [],
        'storage': [{'type': 'persist-to-streams-v1',
                     'streams': ['000000000000000000000002']}],  # "All events"
    }
    code, res = g.post('/api/events/definitions', payload)
    if code >= 300:
        print(f'  [ERROR] event def "{title}": HTTP {code}: {res}')
        return None
    eid = res.get('id')
    print(f'  [ok]  event def "{title}" -> {eid} (>= {threshold} in {window_s}s, by {group_by})')
    return eid


def ensure_gelf_input(g, title, port, node_id):
    _, data = g.get('/api/system/inputs')
    for inp in data.get('inputs', []):
        if inp.get('title') == title:
            print(f'  [skip] input "{title}" already exists ({inp["id"]})')
            return inp['id']
    payload = {
        'title': title,
        'type': 'org.graylog2.inputs.gelf.http.GELFHttpInput',
        'configuration': {
            'bind_address': '127.0.0.1',
            'port': port,
            'decompress_size_limit': 8388608,
            'idle_writer_timeout': 60,
            'max_chunk_size': 65536,
            'number_worker_threads': 2,
            'tcp_keepalive': False,
            'tls_enable': False,
            'enable_cors': True,
            'recv_buffer_size': 1048576,
            'override_source': None,
        },
        'global': False,
        'node': node_id,
    }
    code, res = g.post('/api/system/inputs', payload)
    if code >= 300:
        print(f'  [ERROR] input "{title}": HTTP {code}: {res}')
        return None
    print(f'  [ok]  input "{title}" -> {res.get("id")} (port {port})')
    return res.get('id')


def provision_inputs(g):
    print('→ GELF HTTP inputs')
    _, cluster = g.get('/api/cluster')
    nodes = list(cluster.items())
    # Sort: leader first, then by node_id for stable ordering
    nodes.sort(key=lambda kv: (not kv[1].get('is_leader'), kv[0]))
    for i, (node_id, info) in enumerate(nodes):
        port = 12211 + i
        label = 'graylog1' if info.get('is_leader') else f'graylog{i+1}'
        ensure_gelf_input(g, f'GELF HTTP ({label})', port, node_id)


def provision_streams(g):
    print('→ Streams')
    idx = default_index_set_id(g)
    # Rule field values: `event_category` comes from flattened ECS
    ensure_stream(g, 'Authentication events',
                  'All authentication, session, and login-related events',
                  rules=[
                      # field, type=1 (exact match), value
                      {'field': 'event_category', 'type': 1, 'value': 'authentication', 'inverted': False},
                  ], index_set_id=idx)

    ensure_stream(g, 'Gameplay events',
                  'In-game actions: movement, shots, kills, terminals',
                  rules=[
                      {'field': 'event_category', 'type': 1, 'value': 'gameplay', 'inverted': False},
                  ], index_set_id=idx)


def provision_event_definitions(g):
    print('→ Event definitions (correlation rules)')

    ensure_event_definition(
        g,
        title='Brute-force login',
        description='5+ auth failures from the same source IP within 60 seconds',
        filter_query='event_action:auth_failure',
        group_by=['source_ip'],
        threshold=5,
        window_s=60,
    )

    ensure_event_definition(
        g,
        title='DoS flood',
        description='100+ events from the same source IP within 10 seconds',
        filter_query='*',
        group_by=['source_ip'],
        threshold=100,
        window_s=10,
    )

    ensure_event_definition(
        g,
        title='Failed-login anomaly',
        description='20+ failed logins across all users in 5 minutes (possible distributed brute-force)',
        filter_query='event_action:auth_failure',
        group_by=[],
        threshold=20,
        window_s=300,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://localhost:9000')
    parser.add_argument('--user', default='admin')
    parser.add_argument('--password', default='admin')
    args = parser.parse_args()

    g = GraylogClient(args.url, args.user, args.password)

    code, _ = g.get('/api/system/lbstatus')
    if code != 200:
        print(f'Graylog not reachable at {args.url} (HTTP {code})', file=sys.stderr)
        sys.exit(1)
    print(f'Connected to {args.url} as {args.user}\n')

    provision_inputs(g)
    print()
    provision_streams(g)
    print()
    provision_event_definitions(g)
    print('\nDone.')


if __name__ == '__main__':
    main()
