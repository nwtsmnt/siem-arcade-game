#!/usr/bin/env python3
"""
Provision Graylog with the SIEM content pack:
  • Streams        — Authentication events, Gameplay events, Security alerts
  • Event defs     — Brute-force login, DoS flood, Failed-login anomaly
  • GELF HTTP inputs (creates missing ones on each Graylog node)

Idempotent: re-running skips items that already exist.

Usage:
  python3 scripts/provision-graylog.py [--url http://localhost:9000] \\
                                        [--user socadmin] [--password <REDACTED-PASSWORD>]
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


GELF_HTTP_TYPE = 'org.graylog2.inputs.gelf.http.GELFHttpInput'
GELF_TCP_TYPE = 'org.graylog2.inputs.gelf.tcp.GELFTCPInput'


def ensure_input(g, title, input_type, port, node_id):
    _, data = g.get('/api/system/inputs')
    for inp in data.get('inputs', []):
        if inp.get('title') == title:
            print(f'  [skip] input "{title}" already exists ({inp["id"]})')
            return inp['id']

    if input_type == GELF_HTTP_TYPE:
        config = {
            'bind_address': '127.0.0.1',
            'port': port,
            'decompress_size_limit': 8388608,
            'idle_writer_timeout': 60,
            'max_chunk_size': 65536,
            'number_worker_threads': 8,
            'tcp_keepalive': False,
            'tls_enable': False,
            'enable_cors': True,
            'recv_buffer_size': 1048576,
            'override_source': None,
        }
    elif input_type == GELF_TCP_TYPE:
        config = {
            'bind_address': '127.0.0.1',
            'port': port,
            'recv_buffer_size': 1048576,
            'number_worker_threads': 8,
            'tls_enable': False,
            'tcp_keepalive': True,
            'use_null_delimiter': True,
            'max_message_size': 2097152,
            'override_source': None,
            'decompress_size_limit': 8388608,
        }
    else:
        raise ValueError(f'unknown input type: {input_type}')

    payload = {'title': title, 'type': input_type, 'configuration': config,
               'global': False, 'node': node_id}
    code, res = g.post('/api/system/inputs', payload)
    if code >= 300:
        print(f'  [ERROR] input "{title}": HTTP {code}: {res}')
        return None
    print(f'  [ok]  input "{title}" -> {res.get("id")} (port {port})')
    return res.get('id')


def provision_inputs(g):
    print('→ GELF inputs (HTTP for normal traffic, TCP for high-volume load)')
    _, cluster = g.get('/api/cluster')
    nodes = list(cluster.items())
    # Sort: leader first, then by node_id for stable ordering
    nodes.sort(key=lambda kv: (not kv[1].get('is_leader'), kv[0]))
    for i, (node_id, info) in enumerate(nodes):
        http_port = 12211 + i
        tcp_port = 12221 + i
        label = 'graylog1' if info.get('is_leader') else f'graylog{i+1}'
        ensure_input(g, f'GELF HTTP ({label})', GELF_HTTP_TYPE, http_port, node_id)
        ensure_input(g, f'GELF TCP ({label})', GELF_TCP_TYPE, tcp_port, node_id)


def ensure_http_notification(g, title, url, secret=None):
    """Create (or find existing) Graylog HTTP Notification that POSTs every
    firing event to the given URL. Returns the notification id.
    """
    _, data = g.get('/api/events/notifications?per_page=500')
    for n in data.get('notifications', []):
        if n.get('title') == title:
            print(f'  [skip] notification "{title}" already exists ({n["id"]})')
            return n['id']
    # Graylog's encrypted config field wants the raw value on create,
    # { keep_value: true } on update. We pass the plain string.
    api_secret = secret or ''
    payload = {
        'title': title,
        'description': 'SOC Console ingest — pushes alerts into the analyst UI in real time.',
        'config': {
            'type': 'http-notification-v2',
            'url': url,
            'basic_auth': None,
            'api_key_as_header': bool(secret),
            'api_key': 'X-SOC-Secret' if secret else '',
            'api_secret': api_secret,
            'method': 'POST',
            'time_zone': 'UTC',
            'content_type': 'JSON',
            'headers': '',
            'skip_tls_verification': True,
        },
    }
    code, res = g.post('/api/events/notifications', payload)
    if code >= 300:
        print(f'  [ERROR] notification "{title}": HTTP {code}: {res}')
        return None
    print(f'  [ok]  notification "{title}" -> {res.get("id")}')
    return res.get('id')


def attach_notification_to_event_def(g, event_def_id, notification_id):
    _, d = g.get(f'/api/events/definitions/{event_def_id}')
    existing = [n.get('notification_id') if isinstance(n, dict) else n
                for n in d.get('notifications', [])]
    if notification_id in existing:
        return True
    d['notifications'] = (d.get('notifications') or []) + [{'notification_id': notification_id}]
    # Endpoint expects a put_schedule=true query param to rebuild the scheduler
    code, res = g.put(f'/api/events/definitions/{event_def_id}?schedule=true', d)
    if code >= 300:
        print(f'    [warn] attach to {event_def_id}: HTTP {code}: {str(res)[:120]}')
        return False
    return True


def whitelist_url(g, title, value):
    """Add a URL to Graylog's outbound HTTP whitelist. Graylog blocks notification
    delivery to any URL not on this list.
    """
    _, current = g.get('/api/system/urlwhitelist')
    entries = current.get('entries', [])
    if any(e.get('value') == value for e in entries):
        print(f'  [skip] whitelist for {value} already present')
        return
    entries.append({'id': title.lower().replace(' ', '-'), 'title': title,
                    'value': value, 'type': 'literal'})
    code, _ = g.put('/api/system/urlwhitelist',
                    {'entries': entries, 'disabled': current.get('disabled', False)})
    if code >= 300:
        print(f'  [warn] could not update whitelist: HTTP {code}')
    else:
        print(f'  [ok]   whitelisted {value}')


def provision_notifications(g, soc_url='http://127.0.0.1:8090/api/soc/ingest-event',
                            secret=None):
    print('→ SOC notification + attachment to event defs')
    whitelist_url(g, 'SOC Console ingest', soc_url)
    nid = ensure_http_notification(g, 'SOC Console ingest', soc_url, secret=secret)
    if not nid:
        return
    _, defs = g.get('/api/events/definitions?per_page=500')
    for d in defs.get('event_definitions', []):
        if d['title'] in ('Brute-force login', 'DoS flood', 'DDoS flood', 'Targeted account attack'):
            ok = attach_notification_to_event_def(g, d['id'], nid)
            print(f'  [{"ok" if ok else "warn"}]  attached to "{d["title"]}"')


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

    # All rule queries exclude synthetic load-test traffic so capacity tests
    # don't trigger incident alerts. Load-test events carry labels.load_test=1.
    ensure_event_definition(
        g,
        title='Brute-force login',
        description='5+ auth failures from the same source IP within 60 seconds',
        filter_query='event_action:auth_failure AND NOT labels_load_test:1',
        group_by=['source_ip'],
        threshold=5,
        window_s=60,
    )

    ensure_event_definition(
        g,
        title='DoS flood',
        description='30+ events from the same source IP within 10 seconds (single-source flood)',
        filter_query='NOT labels_load_test:1',
        group_by=['source_ip'],
        threshold=30,
        window_s=10,
    )

    ensure_event_definition(
        g,
        title='DDoS flood',
        description='300+ events in a 30-second window regardless of source (distributed flood)',
        filter_query='NOT labels_load_test:1',
        group_by=[],
        threshold=300,
        window_s=30,
    )

    ensure_event_definition(
        g,
        title='Targeted account attack',
        description='10+ failed logins against the same username across any source IPs within 5 minutes',
        filter_query='event_action:auth_failure AND NOT labels_load_test:1',
        group_by=['user_name'],
        threshold=10,
        window_s=300,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://localhost:9000')
    parser.add_argument('--user', default='socadmin')
    parser.add_argument('--password', default='<REDACTED-PASSWORD>')
    parser.add_argument('--soc-url', default='http://127.0.0.1:8090/api/soc/ingest-event',
                        help='SOC Console endpoint for Graylog HTTP notifications')
    parser.add_argument('--soc-secret', default=None,
                        help='Shared secret sent as X-SOC-Secret header (optional)')
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
    print()
    provision_notifications(g, soc_url=args.soc_url, secret=args.soc_secret)
    print('\nDone.')


if __name__ == '__main__':
    main()
