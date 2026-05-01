#!/usr/bin/env python3
"""
SOC Console — response-plane service.

Separate from log-server.py (which stays on :8080 for the game). This one runs
on :8090 and serves the analyst-facing incident response UI + REST actions.

Real-time model: Graylog HTTP Notifications POST to /api/soc/ingest-event on
every firing alert. We push each alert through an in-process SSE broadcaster
to every connected browser. No polling; sub-second end-to-end latency.

Response actions (all admin-gated):
  • block_ip / unblock_ip      — app-layer 403 (always) + kernel DROP (best-effort)
  • disable_user / enable_user — rejects future logins for that username
  • force_logout_ip            — invalidates active sessions from that IP
  • ack                        — mark an alert as handled (hides from queue)
  • pivot                      — returns a Graylog search URL for the entity

Usage:
  python3 soc-server.py [--port 8090] [--graylog http://localhost:9000] \\
                        [--graylog-user socadmin --graylog-pass <REDACTED-PASSWORD>] \\
                        [--shared-secret <graylog-http-notification-secret>]
"""
import argparse
import base64
import hashlib
import json
import os
import queue
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

import soc_shared as S
import geoip

SERVERS_FILE = 'data/servers.json'
_servers_lock = threading.Lock()


def load_servers():
    if os.path.exists(SERVERS_FILE):
        try:
            with open(SERVERS_FILE, 'r') as f:
                d = json.load(f)
                if isinstance(d, dict):
                    return d.get('servers', [])
        except Exception:
            pass
    return []


def save_servers(servers):
    with _servers_lock:
        os.makedirs(os.path.dirname(SERVERS_FILE), exist_ok=True)
        tmp = f'{SERVERS_FILE}.tmp'
        with open(tmp, 'w') as f:
            json.dump({'servers': servers}, f, indent=2)
        os.replace(tmp, SERVERS_FILE)


def ensure_default_server():
    if not load_servers():
        save_servers([{
            'id': 'siem-arcade-01',
            'name': 'siem-arcade-01',
            'data_center': 'eu-west-1',
            'environment': 'production',
            'url': 'http://localhost:8080',
            'registered_at': datetime.now(timezone.utc).isoformat(timespec='seconds') + 'Z',
        }])

ADMIN_USERNAME = 'socadmin'
# sha256('<REDACTED-PASSWORD>')
ADMIN_PASSWORD_HASH = '<REDACTED-SHA256>'
SESSION_COOKIE = 'soc_session'

# In-memory session tokens (token -> {username, created})
sessions = {}
sessions_lock = threading.Lock()

# Recent alerts buffer (so a fresh browser tab backfills the last N events)
RECENT_ALERTS_MAX = 50
recent_alerts = []
recent_lock = threading.Lock()

# SSE subscriber queues — one per connected browser
subscribers = set()
subscribers_lock = threading.Lock()

# Ack'd events (event_id -> acked_at) — suppressed from new-tab backfill
acked = {}
acked_lock = threading.Lock()


# ─── Config from CLI ────────────────────────────────────────────────────────
CONFIG = {
    'port': 8090,
    'graylog_url': 'http://localhost:9000',
    'graylog_external_url': None,   # public-facing URL used for pivot links only
    'graylog_auth': ('socadmin', '<REDACTED-PASSWORD>'),
    'shared_secret': None,
    'log_server': 'http://localhost:8080',
}


def now_iso():
    n = datetime.now(timezone.utc)
    return n.strftime('%Y-%m-%dT%H:%M:%S.') + f'{n.microsecond // 1000:03d}Z'


# ─── Audit log: record every SOC action as an ECS event forwarded to Graylog
def emit_audit(action, actor, target, outcome='success', extra=None):
    """Send an ECS audit log to the game's log-server so it flows to Graylog."""
    entry = {
        '@timestamp': now_iso(),
        'event': {
            'kind': 'event',
            'category': ['iam', 'configuration'],
            'type': ['change'],
            'action': action,
            'outcome': outcome,
            'provider': 'soc-console',
        },
        'user': {'name': actor, 'roles': ['analyst', 'admin']},
        'source': {'ip': '127.0.0.1'},
        'message': f'SOC action "{action}" by {actor} on {target} → {outcome}',
        'labels': {'soc_action': action, 'target': target, **(extra or {})},
        'log': {'level': 'notice', 'logger': 'soc-console.audit'},
        'ecs': {'version': '8.11'},
    }
    try:
        req = urllib.request.Request(
            f'{CONFIG["log_server"]}/api/logs',
            data=json.dumps(entry).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception as e:
        print(f'  [AUDIT] WARN could not forward audit to log-server: {e}')


# ─── SSE broadcaster ────────────────────────────────────────────────────────

def broadcast(event_type, payload):
    """Push to all connected SSE clients. Drops slow consumers."""
    packet = f'event: {event_type}\ndata: {json.dumps(payload)}\n\n'.encode()
    with subscribers_lock:
        dead = []
        for q in list(subscribers):
            try:
                q.put_nowait(packet)
            except queue.Full:
                dead.append(q)
        for q in dead:
            subscribers.discard(q)


# ─── Kernel-level blocking (best-effort) ────────────────────────────────────

def kernel_block(ip):
    """Try iptables DROP via passwordless sudo. Returns True if accepted."""
    try:
        r = subprocess.run(
            ['sudo', '-n', 'iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            print(f'  [FIREWALL] iptables DROP installed for {ip}')
            return True
        print(f'  [FIREWALL] iptables failed ({r.returncode}): {r.stderr.strip()}')
    except FileNotFoundError:
        print(f'  [FIREWALL] sudo or iptables not available')
    except Exception as e:
        print(f'  [FIREWALL] error: {e}')
    return False


def kernel_unblock(ip):
    try:
        r = subprocess.run(
            ['sudo', '-n', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


# ─── Auth ───────────────────────────────────────────────────────────────────

def issue_session(username):
    tok = secrets.token_urlsafe(32)
    with sessions_lock:
        sessions[tok] = {'username': username, 'created': now_iso()}
    return tok


def valid_session(token):
    with sessions_lock:
        return token in sessions


def revoke_session(token):
    with sessions_lock:
        sessions.pop(token, None)


# ─── Handler ────────────────────────────────────────────────────────────────

class SOCHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # quieter
        pass

    # ─── Helpers ────────────────────────────────────────────────────────────

    def _write(self, status, body=b'', content_type='application/octet-stream', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status, data, extra_headers=None):
        self._write(status, json.dumps(data).encode(), 'application/json; charset=utf-8', extra_headers)

    def _read_body(self):
        n = int(self.headers.get('Content-Length', 0))
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except Exception:
            return {}

    def _cookie(self, name):
        raw = self.headers.get('Cookie', '')
        for part in raw.split(';'):
            part = part.strip()
            if part.startswith(f'{name}='):
                return part[len(name) + 1:]
        return None

    def _require_admin(self):
        tok = self._cookie(SESSION_COOKIE)
        if not tok or not valid_session(tok):
            self._json(401, {'error': 'Not authenticated'})
            return None
        with sessions_lock:
            return sessions[tok]['username']

    # ─── Routing ────────────────────────────────────────────────────────────

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path == '/' or path == '/soc' or path == '/soc.html':
            return self._serve_static('soc.html', 'text/html; charset=utf-8')
        if path.startswith('/reports/') and not path.endswith('/'):
            # Serve generated HTML reports for inline viewing
            return self._serve_report(path)
        if path == '/api/soc/stream':
            return self._sse_stream()
        if path == '/api/soc/state':
            return self._get_state()
        if path == '/api/soc/pivot':
            return self._get_pivot()
        if path == '/api/soc/whoami':
            return self._get_whoami()
        if path == '/api/soc/servers':
            return self._get_servers()
        if path == '/api/soc/kpis':
            return self._get_kpis()
        if path == '/api/soc/events':
            return self._get_events()
        if path == '/api/soc/distributions':
            return self._get_distributions()
        if path == '/api/soc/export.csv':
            return self._get_export_csv()
        self._json(404, {'error': 'not found'})

    def do_POST(self):
        path = self.path.split('?', 1)[0]
        if path == '/api/soc/auth':
            return self._post_auth()
        if path == '/api/soc/logout':
            return self._post_logout()
        if path == '/api/soc/ingest-event':
            return self._post_ingest()
        if path == '/api/soc/block_ip':
            return self._action_block_ip()
        if path == '/api/soc/unblock_ip':
            return self._action_unblock_ip()
        if path == '/api/soc/disable_user':
            return self._action_disable_user()
        if path == '/api/soc/enable_user':
            return self._action_enable_user()
        if path == '/api/soc/force_logout_ip':
            return self._action_force_logout_ip()
        if path == '/api/soc/ack':
            return self._action_ack()
        if path == '/api/soc/servers':
            return self._post_server()
        if path == '/api/soc/compliance-report':
            return self._post_compliance_report()
        if path == '/api/soc/clean_logs':
            return self._post_clean_logs()
        # Delete-by-path: /api/soc/servers/<id>/delete
        if path.startswith('/api/soc/servers/') and path.endswith('/delete'):
            return self._delete_server(path)
        self._json(404, {'error': 'not found'})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    # ─── Static ─────────────────────────────────────────────────────────────

    def _serve_static(self, filename, content_type):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        if not os.path.exists(path):
            return self._json(404, {'error': f'{filename} not found'})
        with open(path, 'rb') as f:
            body = f.read()
        self._write(200, body, content_type)

    def _serve_report(self, path):
        """Serve a generated compliance/daily report. Admin-gated."""
        if self._require_admin() is None:
            return
        # Path safety: only allow files inside reports/ with a .html extension
        rel = path.lstrip('/')
        if '..' in rel or not rel.endswith('.html'):
            return self._json(400, {'error': 'invalid report path'})
        full = os.path.join(os.path.dirname(os.path.abspath(__file__)), rel)
        if not os.path.exists(full):
            return self._json(404, {'error': 'report not found'})
        with open(full, 'rb') as f:
            body = f.read()
        self._write(200, body, 'text/html; charset=utf-8')

    # ─── Auth endpoints ─────────────────────────────────────────────────────

    def _post_auth(self):
        body = self._read_body()
        u = (body.get('username') or '').strip()
        p = body.get('password') or ''
        if u != ADMIN_USERNAME or hashlib.sha256(p.encode()).hexdigest() != ADMIN_PASSWORD_HASH:
            print(f'  [AUTH] SOC LOGIN FAILED: {u!r}')
            return self._json(401, {'error': 'Invalid credentials'})
        tok = issue_session(u)
        print(f'  [AUTH] SOC LOGIN SUCCESS: {u}')
        self._json(
            200, {'status': 'ok', 'username': u},
            extra_headers={'Set-Cookie': f'{SESSION_COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict'},
        )

    def _post_logout(self):
        tok = self._cookie(SESSION_COOKIE)
        if tok:
            revoke_session(tok)
        self._json(
            200, {'status': 'ok'},
            extra_headers={'Set-Cookie': f'{SESSION_COOKIE}=; Path=/; Max-Age=0'},
        )

    def _get_whoami(self):
        tok = self._cookie(SESSION_COOKIE)
        if tok and valid_session(tok):
            with sessions_lock:
                return self._json(200, {'authenticated': True, 'username': sessions[tok]['username']})
        self._json(200, {'authenticated': False})

    # ─── State ──────────────────────────────────────────────────────────────

    def _get_state(self):
        if self._require_admin() is None:
            return
        with recent_lock:
            alerts = list(recent_alerts)
        with acked_lock:
            acked_ids = dict(acked)
        self._json(200, {
            'blocklist': S.load_blocklist(),
            'disabled_users': S.load_disabled_users(),
            'recent_alerts': alerts,
            'acked': acked_ids,
            'sessions_count': len(sessions),
            'subscribers_count': len(subscribers),
        })

    def _get_pivot(self):
        if self._require_admin() is None:
            return
        qs = urllib.parse.parse_qs(self.path.split('?', 1)[1] if '?' in self.path else '')
        entity_type = (qs.get('type', ['ip'])[0])
        value = (qs.get('value', [''])[0])
        hours = int(qs.get('hours', ['1'])[0])
        field = 'source_ip' if entity_type == 'ip' else 'user_name'
        query = urllib.parse.quote(f'{field}:{value}')
        # Pivot links open in the user's browser — use the public URL, not localhost.
        base = CONFIG.get('graylog_external_url') or CONFIG['graylog_url']
        url = f'{base}/search?q={query}&rangetype=relative&relative={hours * 3600}'
        self._json(200, {'url': url, 'query': f'{field}:{value}'})

    # ─── Graylog → SOC ingest ──────────────────────────────────────────────

    def _post_ingest(self):
        if CONFIG['shared_secret']:
            got = self.headers.get('X-SOC-Secret')
            if got != CONFIG['shared_secret']:
                return self._json(401, {'error': 'invalid shared secret'})
        raw = self._read_body()
        # Graylog HTTP notification body shape: event_definition_title/type,
        # priority, backlog (list of messages), event object with fields, key_tuple.
        event = raw.get('event', {}) or {}
        alert = {
            'id': event.get('id') or f'evt-{int(time.time()*1000)}',
            'rule': event.get('event_definition_type') or raw.get('event_definition_title') or 'unknown',
            'rule_title': raw.get('event_definition_title') or event.get('message', '').split(':')[0],
            'message': event.get('message'),
            'priority': event.get('priority'),
            'timestamp': event.get('timestamp') or now_iso(),
            'fields': event.get('fields') or {},
            'key_tuple': event.get('key_tuple') or [],
            'backlog_count': len(raw.get('backlog') or []),
            'raw': raw,
        }

        with recent_lock:
            recent_alerts.append(alert)
            if len(recent_alerts) > RECENT_ALERTS_MAX:
                del recent_alerts[:-RECENT_ALERTS_MAX]

        broadcast('alert', alert)
        print(f'  [ALERT] {alert["rule_title"]} → {alert["message"]}')
        self._json(200, {'status': 'received', 'id': alert['id']})

    # ─── SSE stream ────────────────────────────────────────────────────────

    def _sse_stream(self):
        if self._require_admin() is None:
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Accel-Buffering', 'no')
        self.end_headers()

        q = queue.Queue(maxsize=200)
        with subscribers_lock:
            subscribers.add(q)

        try:
            # Backfill: last 10 alerts that aren't acked
            with recent_lock, acked_lock:
                for a in list(recent_alerts)[-10:]:
                    if a['id'] in acked:
                        continue
                    self.wfile.write(f'event: alert\ndata: {json.dumps(a)}\n\n'.encode())
                # Initial state snapshot
                snapshot = {
                    'blocklist': S.load_blocklist(),
                    'disabled_users': S.load_disabled_users(),
                }
                self.wfile.write(f'event: state\ndata: {json.dumps(snapshot)}\n\n'.encode())
            self.wfile.flush()

            last_beat = time.time()
            while True:
                try:
                    packet = q.get(timeout=5)
                    self.wfile.write(packet)
                    self.wfile.flush()
                except queue.Empty:
                    pass
                if time.time() - last_beat > 20:
                    self.wfile.write(b': heartbeat\n\n')
                    self.wfile.flush()
                    last_beat = time.time()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with subscribers_lock:
                subscribers.discard(q)

    # ─── Response actions ───────────────────────────────────────────────────

    def _action_block_ip(self):
        actor = self._require_admin()
        if not actor:
            return
        body = self._read_body()
        ip = (body.get('ip') or '').strip()
        reason = body.get('reason', 'manual block from SOC console')
        alert_id = body.get('alert_id')
        if not ip:
            return self._json(400, {'error': 'ip required'})

        kernel_ok = kernel_block(ip)
        rec = S.block_ip(ip, reason=reason, actor=actor, alert_id=alert_id, kernel=kernel_ok)
        emit_audit('soc_block_ip', actor, ip, extra={'reason': reason, 'kernel': str(kernel_ok)})
        broadcast('state_change', {'kind': 'block_ip', 'ip': ip, 'record': rec})
        print(f'  [ACTION] BLOCK_IP {ip} by {actor} (kernel={kernel_ok}) — {reason}')
        self._json(200, {'status': 'blocked', 'ip': ip, 'kernel': kernel_ok, 'record': rec})

    def _action_unblock_ip(self):
        actor = self._require_admin()
        if not actor:
            return
        body = self._read_body()
        ip = (body.get('ip') or '').strip()
        if not ip:
            return self._json(400, {'error': 'ip required'})
        removed = S.unblock_ip(ip)
        kernel_unblock(ip)
        emit_audit('soc_unblock_ip', actor, ip)
        broadcast('state_change', {'kind': 'unblock_ip', 'ip': ip})
        print(f'  [ACTION] UNBLOCK_IP {ip} by {actor}')
        self._json(200, {'status': 'unblocked', 'ip': ip, 'was': removed})

    def _action_disable_user(self):
        actor = self._require_admin()
        if not actor:
            return
        body = self._read_body()
        user = (body.get('username') or '').strip()
        reason = body.get('reason', 'manual disable from SOC console')
        alert_id = body.get('alert_id')
        if not user:
            return self._json(400, {'error': 'username required'})
        rec = S.disable_user(user, reason=reason, actor=actor, alert_id=alert_id)
        emit_audit('soc_disable_user', actor, user, extra={'reason': reason})
        broadcast('state_change', {'kind': 'disable_user', 'username': user, 'record': rec})
        print(f'  [ACTION] DISABLE_USER {user} by {actor}')
        self._json(200, {'status': 'disabled', 'username': user, 'record': rec})

    def _action_enable_user(self):
        actor = self._require_admin()
        if not actor:
            return
        body = self._read_body()
        user = (body.get('username') or '').strip()
        if not user:
            return self._json(400, {'error': 'username required'})
        removed = S.enable_user(user)
        emit_audit('soc_enable_user', actor, user)
        broadcast('state_change', {'kind': 'enable_user', 'username': user})
        print(f'  [ACTION] ENABLE_USER {user} by {actor}')
        self._json(200, {'status': 'enabled', 'username': user, 'was': removed})

    def _action_force_logout_ip(self):
        actor = self._require_admin()
        if not actor:
            return
        body = self._read_body()
        ip = (body.get('ip') or '').strip()
        if not ip:
            return self._json(400, {'error': 'ip required'})
        # Kick any active game session from this IP: add a short-TTL block
        # (60 s). The game client posts telemetry every 1 s; the next POST
        # gets 403 → redirect to login. TTL auto-expires so the user can
        # log back in right away.
        S.block_ip(ip, reason=f'force-logout by {actor}', actor=actor,
                   kernel=False, ttl_seconds=60)
        entry = {
            '@timestamp': now_iso(),
            'event': {'category': ['authentication'], 'action': 'force_logout',
                      'outcome': 'success', 'provider': 'soc-console'},
            'source': {'ip': ip},
            'user': {'name': 'all-from-ip'},
            'message': f'Force-logout by {actor}: sessions from {ip} kicked (60s block)',
            'log': {'level': 'notice'},
            'ecs': {'version': '8.11'},
            'labels': {'soc_action': 'force_logout', 'target': ip},
        }
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    f'{CONFIG["log_server"]}/api/logs',
                    data=json.dumps(entry).encode(),
                    headers={'Content-Type': 'application/json'},
                    method='POST',
                ), timeout=2,
            )
        except Exception:
            pass
        emit_audit('soc_force_logout_ip', actor, ip)
        broadcast('state_change', {'kind': 'force_logout_ip', 'ip': ip})
        print(f'  [ACTION] FORCE_LOGOUT_IP {ip} by {actor} (60s TTL)')
        self._json(200, {'status': 'logged_out', 'ip': ip, 'ttl_seconds': 60})

    def _action_ack(self):
        actor = self._require_admin()
        if not actor:
            return
        body = self._read_body()
        event_id = (body.get('id') or '').strip()
        if not event_id:
            return self._json(400, {'error': 'id required'})
        with acked_lock:
            acked[event_id] = {'acked_at': now_iso(), 'acked_by': actor}
        emit_audit('soc_ack_alert', actor, event_id)
        broadcast('state_change', {'kind': 'ack', 'id': event_id, 'by': actor})
        print(f'  [ACTION] ACK {event_id} by {actor}')
        self._json(200, {'status': 'acked', 'id': event_id})

    # ─── Fleet: server registry ────────────────────────────────────────────

    def _get_servers(self):
        if self._require_admin() is None:
            return
        self._json(200, {'servers': load_servers()})

    def _post_server(self):
        actor = self._require_admin()
        if not actor:
            return
        body = self._read_body()
        name = (body.get('name') or '').strip()
        if not name:
            return self._json(400, {'error': 'name required'})
        server = {
            'id': name,
            'name': name,
            'data_center': (body.get('data_center') or 'eu-west-1').strip(),
            'environment': (body.get('environment') or 'production').strip(),
            'url': (body.get('url') or '').strip(),
            'registered_at': now_iso(),
            'registered_by': actor,
        }
        servers = load_servers()
        # Dedup on id
        servers = [s for s in servers if s.get('id') != server['id']] + [server]
        save_servers(servers)
        emit_audit('soc_register_server', actor, name,
                   extra={'data_center': server['data_center']})
        broadcast('state_change', {'kind': 'server_added', 'server': server})
        print(f'  [ACTION] REGISTER_SERVER {name} ({server["data_center"]}) by {actor}')
        self._json(200, {'status': 'registered', 'server': server})

    def _delete_server(self, path):
        actor = self._require_admin()
        if not actor:
            return
        sid = path.split('/')[4]  # /api/soc/servers/<id>/delete
        servers = load_servers()
        before = len(servers)
        servers = [s for s in servers if s.get('id') != sid]
        if len(servers) == before:
            return self._json(404, {'error': 'server not found'})
        save_servers(servers)
        emit_audit('soc_deregister_server', actor, sid)
        broadcast('state_change', {'kind': 'server_removed', 'id': sid})
        print(f'  [ACTION] DEREGISTER_SERVER {sid} by {actor}')
        self._json(200, {'status': 'deleted', 'id': sid})

    # ─── Graylog helpers ───────────────────────────────────────────────────

    def _graylog_search_csv(self, query, range_s, fields, limit=1000, sort='timestamp:desc'):
        import urllib.request, urllib.error
        params = {
            'query': query or '*', 'range': range_s, 'limit': limit,
            'fields': ','.join(fields),
        }
        if sort:
            params['sort'] = sort
        qs = urllib.parse.urlencode(params)
        user, pw = CONFIG['graylog_auth']
        tok = base64.b64encode(f'{user}:{pw}'.encode()).decode()
        req = urllib.request.Request(
            f'{CONFIG["graylog_url"]}/api/search/universal/relative?{qs}',
            headers={'Authorization': f'Basic {tok}', 'X-Requested-By': 'soc-console', 'Accept': 'text/csv'},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode()
        except Exception as e:
            print(f'  [WARN] graylog search failed: {e}')
            return ''

    def _graylog_total_events(self, range_s):
        """Fast count of events in window — used for events/sec KPI."""
        import urllib.request
        qs = urllib.parse.urlencode({
            'query': '*', 'range': range_s,
            'limit': 1, 'fields': 'timestamp',
        })
        user, pw = CONFIG['graylog_auth']
        tok = base64.b64encode(f'{user}:{pw}'.encode()).decode()
        req = urllib.request.Request(
            f'{CONFIG["graylog_url"]}/api/search/universal/relative?{qs}',
            headers={'Authorization': f'Basic {tok}', 'X-Requested-By': 'soc-console',
                     'Accept': 'application/json'},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode())
                return data.get('total_results', 0)
        except Exception:
            return 0

    # ─── Live player-state computation ─────────────────────────────────────

    def _distinct_users(self, query, range_s):
        """Return the set of distinct user_name values matching the query."""
        import csv as _csv, io as _io
        csv_data = self._graylog_search_csv(query, range_s, ['user_name'], limit=10000)
        out = set()
        for r in _csv.DictReader(_io.StringIO(csv_data)):
            u = (r.get('user_name') or '').strip()
            if u and u != 'anonymous':
                out.add(u)
        return out

    def _player_state_counts(self, _csv=None, _io=None):
        """Classify each user by their MOST RECENT event in the last hour:
          active       — last event is not a logout and happened in last 5 min
          idle         — last event is not a logout and happened 5-60 min ago
          disconnected — last event IS a session_end / user_logout
        This is the honest "currently playing" definition, not "logged in
        anywhere in the last 5 min". Excludes SOC operators (socadmin) and
        any event sourced from the SOC Console itself — they're not players.
        """
        import csv as _c, io as _i
        csv_data = self._graylog_search_csv(
            f'user_name:* AND NOT user_name:{ADMIN_USERNAME} AND NOT event_provider:soc-console',
            3600, ['user_name', 'event_action', 'timestamp'], limit=10000,
        )
        now = datetime.now(timezone.utc)
        latest = {}  # user_name -> (datetime, action)
        for r in _c.DictReader(_i.StringIO(csv_data)):
            u = (r.get('user_name') or '').strip()
            if not u or u == 'anonymous':
                continue
            action = (r.get('event_action') or '').strip()
            ts_str = (r.get('timestamp') or '').strip()
            try:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except Exception:
                continue
            cur = latest.get(u)
            if cur is None or ts > cur[0]:
                latest[u] = (ts, action)

        active_n = idle_n = disconnected_n = 0
        for u, (ts, action) in latest.items():
            age = (now - ts).total_seconds()
            is_logout = action in ('session_end', 'user_logout')
            if is_logout:
                disconnected_n += 1
            elif age < 300:
                active_n += 1
            else:
                idle_n += 1
        return active_n, idle_n, disconnected_n

    # ─── KPIs ──────────────────────────────────────────────────────────────

    _kpi_cache = {'at': 0, 'data': None}
    _kpi_lock = threading.Lock()

    def _get_kpis(self):
        if self._require_admin() is None:
            return
        with SOCHandler._kpi_lock:
            if SOCHandler._kpi_cache['data'] and time.time() - SOCHandler._kpi_cache['at'] < 5:
                return self._json(200, SOCHandler._kpi_cache['data'])

        # Events/sec over last 60s
        count_60s = self._graylog_total_events(60)
        events_per_sec = round(count_60s / 60.0, 1)

        # Real player-status counts derived from actual login/logout events.
        # "Active" = distinct user_name with a successful login in last 5 min.
        # "Disconnected" = distinct user_name with session_end/user_logout in
        #   last 1h who haven't re-logged-in since (active overrides).
        # "Idle" = logged in within last 1h but not within last 5 min AND not
        #   currently disconnected.
        import csv as _csv, io as _io
        active_n, idle_n, disconnected_n = self._player_state_counts(_csv, _io)

        alerts_24h = 0
        try:
            import urllib.request
            body = json.dumps({'query':'','filter':{'alerts':'only'},
                'timerange':{'type':'relative','range':86400},'page':1,'per_page':1}).encode()
            user, pw = CONFIG['graylog_auth']
            tok = base64.b64encode(f'{user}:{pw}'.encode()).decode()
            req = urllib.request.Request(
                f'{CONFIG["graylog_url"]}/api/events/search',
                data=body, method='POST',
                headers={'Authorization': f'Basic {tok}', 'X-Requested-By': 'soc-console',
                         'Content-Type': 'application/json'},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                alerts_24h = json.loads(r.read().decode()).get('total_events') or 0
        except Exception:
            pass

        data = {
            'events_per_sec': events_per_sec,
            'events_last_hour': self._graylog_total_events(3600),
            'events_last_24h': self._graylog_total_events(86400),
            'active_players': active_n,
            'idle_players': idle_n,
            'disconnected_players': disconnected_n,
            'alerts_last_24h': alerts_24h,
            'blocked_ips': len(S.load_blocklist()),
            'disabled_users': len(S.load_disabled_users()),
            'geo_cache_size': geoip.cache_stats()['size'],
            'servers': len(load_servers()),
            'subscribers': len(subscribers),
            'generated_at': now_iso(),
        }
        with SOCHandler._kpi_lock:
            SOCHandler._kpi_cache = {'at': time.time(), 'data': data}
        self._json(200, data)

    # ─── Events table ──────────────────────────────────────────────────────

    def _get_events(self):
        if self._require_admin() is None:
            return
        qs = urllib.parse.parse_qs(self.path.split('?', 1)[1] if '?' in self.path else '')
        limit = int(qs.get('limit', ['50'])[0])
        q = qs.get('q', [''])[0] or '*'
        range_s = int(qs.get('range', ['3600'])[0])
        fields = ['timestamp', 'message', 'event_action', 'event_outcome',
                  'event_category', 'event_kind',
                  'user_name', 'source_ip', 'source_geo_country_name',
                  'source_geo_country_iso_code', 'log_level', 'host_name',
                  'labels_game_rank', 'labels_auth_attempts', 'labels_player_status',
                  'session_id']
        csv_data = self._graylog_search_csv(q, range_s, fields, limit=limit)
        rows = []
        import csv as _csv, io as _io
        reader = _csv.DictReader(_io.StringIO(csv_data))
        for r in reader:
            # Re-enrich from the live GeoIP cache: events indexed with
            # "Unknown" (first-time lookup race) get the correct country
            # now that the cache has populated. Cheap: in-memory dict hit.
            ip = (r.get('source_ip') or '').strip()
            cur = (r.get('source_geo_country_name') or '').strip()
            if ip and (not cur or cur == 'Unknown'):
                geo = geoip.lookup(ip)
                if geo and geo.get('country') and geo['country'] != 'Unknown':
                    r['source_geo_country_name'] = geo['country']
                    r['source_geo_country_iso_code'] = geo.get('country_code', '')
            rows.append(r)
        self._json(200, {'events': rows, 'total': len(rows), 'query': q, 'range': range_s})

    # ─── Pie chart distributions ───────────────────────────────────────────

    def _get_distributions(self):
        if self._require_admin() is None:
            return
        qs = urllib.parse.parse_qs(self.path.split('?', 1)[1] if '?' in self.path else '')
        range_s = int(qs.get('range', ['3600'])[0])

        import csv as _csv, io as _io

        def _country_for(row):
            """Prefer the current GeoIP cache over a stale 'Unknown' in Graylog."""
            cn = (row.get('source_geo_country_name') or '').strip()
            ip = (row.get('source_ip') or '').strip()
            if (not cn or cn == 'Unknown') and ip:
                geo = geoip.lookup(ip)
                if geo and geo.get('country') and geo['country'] != 'Unknown':
                    return geo['country']
            return cn or 'Unknown'

        # Events-by-country — per-event count (attacker traffic included)
        events_csv = self._graylog_search_csv(
            '*', range_s, ['source_ip', 'source_geo_country_name'], limit=10000,
        )
        events_by_country = {}
        for r in _csv.DictReader(_io.StringIO(events_csv)):
            cn = _country_for(r)
            events_by_country[cn] = events_by_country.get(cn, 0) + 1

        # Players-by-country — DISTINCT successful logins (one entry per user).
        # Last-write-wins on country if a player logged from multiple IPs.
        # SOC operators are excluded — they're not players.
        login_csv = self._graylog_search_csv(
            f'event_action:user_login AND event_outcome:success AND NOT user_name:{ADMIN_USERNAME}',
            range_s, ['user_name', 'source_ip', 'source_geo_country_name'], limit=10000,
        )
        user_country = {}
        for r in _csv.DictReader(_io.StringIO(login_csv)):
            u = (r.get('user_name') or '').strip()
            cn = _country_for(r)
            if u and u != 'anonymous' and cn and cn != 'Unknown':
                user_country[u] = cn
        players_by_country = {}
        for cn in user_country.values():
            players_by_country[cn] = players_by_country.get(cn, 0) + 1

        # Rank distribution — DISTINCT players' rank (gameplay events only).
        rank_csv = self._graylog_search_csv(
            'labels_game_rank:*', range_s,
            ['user_name', 'labels_game_rank'], limit=10000,
        )
        user_rank = {}
        for r in _csv.DictReader(_io.StringIO(rank_csv)):
            u = (r.get('user_name') or '').strip()
            rk = (r.get('labels_game_rank') or '').strip()
            if u and rk:
                user_rank[u] = rk
        rank_by_player = {}
        for rk in user_rank.values():
            rank_by_player[rk] = rank_by_player.get(rk, 0) + 1

        # Player status — distinct-user login/logout state (unchanged)
        a, i, d = self._player_state_counts()
        status = {'active': a, 'idle': i, 'disconnected': d}

        self._json(200, {
            # Legacy keys kept so older UI doesn't break
            'country': events_by_country,
            'rank': rank_by_player,
            # New keys
            'events_by_country': events_by_country,
            'players_by_country': players_by_country,
            'rank_by_player': rank_by_player,
            'status': status,
            'range': range_s,
        })

    # ─── CSV export ────────────────────────────────────────────────────────

    def _get_export_csv(self):
        if self._require_admin() is None:
            return
        qs = urllib.parse.parse_qs(self.path.split('?', 1)[1] if '?' in self.path else '')
        q = qs.get('q', ['*'])[0] or '*'
        range_s = int(qs.get('range', ['86400'])[0])
        fields = ['timestamp', 'source', 'message', 'event_action', 'event_outcome',
                  'user_name', 'source_ip', 'source_geo_country_name',
                  'log_level', 'host_name', 'labels_game_rank', 'labels_player_status']
        csv_data = self._graylog_search_csv(q, range_s, fields, limit=10000)
        ts = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv')
        self.send_header('Content-Disposition', f'attachment; filename="soc-events-{ts}.csv"')
        self.end_headers()
        self.wfile.write(csv_data.encode())

    # ─── Compliance report ─────────────────────────────────────────────────

    def _post_clean_logs(self):
        """Destructive: delete every graylog_* index and event-index in
        OpenSearch, cycle the deflector so Graylog creates a fresh empty
        write target, and truncate the local NDJSON archive. Admin-only.
        Every call is audit-logged.
        """
        actor = self._require_admin()
        if not actor:
            return
        import urllib.request
        import urllib.error

        summary = {'indices_deleted': [], 'deflector_cycled': False, 'ndjson_truncated': False, 'errors': []}
        os_base = os.environ.get('OPENSEARCH_URL', 'http://127.0.0.1:9201')

        # 1) List and delete all graylog-managed indices
        try:
            req = urllib.request.Request(f'{os_base}/_cat/indices?h=index',
                                         headers={'Accept': 'text/plain'})
            with urllib.request.urlopen(req, timeout=10) as r:
                indices = [ln.strip() for ln in r.read().decode().splitlines() if ln.strip()]
        except Exception as e:
            summary['errors'].append(f'list indices: {e}')
            indices = []

        targets = [i for i in indices if i.startswith('graylog_') or i.startswith('gl-events_') or i.startswith('gl-system-events_')]
        for idx in targets:
            try:
                req = urllib.request.Request(f'{os_base}/{idx}', method='DELETE')
                urllib.request.urlopen(req, timeout=10).read()
                summary['indices_deleted'].append(idx)
            except Exception as e:
                summary['errors'].append(f'delete {idx}: {e}')

        # 2) Cycle deflector via Graylog leader (graylog1:9001)
        try:
            user, pw = CONFIG['graylog_auth']
            tok = base64.b64encode(f'{user}:{pw}'.encode()).decode()
            req = urllib.request.Request(
                'http://127.0.0.1:9001/api/system/deflector/cycle',
                data=b'', method='POST',
                headers={'Authorization': f'Basic {tok}', 'X-Requested-By': 'soc-console'},
            )
            urllib.request.urlopen(req, timeout=10).read()
            summary['deflector_cycled'] = True
        except Exception as e:
            summary['errors'].append(f'deflector cycle: {e}')

        # 3) Truncate local NDJSON archive
        try:
            log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    'logs', 'game-logs.ndjson')
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            open(log_path, 'w').close()
            summary['ndjson_truncated'] = True
        except Exception as e:
            summary['errors'].append(f'truncate ndjson: {e}')

        emit_audit('soc_clean_logs', actor, 'all-log-indices',
                   extra={'deleted': str(len(summary['indices_deleted']))})
        # Also clear recent-alerts buffer so the SOC UI reflects the wipe
        with recent_lock:
            recent_alerts.clear()
        with acked_lock:
            acked.clear()
        broadcast('state_change', {'kind': 'logs_cleaned', 'by': actor})

        print(f'  [ACTION] CLEAN_LOGS by {actor}: deleted={summary["indices_deleted"]} '
              f'cycled={summary["deflector_cycled"]} errors={summary["errors"]}')
        self._json(200, summary)

    def _post_compliance_report(self):
        actor = self._require_admin()
        if not actor:
            return
        body = self._read_body()
        standard = (body.get('standard') or 'gdpr').lower()
        date_from = (body.get('from') or '').strip()
        date_to = (body.get('to') or '').strip()
        if standard not in ('gdpr', 'soc2'):
            return self._json(400, {'error': 'standard must be gdpr|soc2'})
        if not date_from or not date_to:
            return self._json(400, {'error': 'from and to (YYYY-MM-DD) required'})

        cmd = [
            sys.executable, 'scripts/compliance-report.py',
            '--standard', standard,
            '--from', date_from,
            '--to', date_to,
            '--url', CONFIG['graylog_url'],
            '--user', CONFIG['graylog_auth'][0],
            '--password', CONFIG['graylog_auth'][1],
            '--out', 'reports',
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception as e:
            return self._json(500, {'error': f'report run failed: {e}'})
        if r.returncode != 0:
            return self._json(500, {'error': 'report failed', 'stderr': r.stderr[-2000:]})

        # Find the generated file path (script prints it on last line)
        out_path = None
        for line in reversed(r.stdout.splitlines()):
            if line.startswith('→ '):
                out_path = line[2:].strip()
                break
        emit_audit('soc_generate_compliance_report', actor, f'{standard}:{date_from}:{date_to}',
                   extra={'path': out_path or ''})
        self._json(200, {'status': 'generated', 'path': out_path, 'standard': standard,
                         'from': date_from, 'to': date_to, 'stdout': r.stdout[-400:]})


# ─── Threaded server ────────────────────────────────────────────────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8090)
    parser.add_argument('--graylog', default='http://localhost:9000')
    parser.add_argument('--graylog-user', default='socadmin')
    parser.add_argument('--graylog-pass', default='<REDACTED-PASSWORD>')
    parser.add_argument('--graylog-external',
                        help='Public-facing Graylog URL for pivot links (defaults to --graylog)')
    parser.add_argument('--log-server', default='http://localhost:8080')
    parser.add_argument('--shared-secret', default=os.environ.get('SOC_SHARED_SECRET'),
                        help='Required header value for Graylog → SOC ingestion; disabled if empty')
    args = parser.parse_args()

    CONFIG['port'] = args.port
    CONFIG['graylog_url'] = args.graylog
    CONFIG['graylog_external_url'] = args.graylog_external or args.graylog
    CONFIG['graylog_auth'] = (args.graylog_user, args.graylog_pass)
    CONFIG['shared_secret'] = args.shared_secret
    CONFIG['log_server'] = args.log_server

    print('========================================')
    print('  SIEM SOC Console')
    print('========================================')
    print(f'  URL:           http://0.0.0.0:{args.port}')
    print(f'  Graylog:       {args.graylog}')
    print(f'  Log-server:    {args.log_server}')
    print(f'  Shared secret: {"<set>" if args.shared_secret else "<none — ingest unauth>"}')
    print(f'  Login:         socadmin / <REDACTED-PASSWORD>')
    print('========================================\n')

    ensure_default_server()

    server = ThreadedHTTPServer(('0.0.0.0', args.port), SOCHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutdown.')
        server.server_close()


if __name__ == '__main__':
    main()
