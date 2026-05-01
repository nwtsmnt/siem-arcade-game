#!/usr/bin/env python3
"""
SIEM Log Relay Server
- Receives logs via HTTP POST from the game
- Appends each log to a .ndjson file on disk
- Optionally forwards to Logstash HTTP input or Graylog GELF HTTP input
- Also serves the game files (no separate web server needed)

Usage:
  python3 log-server.py [--port 8080] [--logfile logs/game-logs.ndjson] \\
                        [--forward http://localhost:5044] \\
                        [--gelf http://localhost:12201/gelf]

Endpoints:
  GET  /           → serves game files
  POST /api/logs   → receives a single log or array of logs
  GET  /api/logs   → returns last N logs as JSON
"""

import argparse
import hashlib
import json
import os
import random
import socket
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

import soc_shared as S
import geoip

USERS_FILE = 'data/users.json'
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'socadmin')
# Set via env: export ADMIN_PASSWORD_SHA256=$(echo -n 'your-password' | sha256sum | awk '{print $1}')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_SHA256', '')

# Attack simulation state
active_simulations = {}
sim_lock = threading.Lock()

# ECS log.level → syslog severity (what GELF expects)
GELF_LEVEL_MAP = {
    'debug': 7, 'info': 6, 'notice': 5,
    'warn': 4, 'warning': 4,
    'error': 3, 'critical': 2, 'alert': 1, 'emergency': 0,
}


def _flatten_for_gelf(obj, prefix):
    """Flatten nested ECS into GELF additional fields (leading-underscore scalar keys)."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            safe_k = k.lstrip('@').replace('.', '_')
            out.update(_flatten_for_gelf(v, f'{prefix}_{safe_k}'))
    elif isinstance(obj, list):
        if all(isinstance(x, (str, int, float, bool)) for x in obj):
            out[prefix] = ','.join(str(x) for x in obj)
        else:
            out[prefix] = json.dumps(obj, separators=(',', ':'))
    elif obj is not None:
        out[prefix] = obj
    return out


def ecs_to_gelf(log_entry, source_host):
    """Convert an ECS log entry into a GELF 1.1 document."""
    ts_str = log_entry.get('@timestamp')
    try:
        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
    except (ValueError, AttributeError, TypeError):
        ts = datetime.now(timezone.utc).timestamp()

    level_str = log_entry.get('log', {}).get('level', 'info').lower()
    level = GELF_LEVEL_MAP.get(level_str, 6)

    short_msg = (
        log_entry.get('message')
        or log_entry.get('event', {}).get('action')
        or 'event'
    )

    gelf = {
        'version': '1.1',
        'host': source_host,
        'short_message': short_msg,
        'timestamp': ts,
        'level': level,
    }
    for k, v in log_entry.items():
        if k in ('@timestamp', 'message'):
            continue
        safe_k = k.lstrip('@').replace('.', '_')
        gelf.update(_flatten_for_gelf(v, f'_{safe_k}'))
    return gelf


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_users(users):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


class LogRelayHandler(SimpleHTTPRequestHandler):
    log_file = None
    forward_url = None
    gelf_url = None
    gelf_tcp = None  # (host, port) for GELF TCP streaming — load generator only
    gelf_host = 'siem-arcade-game'
    log_count = 0

    def send_json(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def get_client_ip(self):
        # Check X-Forwarded-For first (for proxied setups)
        forwarded = self.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return self.client_address[0]

    def _blocklist_gate(self):
        """If the source IP is on the blocklist, emit a blocked_request log,
        return 403, and return True so the caller aborts. Otherwise False.
        """
        ip = self.get_client_ip()
        if not S.is_blocked(ip):
            return False
        # Ingest endpoints from Graylog/SOC over loopback shouldn't be blocked
        # even if someone blocks 127.0.0.1 by accident — keep them working.
        if ip in ('127.0.0.1', '::1'):
            return False
        S.bump_hit_count(ip)
        method = self.command
        path = self.path.split('?', 1)[0]
        msg = f'Request blocked: {ip} tried {method} {path} (IP on blocklist)'
        print(f'  [BLOCK] {msg}')
        self.emit_auth_log('blocked_request', 'failure', 'anonymous', ip, 'warn', msg)
        self.send_json(403, {'error': 'Your IP is blocked by the SOC',
                             'ip': ip, 'status': 'blocked'})
        return True

    def emit_auth_log(self, action, outcome, username, client_ip, level, message):
        """Emit a server-side ECS auth log and push through the same pipeline
        as client-submitted logs (file + GELF). This ensures every auth attempt
        is recorded, even from non-browser clients (attackers, curl, scripts).
        """
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        category = ['authentication']
        if action == 'user_register':
            category.append('iam')
        source = {'ip': client_ip}
        geo = geoip.lookup(client_ip)
        if geo:
            source['geo'] = {
                'country_name': geo['country'],
                'country_iso_code': geo['country_code'],
                'city_name': geo.get('city', ''),
            }
            source['as'] = {'organization': {'name': geo.get('isp', '')}}
        entry = {
            '@timestamp': ts,
            'event': {
                'kind': 'event',
                'category': category,
                'type': ['start' if outcome == 'success' else 'start'],
                'action': action,
                'outcome': outcome,
                'severity': 0 if outcome == 'success' else 3,
                'provider': 'auth-server',
            },
            'user': {'name': username},
            'source': source,
            'message': message,
            'log': {'level': level, 'logger': 'log-server.auth'},
            'ecs': {'version': '8.11'},
        }
        line = json.dumps(entry, separators=(',', ':'))
        if LogRelayHandler.log_file:
            try:
                with open(LogRelayHandler.log_file, 'a') as f:
                    f.write(line + '\n')
            except Exception:
                pass
        if LogRelayHandler.gelf_url:
            try:
                gelf = ecs_to_gelf(entry, LogRelayHandler.gelf_host)
                req = urllib.request.Request(
                    LogRelayHandler.gelf_url,
                    data=json.dumps(gelf).encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    method='POST',
                )
                urllib.request.urlopen(req, timeout=2)
            except Exception:
                pass
        if LogRelayHandler.forward_url:
            try:
                req = urllib.request.Request(
                    LogRelayHandler.forward_url,
                    data=line.encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    method='POST',
                )
                urllib.request.urlopen(req, timeout=2)
            except Exception:
                pass
        LogRelayHandler.log_count += 1

    def do_POST(self):
        if self._blocklist_gate():
            return

        if self.path == '/api/logout':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b'{}'
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            username = (data.get('username') or 'unknown').strip()
            client_ip = self.get_client_ip()
            print(f'  [AUTH] LOGOUT: {username} from {client_ip}')
            self.emit_auth_log('user_logout', 'success', username, client_ip, 'info',
                               f'User {username} logged out from {client_ip}')
            self.send_json(200, {'status': 'ok', 'message': 'Logged out'})
            return

        if self.path == '/api/auth':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_json(400, {'error': 'Invalid JSON'})
                return

            username = data.get('username', '').strip()
            password = data.get('password', '')

            if not username or not password:
                self.send_json(400, {'error': 'Username and password are required'})
                return

            if len(username) < 2 or len(username) > 30:
                self.send_json(400, {'error': 'Username must be 2-30 characters'})
                return

            if len(password) < 3:
                self.send_json(400, {'error': 'Password must be at least 3 characters'})
                return

            client_ip = self.get_client_ip()

            # Disabled-user gate: SOC Console can disable an account and reject
            # future logins without removing it. Treat as auth_failure so Graylog
            # correlations still see the attempt.
            if S.is_disabled(username):
                disabled_info = S.load_disabled_users().get(username, {})
                print(f'  [AUTH] LOGIN REJECTED: {username} from {client_ip} — account disabled '
                      f'(reason: {disabled_info.get("reason","n/a")})')
                self.emit_auth_log('disabled_account_login_attempt', 'failure', username, client_ip, 'warn',
                                   f'Login attempt for disabled account "{username}" from {client_ip}')
                self.send_json(403, {
                    'status': 'disabled',
                    'message': 'Account disabled by SOC.',
                    'username': username,
                    'ip': client_ip,
                    'reason': disabled_info.get('reason'),
                })
                return

            users = load_users()
            pw_hash = hash_password(password)

            if username in users:
                # User exists — check password
                if users[username]['password'] == pw_hash:
                    users[username]['last_login'] = datetime.now(timezone.utc).isoformat()
                    users[username]['login_count'] = users[username].get('login_count', 0) + 1
                    users[username]['last_ip'] = client_ip
                    save_users(users)
                    is_admin = username == ADMIN_USERNAME
                    print(f'  [AUTH] LOGIN SUCCESS: {username} from {client_ip}{" [ADMIN]" if is_admin else ""}')
                    self.emit_auth_log('user_login', 'success', username, client_ip, 'info',
                                       f'User {username} logged in successfully from {client_ip}')
                    self.send_json(200, {
                        'status': 'success',
                        'message': f'Welcome back, {username}!',
                        'username': username,
                        'ip': client_ip,
                        'login_count': users[username]['login_count'],
                        'isAdmin': is_admin,
                    })
                else:
                    print(f'  [AUTH] LOGIN FAILED: {username} from {client_ip} (wrong password)')
                    self.emit_auth_log('auth_failure', 'failure', username, client_ip, 'warn',
                                       f'Authentication failed for user "{username}" from {client_ip} — wrong password')
                    self.send_json(401, {
                        'status': 'wrong_password',
                        'message': 'User exists but password is incorrect.',
                        'username': username,
                        'ip': client_ip,
                    })
            else:
                # New user — register
                users[username] = {
                    'password': pw_hash,
                    'created': datetime.now(timezone.utc).isoformat(),
                    'last_login': datetime.now(timezone.utc).isoformat(),
                    'login_count': 1,
                    'last_ip': client_ip,
                }
                save_users(users)
                is_admin = username == ADMIN_USERNAME
                print(f'  [AUTH] NEW USER: {username} registered from {client_ip}')
                self.emit_auth_log('user_register', 'success', username, client_ip, 'info',
                                   f'New account registered: {username} from {client_ip}')
                self.send_json(201, {
                    'status': 'created',
                    'message': f'Account created! Welcome, {username}!',
                    'username': username,
                    'ip': client_ip,
                    'login_count': 1,
                    'isAdmin': is_admin,
                })
            return

        if self.path == '/api/logs':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_json(400, {'error': 'Invalid JSON'})
                return

            # Accept single log or array
            logs = data if isinstance(data, list) else [data]

            for log_entry in logs:
                line = json.dumps(log_entry, separators=(',', ':'))

                # Append to file
                if LogRelayHandler.log_file:
                    with open(LogRelayHandler.log_file, 'a') as f:
                        f.write(line + '\n')

                # Forward to Logstash
                if LogRelayHandler.forward_url:
                    try:
                        req = urllib.request.Request(
                            LogRelayHandler.forward_url,
                            data=line.encode('utf-8'),
                            headers={'Content-Type': 'application/json'},
                            method='POST'
                        )
                        urllib.request.urlopen(req, timeout=2)
                    except Exception:
                        # Don't fail if Logstash is down
                        pass

                # Forward to Graylog as GELF
                if LogRelayHandler.gelf_url:
                    try:
                        gelf_doc = ecs_to_gelf(log_entry, LogRelayHandler.gelf_host)
                        req = urllib.request.Request(
                            LogRelayHandler.gelf_url,
                            data=json.dumps(gelf_doc).encode('utf-8'),
                            headers={'Content-Type': 'application/json'},
                            method='POST'
                        )
                        urllib.request.urlopen(req, timeout=2)
                    except Exception:
                        # Don't fail if Graylog is down
                        pass

                LogRelayHandler.log_count += 1

                # Print to terminal
                level = log_entry.get('log', {}).get('level', 'info').upper()
                action = log_entry.get('event', {}).get('action', '?')
                msg = log_entry.get('message', '')
                ts = log_entry.get('@timestamp', '')[:19]
                print(f'  [{ts}] {level:5s} | {action:25s} | {msg}')

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'received': len(logs), 'total': LogRelayHandler.log_count}).encode())
            return

        if self.path == '/api/simulate':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_json(400, {'error': 'Invalid JSON'})
                return

            attack_type = data.get('type', '')
            intensity = data.get('intensity', 'medium')
            duration = data.get('duration', 60)
            source_mode = data.get('sourceMode', 'single')
            target_mode = data.get('targetMode', 'common')
            rate = int(data.get('rate', 0))  # target eps (load_test only)

            if attack_type == 'stop_all':
                with sim_lock:
                    for sid in list(active_simulations.keys()):
                        active_simulations[sid]['active'] = False
                    active_simulations.clear()
                self.send_json(200, {'status': 'stopped', 'message': 'All simulations stopped'})
                return

            sim_id = f'{attack_type}-{int(time.time())}'
            sim_state = {'active': True, 'type': attack_type, 'generated': 0, 'target_rate': rate}

            with sim_lock:
                active_simulations[sim_id] = sim_state

            thread = threading.Thread(
                target=run_simulation,
                args=(sim_id, sim_state, attack_type, intensity, duration, source_mode, target_mode,
                      LogRelayHandler.log_file, LogRelayHandler.forward_url),
                daemon=True
            )
            thread.start()

            self.send_json(200, {
                'status': 'started',
                'simId': sim_id,
                'type': attack_type,
                'intensity': intensity,
                'duration': duration,
            })
            return

        if self.path == '/api/simulate/status':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length else b'{}'
            with sim_lock:
                status = {sid: {'type': s['type'], 'generated': s['generated'], 'active': s['active']}
                          for sid, s in active_simulations.items()}
            self.send_json(200, {'simulations': status, 'totalLogs': LogRelayHandler.log_count})
            return

        self.send_json(404, {'error': 'Not found'})

    def do_GET(self):
        if self._blocklist_gate():
            return

        if self.path == '/api/simulate/status':
            with sim_lock:
                status = {sid: {'type': s['type'], 'generated': s['generated'], 'active': s['active']}
                          for sid, s in active_simulations.items()}
            self.send_json(200, {'simulations': status, 'totalLogs': LogRelayHandler.log_count})
            return

        if self.path == '/api/logs':
            # Return last N logs
            n = 50
            lines = []
            if LogRelayHandler.log_file and os.path.exists(LogRelayHandler.log_file):
                with open(LogRelayHandler.log_file, 'r') as f:
                    all_lines = f.readlines()
                    lines = all_lines[-n:]

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            logs = [json.loads(l) for l in lines if l.strip()]
            self.wfile.write(json.dumps({'logs': logs, 'total': LogRelayHandler.log_count}).encode())
            return

        # Serve static files
        return super().do_GET()

    def do_OPTIONS(self):
        # CORS preflight
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress default access logs to keep output clean
        pass


## ─── Attack Simulation Engine ───

TOR_EXIT_NODES = ['185.220.101.42', '185.220.101.33', '185.220.100.252', '23.129.64.210', '51.15.43.205']
SCANNER_IPS = ['45.155.205.233', '91.240.118.172', '103.251.167.20', '196.251.73.39', '78.128.113.34',
               '162.247.74.27', '171.25.193.77', '104.244.76.13', '209.141.58.146', '5.2.69.50']
COMMON_USERNAMES = ['admin', 'root', 'administrator', 'test', 'user', 'guest', 'operator',
                    'sysadmin', 'backup', 'service', 'deploy', 'jenkins', 'postgres', 'mysql',
                    'ftp', 'www-data', 'ubuntu', 'centos', 'pi', 'oracle']
PLAYER_NAMES = ['CyberNinja', 'H4ckM4ster', 'SecOpsLead', 'ThreatHunter', 'RedTeam01',
                'BlueTeam42', 'PenTester', 'SOCAnalyst', 'IRHandler', 'MalwareRE']

# Persistent profile per player — consistent IP set + rank. Sim uses these so
# "MalwareRE" always logs from Japan at rank Platinum, not a fresh random IP
# every event. Two IPs for some players = "occasional travel / VPN".
PLAYER_PROFILES = {
    'CyberNinja':   {'ips': ['126.163.42.150', '126.163.42.88'],  'rank': 'Platinum'},
    'H4ckM4ster':   {'ips': ['207.126.117.10', '207.126.117.88'], 'rank': 'Gold'},
    'SecOpsLead':   {'ips': ['85.214.205.100'],                   'rank': 'Diamond'},
    'ThreatHunter': {'ips': ['81.2.69.142'],                      'rank': 'Gold'},
    'RedTeam01':    {'ips': ['142.250.100.13'],                   'rank': 'Silver'},
    'BlueTeam42':   {'ips': ['203.220.50.1'],                     'rank': 'Platinum'},
    'PenTester':    {'ips': ['62.112.200.150'],                   'rank': 'Diamond'},
    'SOCAnalyst':   {'ips': ['194.47.200.10'],                    'rank': 'Gold'},
    'IRHandler':    {'ips': ['78.193.205.10'],                    'rank': 'Silver'},
    'MalwareRE':    {'ips': ['103.50.100.50'],                    'rank': 'Platinum'},
}
TERMINAL_DATA = ['NETWORK TOPOLOGY', 'USER DATABASE', 'INCIDENT LOG', 'THREAT INTELLIGENCE',
                 'SYSTEM AUDIT', 'ENCRYPTION KEYS', 'FIREWALL RULES', 'ACCESS LOGS']

def get_ips(source_mode, count=1):
    if source_mode == 'single':
        ip = random.choice(SCANNER_IPS)
        return [ip] * count
    elif source_mode == 'distributed':
        return [f'{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}' for _ in range(count)]
    elif source_mode == 'tor':
        return [random.choice(TOR_EXIT_NODES) for _ in range(count)]
    return [random.choice(SCANNER_IPS) for _ in range(count)]

def get_targets(target_mode, count=1):
    if target_mode == 'admin':
        return ['admin'] * count
    elif target_mode == 'common':
        return [random.choice(COMMON_USERNAMES) for _ in range(count)]
    elif target_mode == 'random':
        return [f'user_{random.randint(1000,9999)}' for _ in range(count)]
    return [random.choice(COMMON_USERNAMES) for _ in range(count)]

def get_delay(intensity):
    if intensity == 'low': return random.uniform(2.0, 5.0)
    elif intensity == 'medium': return random.uniform(0.5, 2.0)
    elif intensity == 'high': return random.uniform(0.05, 0.3)
    return 1.0

SERVERS_FILE = 'data/servers.json'
_DEFAULT_SERVER = {
    'id': 'siem-arcade-01',
    'name': 'siem-arcade-01',
    'data_center': 'eu-west-1',
    'environment': 'production',
}


def _load_servers():
    """Return the currently registered servers. Falls back to a single default."""
    if os.path.exists(SERVERS_FILE):
        try:
            with open(SERVERS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict) and data.get('servers'):
                    return data['servers']
        except Exception:
            pass
    return [_DEFAULT_SERVER]


def _pick_server():
    return random.choice(_load_servers())


_GAMEPLAY_CATEGORIES = {'gameplay', 'process', 'game', 'session'}


def make_ecs_log(action, outcome, user, ip, severity=0, level='info', message='', category='authentication', labels=None):
    # Geo enrichment (non-blocking). First lookup of an IP queues it;
    # subsequent lookups hit the cache.
    geo = geoip.lookup(ip)
    source = {'ip': ip}
    if geo:
        source['geo'] = {
            'country_name': geo['country'],
            'country_iso_code': geo['country_code'],
            'city_name': geo.get('city', ''),
        }
        source['as'] = {'organization': {'name': geo.get('isp', '')}}
    else:
        source['geo'] = {'country_name': 'Unknown', 'country_iso_code': 'XX'}

    server = _pick_server()
    is_gameplay = category in _GAMEPLAY_CATEGORIES

    base_labels = {'environment': server.get('environment', 'production')}
    if is_gameplay:
        base_labels['game_rank'] = random.choice(['Bronze', 'Silver', 'Gold', 'Platinum', 'Diamond'])
        base_labels['game_score'] = random.randint(0, 10000)
    # auth_attempts and game_rank on auth events were fake — don't set them here.

    return {
        '@timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        'event': {
            'kind': 'event',
            'category': [category],
            'type': ['start'],
            'action': action,
            'severity': severity,
            'outcome': outcome,
            'duration': 0,
        },
        'host': {
            'name': server['name'],
            'id': server.get('id', server['name']),
        },
        'cloud': {
            'availability_zone': server.get('data_center', 'eu-west-1'),
            'region': server.get('data_center', 'eu-west-1').rsplit('-', 1)[0] if '-' in server.get('data_center', '') else server.get('data_center', ''),
        },
        'user': {
            'name': user,
            'id': f'usr-{"".join(random.choices("0123456789abcdef", k=8))}',
            'roles': ['player'],
        },
        'source': source,
        'session': {'id': f'sess-{"".join(random.choices("0123456789abcdef", k=8))}'},
        'message': message,
        'log': {'level': level},
        'labels': {**base_labels, **(labels or {})},
        'ecs': {'version': '8.11'},
    }

def write_log(log_entry, log_file, forward_url):
    line = json.dumps(log_entry, separators=(',', ':'))
    if log_file:
        with open(log_file, 'a') as f:
            f.write(line + '\n')
    if forward_url:
        try:
            req = urllib.request.Request(forward_url, data=line.encode('utf-8'),
                                        headers={'Content-Type': 'application/json'}, method='POST')
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass
    # Forward to Graylog via GELF so simulated attacks trigger the same
    # detection rules as real traffic.
    if LogRelayHandler.gelf_url:
        try:
            gelf = ecs_to_gelf(log_entry, LogRelayHandler.gelf_host)
            req = urllib.request.Request(LogRelayHandler.gelf_url, data=json.dumps(gelf).encode('utf-8'),
                                         headers={'Content-Type': 'application/json'}, method='POST')
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass
    LogRelayHandler.log_count += 1
    level = log_entry.get('log', {}).get('level', 'info').upper()
    action = log_entry.get('event', {}).get('action', '?')
    msg = log_entry.get('message', '')[:80]
    ts = log_entry.get('@timestamp', '')[:19]
    print(f'  [{ts}] {level:5s} | {"[SIM] " + action:31s} | {msg}')

def run_simulation(sim_id, state, attack_type, intensity, duration, source_mode, target_mode, log_file, forward_url):
    print(f'\n  [SIM] Starting {attack_type} simulation (intensity={intensity}, duration={duration}s)')
    end_time = time.time() + duration

    try:
        if attack_type == 'normal_activity':
            sim_normal_activity(state, intensity, end_time, log_file, forward_url)
        elif attack_type == 'brute_force':
            sim_brute_force(state, intensity, end_time, source_mode, target_mode, log_file, forward_url)
        elif attack_type == 'credential_stuffing':
            sim_credential_stuffing(state, intensity, end_time, log_file, forward_url)
        elif attack_type == 'dos':
            sim_dos(state, intensity, end_time, log_file, forward_url)
        elif attack_type == 'ddos':
            sim_ddos(state, intensity, end_time, log_file, forward_url)
        elif attack_type == 'load_test':
            sim_load_test(state, state.get('target_rate', 1000), end_time, log_file, forward_url)
        elif attack_type == 'account_takeover':
            sim_account_takeover(state, intensity, end_time, source_mode, target_mode, log_file, forward_url)
    except Exception as e:
        print(f'  [SIM] Error in {attack_type}: {e}')

    state['active'] = False
    print(f'  [SIM] Finished {attack_type}: {state["generated"]} logs generated')

def sim_normal_activity(state, intensity, end_time, log_file, forward_url):
    while time.time() < end_time and state['active']:
        user = random.choice(PLAYER_NAMES)
        profile = PLAYER_PROFILES.get(user)
        # Pick one of the player's registered IPs — consistent across events
        ip = random.choice(profile['ips']) if profile else \
             f'{random.randint(80,200)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}'
        rank_label = {'game_rank': profile['rank']} if profile else {}

        # Login (auth event — no rank/score baked in)
        write_log(make_ecs_log('user_login', 'success', user, ip, 0, 'info',
                               f'User {user} logged in from {ip}'), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))
        # Gameplay actions — carry player's persistent rank
        for _ in range(random.randint(3, 8)):
            if not state['active'] or time.time() >= end_time: break
            action = random.choice(['player_move', 'player_shoot', 'enemy_kill', 'player_shoot', 'player_shoot'])
            write_log(make_ecs_log(action, 'success', user, ip, 0, 'info',
                                   f'{user} performed {action}', 'process',
                                   labels=rank_label),
                      log_file, forward_url)
            state['generated'] += 1
            time.sleep(get_delay(intensity) * 0.5)
        # Session end
        write_log(make_ecs_log('session_end', 'success', user, ip, 0, 'info',
                               f'Session ended for {user}', 'session',
                               labels=rank_label), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))

def sim_brute_force(state, intensity, end_time, source_mode, target_mode, log_file, forward_url):
    ips = get_ips(source_mode, 50)
    while time.time() < end_time and state['active']:
        ip = random.choice(ips)
        user = random.choice(get_targets(target_mode))
        write_log(make_ecs_log('auth_failure', 'failure', user, ip, 3, 'warn',
                               f'Failed login for "{user}" from {ip} — wrong password',
                               labels={'attack_type': 'brute_force', 'threat_level': 'high'}), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))

def sim_credential_stuffing(state, intensity, end_time, log_file, forward_url):
    ip = random.choice(SCANNER_IPS)
    idx = 0
    while time.time() < end_time and state['active']:
        user = f'{random.choice(COMMON_USERNAMES)}_{idx}'
        write_log(make_ecs_log('auth_failure', 'failure', user, ip, 3, 'warn',
                               f'Credential stuffing: failed login for "{user}" from {ip}',
                               labels={'attack_type': 'credential_stuffing', 'threat_level': 'high'}), log_file, forward_url)
        state['generated'] += 1
        idx += 1
        time.sleep(get_delay(intensity))

def sim_load_test(state, target_rate, end_time, log_file, forward_url):
    """Synthetic load generator for capacity validation.

    Two transport modes:
      • GELF TCP (preferred, --gelf-tcp set): each worker opens one
        long-lived TCP socket and streams null-terminated GELF JSON
        messages. No HTTP parse per event, no request/response round-trip.
      • GELF HTTP (fallback): one keep-alive HTTP connection per worker,
        one request per event. Capped by HTTP parse cost on the Graylog
        input (~3 k eps per node in testing).

    Every event carries `labels.load_test=1` and `event.kind=metric` so the
    detection rules can exclude them and so forensic searches can filter.
    Skips the NDJSON archive write — durable storage is pointless for a
    load test and would bottleneck at this rate.

    target_rate clamps to [100, 20000] eps.
    """
    import http.client
    import urllib.parse as _up

    target_rate = max(100, min(20000, int(target_rate or 1000)))

    tcp_target = LogRelayHandler.gelf_tcp   # (host, port) or None
    gelf_url = LogRelayHandler.gelf_url
    gelf_host = LogRelayHandler.gelf_host
    parsed = _up.urlparse(gelf_url) if gelf_url else None
    using_tcp = tcp_target is not None

    # TCP is orders of magnitude cheaper per event, so we can go with
    # fewer heavier workers (one socket each) and get higher per-worker
    # throughput. HTTP path keeps the old 50-worker sweet spot.
    if using_tcp:
        num_workers = min(32, max(4, target_rate // 600 + 1))
    else:
        num_workers = min(50, max(4, target_rate // 220 + 1))
    per_worker_rate = target_rate / num_workers
    interval = 1.0 / per_worker_rate

    print(f'  [LOAD] transport={"GELF TCP" if using_tcp else "GELF HTTP"} '
          f'target={target_rate} eps workers={num_workers} '
          f'per-worker={per_worker_rate:.1f} eps (interval {interval*1000:.2f} ms)')

    def _open_tcp():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s.settimeout(5)
        s.connect(tcp_target)
        return s

    def _worker(wid):
        sock = None
        conn = None
        if using_tcp:
            try:
                sock = _open_tcp()
            except Exception as e:
                print(f'  [LOAD] worker {wid} TCP connect failed: {e}')
                return
        elif parsed:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)

        ecs_version = {'version': '8.11'}
        next_at = time.time()
        sent = 0
        # Pre-resolve — building the full ECS dict per event is wasted work
        # on the TCP path. Use a slimmer payload when we don't need ECS
        # round-tripping; the detection rules only key off a few fields.
        while state['active'] and time.time() < end_time:
            now = time.time()
            if now < next_at:
                time.sleep(next_at - now)
            fake_user = f'loadtest_{wid:02d}_{sent % 100:03d}'
            # Rotate IPs in an RFC6598 (shared-address) range so they don't
            # collide with real player/attacker IPs and are easy to filter.
            ip = f'100.{wid % 64 + 64}.{(sent // 256) % 256}.{sent % 256}'
            action = 'player_move' if sent % 3 else ('enemy_kill' if sent % 2 else 'player_shoot')

            if using_tcp:
                # Flat GELF — skip ecs_to_gelf's flattener by inlining just
                # the fields the pipeline actually needs.
                gelf = {
                    'version': '1.1',
                    'host': gelf_host,
                    'short_message': action,
                    'timestamp': time.time(),
                    'level': 6,
                    '_event_kind': 'metric',
                    '_event_action': action,
                    '_event_outcome': 'success',
                    '_user_name': fake_user,
                    '_source_ip': ip,
                    '_labels_load_test': '1',
                    '_labels_worker_id': str(wid),
                }
                try:
                    sock.sendall(json.dumps(gelf, separators=(',', ':')).encode() + b'\x00')
                except Exception:
                    try: sock.close()
                    except Exception: pass
                    try: sock = _open_tcp()
                    except Exception: sock = None
            elif conn:
                entry = {
                    '@timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                    'event': {'kind': 'metric', 'category': ['process'], 'type': ['info'],
                              'action': action, 'outcome': 'success'},
                    'user': {'name': fake_user, 'roles': ['player']},
                    'source': {'ip': ip},
                    'host': {'name': 'load-test-gen'},
                    'message': f'load-test {action} from {fake_user}',
                    'log': {'level': 'info', 'logger': 'load-test'},
                    'labels': {'load_test': '1', 'worker_id': str(wid)},
                    'ecs': ecs_version,
                }
                try:
                    gelf = ecs_to_gelf(entry, gelf_host)
                    body = json.dumps(gelf, separators=(',', ':')).encode()
                    conn.request('POST', parsed.path, body, {'Content-Type': 'application/json'})
                    resp = conn.getresponse()
                    resp.read()
                except Exception:
                    try: conn.close()
                    except Exception: pass
                    try:
                        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
                    except Exception:
                        conn = None

            sent += 1
            state['generated'] += 1
            next_at += interval
            if time.time() - next_at > 1.0:
                next_at = time.time()

        if sock:
            try: sock.close()
            except Exception: pass
        if conn:
            try: conn.close()
            except Exception: pass

    threads = [threading.Thread(target=_worker, args=(i,), daemon=True,
                                name=f'loadtest-{i}')
               for i in range(num_workers)]
    for t in threads: t.start()
    for t in threads: t.join()
    print(f'  [LOAD] done — total {state["generated"]} events')


def sim_dos(state, intensity, end_time, log_file, forward_url):
    """Single-source DoS flood. Picks ONE attacker IP and hammers from it so
    the per-IP 'DoS flood' rule trips reliably (>= 30 events / 10s / IP)."""
    ip = random.choice(SCANNER_IPS)
    while time.time() < end_time and state['active']:
        write_log(make_ecs_log('session_start', 'success', f'anon_{random.randint(1000,9999)}',
                               ip, 2, 'warn', f'DoS: Connection flood from {ip}', 'session',
                               labels={'attack_type': 'dos', 'threat_level': 'high'}),
                  log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity) * 0.2)

def sim_ddos(state, intensity, end_time, log_file, forward_url):
    """Distributed DoS flood. Every event uses a different random source IP,
    so the per-IP rule does NOT trip — the global-rate 'DDoS flood' rule
    (>= 300 events / 30s, no group_by) is what catches it."""
    while time.time() < end_time and state['active']:
        ip = f'{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        write_log(make_ecs_log('session_start', 'success', f'anon_{random.randint(1000,9999)}',
                               ip, 2, 'warn', f'DDoS: Connection from {ip}', 'session',
                               labels={'attack_type': 'ddos', 'threat_level': 'critical'}),
                  log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity) * 0.2)

def sim_account_takeover(state, intensity, end_time, source_mode, target_mode, log_file, forward_url):
    target = random.choice(get_targets(target_mode))
    attack_ip = random.choice(get_ips(source_mode))
    # Phase 1: brute force
    for i in range(random.randint(5, 15)):
        if not state['active'] or time.time() >= end_time: return
        write_log(make_ecs_log('auth_failure', 'failure', target, attack_ip, 3, 'warn',
                               f'Brute force attempt {i+1} on "{target}" from {attack_ip}',
                               labels={'attack_type': 'account_takeover', 'threat_level': 'high'}), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))
    # Phase 2: success
    write_log(make_ecs_log('user_login', 'success', target, attack_ip, 4, 'warn',
                           f'COMPROMISED: "{target}" login succeeded from attacker IP {attack_ip}',
                           labels={'attack_type': 'account_takeover', 'threat_level': 'critical'}), log_file, forward_url)
    state['generated'] += 1
    time.sleep(1)
    # Phase 3: malicious actions
    while time.time() < end_time and state['active']:
        action = random.choice(['terminal_access', 'special_ability', 'terminal_access'])
        write_log(make_ecs_log(action, 'success', target, attack_ip, 4, 'warn',
                               f'POST-COMPROMISE: {target} performing {action} from {attack_ip}', 'process',
                               labels={'attack_type': 'account_takeover', 'threat_level': 'critical'}), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))


def main():
    parser = argparse.ArgumentParser(description='SIEM Game Log Relay Server')
    parser.add_argument('--port', type=int, default=8080, help='Server port (default: 8080)')
    parser.add_argument('--logfile', type=str, default='logs/game-logs.ndjson', help='Output log file path')
    parser.add_argument('--forward', type=str, default=None, help='Logstash HTTP input URL to forward logs to')
    parser.add_argument('--gelf', type=str, default=None, help='Graylog GELF HTTP input URL (e.g. http://localhost:12201/gelf)')
    parser.add_argument('--gelf-tcp', type=str, default=None,
                        help='Graylog GELF TCP endpoint host:port for high-volume load generation (e.g. 127.0.0.1:12202)')
    parser.add_argument('--gelf-host', type=str, default=socket.gethostname() or 'siem-arcade-game',
                        help='Source host name to tag GELF messages with (default: machine hostname)')
    args = parser.parse_args()

    # Ensure log directory exists
    log_dir = os.path.dirname(args.logfile)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    LogRelayHandler.log_file = args.logfile
    LogRelayHandler.forward_url = args.forward
    LogRelayHandler.gelf_url = args.gelf
    LogRelayHandler.gelf_host = args.gelf_host
    # Parse --gelf-tcp into (host, port) tuple for sim_load_test
    LogRelayHandler.gelf_tcp = None
    if args.gelf_tcp:
        _host, _, _port = args.gelf_tcp.rpartition(':')
        LogRelayHandler.gelf_tcp = (_host or '127.0.0.1', int(_port))

    print(f'========================================')
    print(f'  SIEM Game Log Relay Server')
    print(f'========================================')
    print(f'  Game:     http://localhost:{args.port}')
    print(f'  Log API:  http://localhost:{args.port}/api/logs')
    print(f'  Log file: {args.logfile}')
    if args.forward:
        print(f'  Forward:  {args.forward}')
    if args.gelf:
        print(f'  GELF:     {args.gelf}  (host={args.gelf_host})')
    if args.gelf_tcp:
        print(f'  GELF TCP: {args.gelf_tcp}  (high-volume path)')
    print(f'========================================')
    print(f'  Waiting for logs...\n')

    server = HTTPServer(('0.0.0.0', args.port), LogRelayHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f'\n\nShutdown. Total logs received: {LogRelayHandler.log_count}')
        print(f'Logs saved to: {args.logfile}')
        server.server_close()


if __name__ == '__main__':
    main()
