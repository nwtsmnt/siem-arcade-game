#!/usr/bin/env python3
"""
SIEM Log Relay Server
- Receives logs via HTTP POST from the game
- Appends each log to a .ndjson file on disk
- Optionally forwards to Logstash HTTP input
- Also serves the game files (no separate web server needed)

Usage:
  python3 log-server.py [--port 8080] [--logfile logs/game-logs.ndjson] [--forward http://localhost:5044]

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
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

USERS_FILE = 'data/users.json'
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = hashlib.sha256('admin'.encode('utf-8')).hexdigest()

# Attack simulation state
active_simulations = {}
sim_lock = threading.Lock()


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

    def do_POST(self):
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
                    except Exception as e:
                        # Don't fail if Logstash is down
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

            if attack_type == 'stop_all':
                with sim_lock:
                    for sid in list(active_simulations.keys()):
                        active_simulations[sid]['active'] = False
                    active_simulations.clear()
                self.send_json(200, {'status': 'stopped', 'message': 'All simulations stopped'})
                return

            sim_id = f'{attack_type}-{int(time.time())}'
            sim_state = {'active': True, 'type': attack_type, 'generated': 0}

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

def make_ecs_log(action, outcome, user, ip, severity=0, level='info', message='', category='authentication', labels=None):
    return {
        '@timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        'event': {
            'kind': 'event',
            'category': [category],
            'type': ['start'],
            'action': action,
            'severity': severity,
            'outcome': outcome,
            'duration': 0
        },
        'user': {
            'name': user,
            'id': f'usr-{"".join(random.choices("0123456789abcdef", k=8))}',
            'roles': ['player']
        },
        'source': {'ip': ip, 'geo': {'country_name': 'Unknown', 'country_iso_code': 'XX'}},
        'session': {'id': f'sess-{"".join(random.choices("0123456789abcdef", k=8))}'},
        'message': message,
        'log': {'level': level},
        'labels': {
            'game_rank': random.choice(['Bronze', 'Silver', 'Gold', 'Platinum']),
            'game_score': random.randint(0, 10000),
            'auth_attempts': random.randint(1, 50),
            'player_status': 'active',
            **(labels or {})
        },
        'ecs': {'version': '8.11'}
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
        elif attack_type == 'ddos':
            sim_ddos(state, intensity, end_time, log_file, forward_url)
        elif attack_type == 'privilege_escalation':
            sim_privilege_escalation(state, intensity, end_time, log_file, forward_url)
        elif attack_type == 'data_exfiltration':
            sim_data_exfiltration(state, intensity, end_time, log_file, forward_url)
        elif attack_type == 'insider_threat':
            sim_insider_threat(state, intensity, end_time, log_file, forward_url)
        elif attack_type == 'account_takeover':
            sim_account_takeover(state, intensity, end_time, source_mode, target_mode, log_file, forward_url)
    except Exception as e:
        print(f'  [SIM] Error in {attack_type}: {e}')

    state['active'] = False
    print(f'  [SIM] Finished {attack_type}: {state["generated"]} logs generated')

def sim_normal_activity(state, intensity, end_time, log_file, forward_url):
    while time.time() < end_time and state['active']:
        user = random.choice(PLAYER_NAMES)
        ip = f'{random.randint(80,200)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}'
        sess = f'sess-{"".join(random.choices("0123456789abcdef", k=8))}'
        # Login
        write_log(make_ecs_log('user_login', 'success', user, ip, 0, 'info', f'User {user} logged in from {ip}'), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))
        # Gameplay actions
        for _ in range(random.randint(3, 8)):
            if not state['active'] or time.time() >= end_time: break
            action = random.choice(['player_move', 'player_shoot', 'enemy_kill', 'player_shoot', 'player_shoot'])
            write_log(make_ecs_log(action, 'success', user, ip, 0, 'info', f'{user} performed {action}', 'process'), log_file, forward_url)
            state['generated'] += 1
            time.sleep(get_delay(intensity) * 0.5)
        # Logout
        write_log(make_ecs_log('session_end', 'success', user, ip, 0, 'info', f'Session ended for {user}', 'session'), log_file, forward_url)
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

def sim_ddos(state, intensity, end_time, log_file, forward_url):
    while time.time() < end_time and state['active']:
        ip = f'{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
        write_log(make_ecs_log('session_start', 'success', f'anon_{random.randint(1000,9999)}', ip, 2, 'warn',
                               f'DDoS: Connection flood from {ip}', 'session',
                               labels={'attack_type': 'ddos', 'threat_level': 'critical'}), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity) * 0.2)

def sim_privilege_escalation(state, intensity, end_time, log_file, forward_url):
    user = random.choice(PLAYER_NAMES)
    ip = f'{random.randint(80,200)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}'
    write_log(make_ecs_log('user_login', 'success', user, ip, 0, 'info', f'{user} logged in normally'), log_file, forward_url)
    state['generated'] += 1
    time.sleep(2)
    while time.time() < end_time and state['active']:
        action = random.choice(['terminal_access', 'terminal_access', 'special_ability'])
        terminal = random.choice(TERMINAL_DATA)
        write_log(make_ecs_log(action, 'success', user, ip, 4, 'warn',
                               f'ESCALATION: {user} accessed {terminal} with elevated privileges', 'process',
                               labels={'attack_type': 'privilege_escalation', 'threat_level': 'critical'}), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))

def sim_data_exfiltration(state, intensity, end_time, log_file, forward_url):
    user = random.choice(PLAYER_NAMES)
    ip = random.choice(SCANNER_IPS)
    while time.time() < end_time and state['active']:
        terminal = random.choice(TERMINAL_DATA)
        size_kb = random.randint(500, 50000)
        write_log(make_ecs_log('terminal_access', 'success', user, ip, 4, 'warn',
                               f'EXFILTRATION: {user} downloaded {size_kb}KB from {terminal}', 'process',
                               labels={'attack_type': 'data_exfiltration', 'threat_level': 'critical', 'data_size_kb': str(size_kb)}), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))

def sim_insider_threat(state, intensity, end_time, log_file, forward_url):
    user = random.choice(PLAYER_NAMES)
    ip = f'10.0.{random.randint(1,10)}.{random.randint(1,254)}'
    while time.time() < end_time and state['active']:
        action = random.choice(['terminal_access', 'player_move', 'terminal_access', 'special_ability'])
        write_log(make_ecs_log(action, 'success', user, ip, 2, 'warn',
                               f'INSIDER: Unusual {action} by {user} at off-hours from internal IP {ip}', 'process',
                               labels={'attack_type': 'insider_threat', 'threat_level': 'medium'}), log_file, forward_url)
        state['generated'] += 1
        time.sleep(get_delay(intensity))

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
    args = parser.parse_args()

    # Ensure log directory exists
    log_dir = os.path.dirname(args.logfile)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    LogRelayHandler.log_file = args.logfile
    LogRelayHandler.forward_url = args.forward

    print(f'========================================')
    print(f'  SIEM Game Log Relay Server')
    print(f'========================================')
    print(f'  Game:     http://localhost:{args.port}')
    print(f'  Log API:  http://localhost:{args.port}/api/logs')
    print(f'  Log file: {args.logfile}')
    if args.forward:
        print(f'  Forward:  {args.forward}')
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
