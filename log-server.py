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
import sys
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

USERS_FILE = 'data/users.json'


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
                    print(f'  [AUTH] LOGIN SUCCESS: {username} from {client_ip}')
                    self.send_json(200, {
                        'status': 'success',
                        'message': f'Welcome back, {username}!',
                        'username': username,
                        'ip': client_ip,
                        'login_count': users[username]['login_count'],
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
                print(f'  [AUTH] NEW USER: {username} registered from {client_ip}')
                self.send_json(201, {
                    'status': 'created',
                    'message': f'Account created! Welcome, {username}!',
                    'username': username,
                    'ip': client_ip,
                    'login_count': 1,
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

        self.send_json(404, {'error': 'Not found'})

    def do_GET(self):
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
