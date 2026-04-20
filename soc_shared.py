"""
Shared state between log-server.py and soc-server.py.

Two JSON files under data/ hold the mutable enforcement state:
  - blocklist.json       — {ip: {blocked_at, blocked_by, reason, hit_count, kernel, alert_id}}
  - disabled_users.json  — {username: {disabled_at, disabled_by, reason}}

Writes are atomic (tmp-file + os.replace) and serialised behind a lock so both
processes can safely mutate them. Reads hit the filesystem on each call — good
enough for our scale (small JSON, small number of entries, sub-ms cost).
"""
import json
import os
import threading
from datetime import datetime, timezone

BLOCKLIST_FILE = 'data/blocklist.json'
DISABLED_USERS_FILE = 'data/disabled_users.json'

_write_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + f'{datetime.now(timezone.utc).microsecond // 1000:03d}Z'


def _load(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def _save(path, data):
    with _write_lock:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f'{path}.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)


# ─── Blocklist ─────────────────────────────────────────────────────────────

def load_blocklist():
    return _load(BLOCKLIST_FILE)


def is_blocked(ip):
    return ip in load_blocklist()


def block_ip(ip, reason='', actor='admin', alert_id=None, kernel=False):
    data = load_blocklist()
    data[ip] = {
        'blocked_at': _now(),
        'blocked_by': actor,
        'reason': reason,
        'alert_id': alert_id,
        'hit_count': data.get(ip, {}).get('hit_count', 0),
        'kernel': kernel,
    }
    _save(BLOCKLIST_FILE, data)
    return data[ip]


def unblock_ip(ip):
    data = load_blocklist()
    if ip in data:
        removed = data.pop(ip)
        _save(BLOCKLIST_FILE, data)
        return removed
    return None


def bump_hit_count(ip):
    """Called by log-server on each blocked request; best-effort, not strict."""
    data = load_blocklist()
    if ip in data:
        data[ip]['hit_count'] = data[ip].get('hit_count', 0) + 1
        data[ip]['last_hit'] = _now()
        _save(BLOCKLIST_FILE, data)


# ─── Disabled users ────────────────────────────────────────────────────────

def load_disabled_users():
    return _load(DISABLED_USERS_FILE)


def is_disabled(username):
    return username in load_disabled_users()


def disable_user(username, reason='', actor='admin', alert_id=None):
    data = load_disabled_users()
    data[username] = {
        'disabled_at': _now(),
        'disabled_by': actor,
        'reason': reason,
        'alert_id': alert_id,
    }
    _save(DISABLED_USERS_FILE, data)
    return data[username]


def enable_user(username):
    data = load_disabled_users()
    if username in data:
        removed = data.pop(username)
        _save(DISABLED_USERS_FILE, data)
        return removed
    return None
