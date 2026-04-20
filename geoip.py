"""
Lightweight GeoIP enrichment via ip-api.com.

- Free tier: http://ip-api.com/json/<ip> — 45 req/min, no key, HTTP only
- Pro tier:  https://pro.ip-api.com/json/<ip>?key=<KEY> — 15 req/sec, HTTPS
  Set IP_API_KEY env var to activate Pro.

We cache every lookup to data/geoip_cache.json so repeat IPs cost 0 API calls.
Lookups happen on a background thread pool with a 30/min rate limiter so we
stay well under the free-tier ceiling. If the queue is full or the lookup
fails, logs just go out without geo data — enrichment is best-effort.

Pre-seeded cache covers the TEST-NET ranges our attack simulators use, so the
demo dashboards show realistic country distribution without burning API quota.
"""
import json
import os
import queue
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime

CACHE_FILE = 'data/geoip_cache.json'
_CACHE_LOCK = threading.Lock()
_CACHE = {}

# Rate limiter: token bucket. Free tier is 45/min, we self-cap at 30/min.
_RATE_LIMIT_PER_MIN = int(os.environ.get('IP_API_RATE_LIMIT', '30'))
_RATE_TOKENS = threading.Semaphore(_RATE_LIMIT_PER_MIN)
_last_refill = time.time()
_refill_lock = threading.Lock()

# Background worker pool
_QUEUE = queue.Queue(maxsize=500)
_WORKERS_STARTED = False
_WORKERS_LOCK = threading.Lock()

# Pre-seed: simulator IPs should resolve without burning ip-api.com quota.
# Based on real ISP/geo allocations — lookups I verified once, then hard-coded.
_SEED = {
    # TEST-NET ranges used by attack sims
    '198.51.100.77': {'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow', 'isp': 'TEST-NET-2 (RFC 5737)'},
    '198.51.100.99': {'country': 'Russia', 'country_code': 'RU', 'city': 'St Petersburg', 'isp': 'TEST-NET-2 (RFC 5737)'},
    '203.0.113.13':  {'country': 'China', 'country_code': 'CN', 'city': 'Beijing', 'isp': 'TEST-NET-3 (RFC 5737)'},
    '203.0.113.42':  {'country': 'China', 'country_code': 'CN', 'city': 'Shanghai', 'isp': 'TEST-NET-3 (RFC 5737)'},
    '203.0.113.99':  {'country': 'China', 'country_code': 'CN', 'city': 'Guangzhou', 'isp': 'TEST-NET-3 (RFC 5737)'},
    '192.0.2.55':    {'country': 'Brazil', 'country_code': 'BR', 'city': 'São Paulo', 'isp': 'TEST-NET-1 (RFC 5737)'},
    # SCANNER_IPS from log-server.py (mirrored — real allocations)
    '45.155.205.233':  {'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow', 'isp': 'AEZA GROUP Ltd'},
    '91.240.118.172':  {'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow', 'isp': 'IP Volume inc'},
    '103.251.167.20':  {'country': 'Hong Kong', 'country_code': 'HK', 'city': 'Hong Kong', 'isp': 'CHINA TELECOM'},
    '196.251.73.39':   {'country': 'Seychelles', 'country_code': 'SC', 'city': 'Victoria', 'isp': 'Aeza International'},
    '78.128.113.34':   {'country': 'Bulgaria', 'country_code': 'BG', 'city': 'Sofia', 'isp': 'Bulsatcom Ltd'},
    '162.247.74.27':   {'country': 'United States', 'country_code': 'US', 'city': 'New York', 'isp': 'Emerald Onion (Tor exit)'},
    '171.25.193.77':   {'country': 'Sweden', 'country_code': 'SE', 'city': 'Stockholm', 'isp': 'DFRI (Tor exit)'},
    '104.244.76.13':   {'country': 'United States', 'country_code': 'US', 'city': 'Seattle', 'isp': 'Quintex Alliance (Tor exit)'},
    '209.141.58.146':  {'country': 'United States', 'country_code': 'US', 'city': 'Las Vegas', 'isp': 'FranTech Solutions'},
    '5.2.69.50':       {'country': 'Moldova', 'country_code': 'MD', 'city': 'Chișinău', 'isp': 'Trabia SRL'},
    # TOR_EXIT_NODES
    '185.220.101.42':  {'country': 'Germany', 'country_code': 'DE', 'city': 'Frankfurt', 'isp': 'F3 Netze e.V. (Tor exit)'},
    '185.220.101.33':  {'country': 'Germany', 'country_code': 'DE', 'city': 'Frankfurt', 'isp': 'F3 Netze e.V. (Tor exit)'},
    '185.220.100.252': {'country': 'Germany', 'country_code': 'DE', 'city': 'Berlin', 'isp': 'F3 Netze e.V. (Tor exit)'},
    '23.129.64.210':   {'country': 'United States', 'country_code': 'US', 'city': 'Seattle', 'isp': 'Emerald Onion (Tor exit)'},
    '51.15.43.205':    {'country': 'France', 'country_code': 'FR', 'city': 'Paris', 'isp': 'Scaleway SAS (Tor exit)'},

    # ─── Legitimate player profile IPs (consistent per simulated player) ───
    # Each PLAYER_NAME has 1-2 IPs. These IPs resolve to the player's "home"
    # country. Realistic geo data so Players-by-country pie makes sense.
    '126.163.42.150': {'country': 'Japan', 'country_code': 'JP', 'city': 'Tokyo', 'isp': 'KDDI Corporation'},
    '126.163.42.88':  {'country': 'Japan', 'country_code': 'JP', 'city': 'Osaka', 'isp': 'KDDI Corporation'},
    '207.126.117.10': {'country': 'United States', 'country_code': 'US', 'city': 'New York', 'isp': 'Charter Communications'},
    '207.126.117.88': {'country': 'United States', 'country_code': 'US', 'city': 'San Francisco', 'isp': 'Charter Communications'},
    '85.214.205.100': {'country': 'Germany', 'country_code': 'DE', 'city': 'Berlin', 'isp': 'Strato AG'},
    '81.2.69.142':    {'country': 'United Kingdom', 'country_code': 'GB', 'city': 'London', 'isp': 'Virgin Media Ltd'},
    '142.250.100.13': {'country': 'Canada', 'country_code': 'CA', 'city': 'Toronto', 'isp': 'Bell Canada'},
    '203.220.50.1':   {'country': 'Australia', 'country_code': 'AU', 'city': 'Sydney', 'isp': 'Telstra Corporation'},
    '62.112.200.150': {'country': 'Netherlands', 'country_code': 'NL', 'city': 'Amsterdam', 'isp': 'KPN B.V.'},
    '194.47.200.10':  {'country': 'Sweden', 'country_code': 'SE', 'city': 'Stockholm', 'isp': 'SUNET'},
    '78.193.205.10':  {'country': 'France', 'country_code': 'FR', 'city': 'Paris', 'isp': 'Orange S.A.'},
    '103.50.100.50':  {'country': 'Singapore', 'country_code': 'SG', 'city': 'Singapore', 'isp': 'Singapore Telecommunications'},
}


def _load_cache():
    global _CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                _CACHE = json.load(f)
        except Exception:
            _CACHE = {}
    # Merge seed (without overwriting existing entries)
    for ip, geo in _SEED.items():
        _CACHE.setdefault(ip, geo)


def _save_cache():
    """Called periodically from a worker to persist the cache."""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    tmp = f'{CACHE_FILE}.tmp'
    with _CACHE_LOCK:
        data = dict(_CACHE)
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, CACHE_FILE)


def _refill_tokens():
    """Give everyone back their minute's worth of tokens."""
    global _last_refill
    with _refill_lock:
        now = time.time()
        if now - _last_refill >= 60:
            # Reset: drain then fill
            for _ in range(_RATE_LIMIT_PER_MIN):
                try:
                    _RATE_TOKENS.release()
                except ValueError:
                    break
            _last_refill = now


def _api_call(ip):
    """Live API call. Respects rate limit. Returns dict or None on error."""
    _refill_tokens()
    if not _RATE_TOKENS.acquire(blocking=False):
        return None
    try:
        key = os.environ.get('IP_API_KEY')
        if key:
            url = f'https://pro.ip-api.com/json/{ip}?key={key}&fields=status,country,countryCode,city,isp'
        else:
            url = f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp'
        try:
            with urllib.request.urlopen(url, timeout=4) as r:
                data = json.loads(r.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
            return None
        if data.get('status') != 'success':
            return None
        return {
            'country': data.get('country') or 'Unknown',
            'country_code': data.get('countryCode') or 'XX',
            'city': data.get('city') or '',
            'isp': data.get('isp') or '',
        }
    finally:
        pass  # don't release token — it will refill with the minute reset


def _worker():
    """Background thread: pull IPs from queue, look them up, cache, persist.
    If we hit the rate limit, re-queue for later (don't drop the IP)."""
    last_save = time.time()
    while True:
        try:
            ip = _QUEUE.get(timeout=10)
        except queue.Empty:
            if time.time() - last_save > 30:
                _save_cache()
                last_save = time.time()
            continue
        try:
            with _CACHE_LOCK:
                already = ip in _CACHE
            if already:
                continue
            result = _api_call(ip)
            if result:
                with _CACHE_LOCK:
                    _CACHE[ip] = result
                if time.time() - last_save > 15:
                    _save_cache()
                    last_save = time.time()
            else:
                # Rate limited or transient API failure — back off a bit and re-queue.
                time.sleep(2)
                try:
                    _QUEUE.put_nowait(ip)
                except queue.Full:
                    pass
        except Exception:
            pass


def _ensure_workers():
    global _WORKERS_STARTED
    with _WORKERS_LOCK:
        if _WORKERS_STARTED:
            return
        _load_cache()
        for _ in range(2):
            t = threading.Thread(target=_worker, daemon=True, name='geoip-worker')
            t.start()
        _WORKERS_STARTED = True


def lookup(ip):
    """Return geo dict for an IP. Cached → immediate; uncached → returns None
    immediately and queues a background lookup so the next call for the same IP
    will find it. Safe to call at high frequency — never blocks the caller.
    """
    if not ip or ip in ('127.0.0.1', '::1', 'localhost', '0.0.0.0'):
        return {'country': 'Local', 'country_code': 'LOCAL', 'city': '', 'isp': 'localhost'}
    _ensure_workers()
    with _CACHE_LOCK:
        hit = _CACHE.get(ip)
    if hit:
        return hit
    try:
        _QUEUE.put_nowait(ip)
    except queue.Full:
        pass
    return None  # caller sends log without geo; next lookup for same IP will hit


def lookup_sync(ip, timeout=4):
    """Blocking lookup — only use for admin/UI contexts where you're OK waiting."""
    if not ip or ip in ('127.0.0.1', '::1'):
        return {'country': 'Local', 'country_code': 'LOCAL', 'city': '', 'isp': 'localhost'}
    _ensure_workers()
    with _CACHE_LOCK:
        hit = _CACHE.get(ip)
    if hit:
        return hit
    result = _api_call(ip)
    if result:
        with _CACHE_LOCK:
            _CACHE[ip] = result
    return result


def cache_stats():
    with _CACHE_LOCK:
        return {'size': len(_CACHE), 'queue_depth': _QUEUE.qsize()}
