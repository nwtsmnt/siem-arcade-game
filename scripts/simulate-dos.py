#!/usr/bin/env python3
"""
DoS flood simulator.

Sends a high-rate burst of requests against the game server from a spoofed
source IP. Every request generates at least one log event; the Graylog "DoS
flood" event definition fires when the per-IP event rate crosses the
configured threshold (default: 100 events in 10s).

Usage:
  python3 scripts/simulate-dos.py [--target http://localhost:8080] \\
                                   [--requests 200] \\
                                   [--rate 50] \\
                                   [--source-ip 203.0.113.13]

Watch the dashboard after running — the DoS event should fire within seconds.
"""
import argparse
import json
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def fire(target, source_ip, i):
    # Hit the auth endpoint — cheap, logs every time, realistic attacker behaviour.
    req = urllib.request.Request(
        f'{target}/api/auth',
        data=json.dumps({'username': f'flood{i}', 'password': 'x'}).encode(),
        headers={
            'Content-Type': 'application/json',
            'X-Forwarded-For': source_ip,
        },
        method='POST',
    )
    try:
        urllib.request.urlopen(req, timeout=3).read()
        return True
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description='DoS flood simulator')
    parser.add_argument('--target', default='http://localhost:8080',
                        help='Game server base URL (default: http://localhost:8080)')
    parser.add_argument('--requests', type=int, default=200,
                        help='Total requests to send (default: 200)')
    parser.add_argument('--rate', type=int, default=50,
                        help='Target requests per second (default: 50)')
    parser.add_argument('--source-ip', default='203.0.113.13',
                        help='Spoofed source IP via X-Forwarded-For (default: 203.0.113.13 — TEST-NET-3)')
    parser.add_argument('--workers', type=int, default=10,
                        help='Concurrent workers (default: 10)')
    args = parser.parse_args()

    print('=' * 60)
    print('  DoS FLOOD SIMULATOR')
    print('=' * 60)
    print(f'  Target:     {args.target}/api/auth')
    print(f'  Source IP:  {args.source_ip} (spoofed)')
    print(f'  Requests:   {args.requests} total')
    print(f'  Target rate: {args.rate} req/s')
    print(f'  Workers:    {args.workers}')
    print('=' * 60)
    print('  >>> WATCH YOUR GRAYLOG DASHBOARD NOW <<<')
    print('=' * 60)
    print()

    interval = 1.0 / args.rate
    start = time.time()
    sent = 0
    ok = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = []
        for i in range(args.requests):
            scheduled_at = start + i * interval
            sleep_for = scheduled_at - time.time()
            if sleep_for > 0:
                time.sleep(sleep_for)
            futures.append(pool.submit(fire, args.target, args.source_ip, i))
            sent += 1
            if sent % 25 == 0:
                elapsed = time.time() - start
                rate = sent / elapsed if elapsed else 0
                print(f'  [{elapsed:5.1f}s] sent={sent:4d}  rate={rate:.1f} req/s')

        for f in futures:
            if f.result():
                ok += 1

    elapsed = time.time() - start
    print()
    print('=' * 60)
    print(f'  DONE — {sent} requests in {elapsed:.1f}s ({sent/elapsed:.1f} req/s)')
    print(f'  Successful: {ok}/{sent}')
    print(f'  Check Graylog: Alerts → Events → "DoS flood"')
    print('=' * 60)


if __name__ == '__main__':
    main()
