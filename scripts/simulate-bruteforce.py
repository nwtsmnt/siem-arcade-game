#!/usr/bin/env python3
"""
Brute-force login simulator.

Sends N failed login attempts against the game's /api/auth endpoint from a
spoofed source IP. This triggers the game's ECS `auth_failure` logger, which
forwards to Graylog as GELF — where the "Brute-force login" event definition
fires once the threshold is crossed.

Usage:
  python3 scripts/simulate-bruteforce.py [--target http://localhost:8080] \\
                                          [--username admin] \\
                                          [--attempts 10] \\
                                          [--delay 0.3] \\
                                          [--source-ip 198.51.100.77]

Watch the dashboard after running — the alert fires on the threshold
configured in the Graylog event definition (default: 5 failures in 60s).
"""
import argparse
import json
import sys
import time
import urllib.request


def attempt(target, username, password, source_ip):
    req = urllib.request.Request(
        f'{target}/api/auth',
        data=json.dumps({'username': username, 'password': password}).encode(),
        headers={
            'Content-Type': 'application/json',
            'X-Forwarded-For': source_ip,
        },
        method='POST',
    )
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def main():
    parser = argparse.ArgumentParser(description='Brute-force login simulator')
    parser.add_argument('--target', default='http://localhost:8080',
                        help='Game server base URL (default: http://localhost:8080)')
    parser.add_argument('--username', default='admin',
                        help='Username to hammer (default: admin)')
    parser.add_argument('--attempts', type=int, default=10,
                        help='Number of failed attempts to send (default: 10)')
    parser.add_argument('--delay', type=float, default=0.3,
                        help='Seconds between attempts (default: 0.3)')
    parser.add_argument('--source-ip', default='198.51.100.77',
                        help='Spoofed source IP via X-Forwarded-For (default: 198.51.100.77 — TEST-NET-2)')
    args = parser.parse_args()

    print('=' * 60)
    print('  BRUTE-FORCE SIMULATOR')
    print('=' * 60)
    print(f'  Target:     {args.target}/api/auth')
    print(f'  Username:   {args.username}')
    print(f'  Source IP:  {args.source_ip} (spoofed)')
    print(f'  Attempts:   {args.attempts}')
    print(f'  Delay:      {args.delay}s between attempts')
    print('=' * 60)
    print('  >>> WATCH YOUR GRAYLOG DASHBOARD NOW <<<')
    print('=' * 60)
    print()

    # First: register the victim account so we generate real auth_failure logs
    # (not "user doesn't exist" logs). If it already exists this is a no-op.
    print(f'[0] Ensuring victim account "{args.username}" exists...')
    code, _ = attempt(args.target, args.username, 'correct-horse-battery-staple', args.source_ip)
    if code in (200, 201):
        print(f'    → account ready (HTTP {code})')
    else:
        print(f'    → HTTP {code} — continuing anyway')
    time.sleep(0.5)

    passwords = [f'wrongpass{i:03d}' for i in range(args.attempts)]
    failed = 0
    for i, pw in enumerate(passwords, 1):
        code, body = attempt(args.target, args.username, pw, args.source_ip)
        if code == 401:
            failed += 1
            print(f'[{i:2d}/{args.attempts}] HTTP 401  ← auth_failure logged')
        elif code == 0:
            print(f'[{i:2d}/{args.attempts}] NETWORK ERROR: {body[:80]}')
            sys.exit(1)
        else:
            print(f'[{i:2d}/{args.attempts}] HTTP {code}  body={body[:60]}')
        time.sleep(args.delay)

    print()
    print('=' * 60)
    print(f'  DONE — {failed}/{args.attempts} attempts rejected as expected')
    print(f'  Check Graylog: Alerts → Events → "Brute-force login"')
    print('=' * 60)


if __name__ == '__main__':
    main()
