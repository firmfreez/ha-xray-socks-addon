#!/usr/bin/python3
"""Fixed OpenConnect route hook. Never execute imported scripts."""
import os
from pathlib import Path
import subprocess
import sys
from vpn_dns import ipv4_servers, publish


def update(work, env):
    work = Path(work)
    reason = env.get('reason')
    if reason not in ('connect', 'reconnect', 'disconnect'):
        return
    connected = reason != 'disconnect'
    manual = ipv4_servers((work / 'dns-manual').read_text().split(','))
    servers = manual or ipv4_servers(env.get('INTERNAL_IP4_DNS', '').split())
    publish(work, servers if connected else [],
            'manual' if connected and manual else 'anyconnect' if connected else 'disconnected')
    (work / 'tunnel-state').write_text('connected' if connected else 'disconnected')


def main():
    work = Path(sys.argv[1])
    env = dict(os.environ)
    # vpnc-script sets routes and addresses; manager owns DNS and its inode.
    routing = dict(env, INTERNAL_IP4_DNS='', INTERNAL_IP6_DNS='')
    subprocess.run(['/etc/vpnc/vpnc-script'], env=routing, check=True, timeout=30)
    update(work, env)


if __name__ == '__main__':
    main()
