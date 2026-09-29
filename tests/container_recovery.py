"""Run inside a disposable privileged image; never uses real VPN credentials."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import threading
import time
from unittest.mock import patch

sys.path.insert(0, '/app')
import runtime as module
from runtime import Runtime, run
from model import validate
from container_smoke import fetch


def wait(check, runtimes, timeout=25):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if check():
            return
        time.sleep(.1)
    raise AssertionError('\n'.join(line for r in runtimes for line in r.logs))


def tunnel(runtime):
    slot = runtime.p['slot']
    host, peer = f'10.250.{slot}.1', f'10.250.{slot}.2'
    device = f'testvpn{slot}'
    run('ip', 'link', 'add', device, 'type', 'veth', 'peer', 'name', 'tun-test', 'netns', runtime.ns)
    run('ip', 'addr', 'add', host + '/30', 'dev', device)
    run('ip', 'link', 'set', device, 'up')
    run('ip', 'netns', 'exec', runtime.ns, 'ip', 'addr', 'add', peer + '/30', 'dev', 'tun-test')
    run('ip', 'netns', 'exec', runtime.ns, 'ip', 'link', 'set', 'tun-test', 'up')
    return f'http://{host}:18080'


class HTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'isolated-profile-ok')

    def log_message(self, *_):
        pass


def main():
    assert sys.platform == 'linux' and Path('/app/server.py').exists()
    resolver = Path('/etc/resolv.conf').read_bytes()
    http = ThreadingHTTPServer(('0.0.0.0', 18080), HTTP)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        stub = root / 'openvpn'
        stub.write_text('#!/bin/sh\nexec sleep 300\n')
        stub.chmod(0o755)
        os.environ['PATH'] = str(root) + ':' + os.environ['PATH']
        runtimes = []
        for slot, endpoint in [(1, '192.0.2.1'), (4, 'unstable.test')]:
            directory = root / str(slot)
            (directory / 'assets').mkdir(parents=True)
            runtimes.append(Runtime(validate(dict(name=f'Profile {slot}', slot=slot, kind='openvpn',
                ovpn=f'client\ndev tun\nremote {endpoint} 1194\n')), directory))
        stable, recovering = runtimes
        calls = 0
        def resolve(host):
            nonlocal calls
            if host == 'unstable.test':
                calls += 1
                if calls == 1:
                    raise socket.gaierror(-3, 'Injected DNS outage')
            return ['192.0.2.1']
        def healthy(runtime, url):
            result = fetch(1080 + runtime.p['slot'], url)
            assert result.returncode == 0 and result.stdout == 'isolated-profile-ok', result.stderr
        try:
            with patch.object(module, 'endpoint_addresses', side_effect=resolve), \
                 patch.object(Runtime, 'monitor_ip'):
                for r in runtimes:
                    r.launch()
                wait(lambda: stable.state == 'running_unverified' and recovering.state == 'retrying', runtimes)
                stable_url = tunnel(stable)
                healthy(stable, stable_url)
                stable_pids = [p.pid for p in stable.children]
                stable_started = stable.started_at
                wait(lambda: recovering.state == 'running_unverified', runtimes)
                retry_url = tunnel(recovering)
                healthy(recovering, retry_url)
                healthy(stable, stable_url)
                # Kill only this profile's transport and observe automatic recovery.
                old_pid = recovering.children[0].pid
                os.kill(old_pid, signal.SIGKILL)
                wait(lambda: recovering.state == 'retrying', runtimes)
                healthy(stable, stable_url)
                wait(lambda: recovering.state == 'running_unverified' and recovering.children[0].pid != old_pid, runtimes)
                retry_url = tunnel(recovering)
                healthy(recovering, retry_url)
                healthy(stable, stable_url)
                assert [p.pid for p in stable.children] == stable_pids
                assert stable.started_at == stable_started
                assert Path('/etc/resolv.conf').read_bytes() == resolver
                # Cancellation must leave no namespace or NAT rule to poison the next start.
                for r in runtimes:
                    r.stop()
                assert not run('ip', 'netns', 'list').stdout.strip()
                assert '10.253.' not in run('iptables', '-t', 'nat', '-S', 'POSTROUTING').stdout
                assert all(not r.worker.is_alive() and r.state == 'stopped' for r in runtimes)
                print('PASS: DNS recovery, process crash recovery, uninterrupted sibling TCP, resolver isolation and clean cancellation', flush=True)
        finally:
            for r in runtimes:
                r.stop()
            http.shutdown()
            http.server_close()


if __name__ == '__main__':
    main()
