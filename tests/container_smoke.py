"""Run explicitly INSIDE the ARM64 image, never against real VPNs or HA data.

Exercise the actual namespaces, SOCKS relay and egress firewall using a synthetic
tunnel. OpenVPN auth is deliberately replaced with a sleeping test process.
The actual Xray primary listener and isolated AWG engine are started separately.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, '/app')
from model import validate
from runtime import Runtime, run


def wait_port(port, runtime):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        assert runtime.state != 'error', '\n'.join(runtime.logs)
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return
        except OSError:
            time.sleep(.25)
    raise AssertionError(f'No listener on {port}: ' + '\n'.join(runtime.logs))


def fetch(port, url):
    return subprocess.run(['curl', '--silent', '--show-error', '--noproxy', '',
                           '--proxy', f'socks5h://127.0.0.1:{port}', '--max-time', '4', url],
                          text=True, capture_output=True, timeout=6)


def udp_fetch(port, host, target_port, payload=b'udp-through-vpn'):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as control:
        control.sendall(b'\x05\x01\x00')
        assert control.recv(2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01' + bytes(6))
        reply = b''
        while len(reply) < 10:
            chunk = control.recv(10-len(reply))
            assert chunk, 'SOCKS UDP association closed'
            reply += chunk
        assert reply[:4] == b'\x05\x00\x00\x01', reply
        address = socket.inet_ntoa(reply[4:8])
        if address == '0.0.0.0':
            address = '127.0.0.1'
        relay_port = struct.unpack('!H', reply[8:10])[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            packet = b'\x00\x00\x00\x01' + socket.inet_aton(host) + struct.pack('!H', target_port) + payload
            udp.sendto(packet, (address, relay_port))
            response, _ = udp.recvfrom(65535)
            assert response.endswith(payload), response
            return response


def synthetic_tunnel(base, kind="openvpn"):
    bindir = base / 'bin'
    bindir.mkdir(parents=True)
    stub = bindir / ('openvpn' if kind == 'openvpn' else 'snx-rs')
    stub.write_text('#!/bin/sh\nset -e\n'+("sysctl -qw net.ipv4.conf.lo.rp_filter=2\nprintf 'nameserver 10.250.0.1\\n' > /etc/resolv.conf\n" if kind == 'checkpoint' else '')+'exec sleep 120\n')
    stub.chmod(0o755)
    original_path = os.environ['PATH']
    os.environ['PATH'] = str(bindir) + ':' + original_path
    directory = base / 'work'
    (directory / 'assets').mkdir(parents=True)
    profile = validate(dict(name='Synthetic work', kind=kind, slot=1,
                            ovpn='client\ndev tun\n', dns='10.250.0.1' if kind == 'openvpn' else '',
                            server='127.0.0.1', login_type='vpn_Test'))
    original_resolver = Path('/etc/resolv.conf').read_text()
    host_rp_filter = Path('/proc/sys/net/ipv4/conf/lo/rp_filter').read_text()
    host_sysctl_writable = os.access('/proc/sys/net/ipv4/conf/lo/rp_filter', os.W_OK)
    runtime = Runtime(profile, directory)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'synthetic-work-resource')

        def log_message(self, *_):
            pass

    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(('0.0.0.0', 18081))
    echo.settimeout(0.2)
    echo_stop = threading.Event()
    def echo_udp():
        try:
            while not echo_stop.is_set():
                try:
                    data, peer = echo.recvfrom(65535)
                except socket.timeout:
                    continue
                echo.sendto(data, peer)
        except OSError:
            pass
    echo_thread = threading.Thread(target=echo_udp, daemon=True)
    echo_thread.start()
    http = ThreadingHTTPServer(('0.0.0.0', 18080), Handler)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    try:
        runtime.start()
        wait_port(1081, runtime)
        if kind == 'checkpoint':
            assert runtime.dns_status()['servers'] == ['10.250.0.1']
            assert Path('/etc/resolv.conf').read_text() == original_resolver, 'Check Point changed container DNS'
            assert Path('/proc/sys/net/ipv4/conf/lo/rp_filter').read_text() == host_rp_filter, 'Changed container sysctl'
            assert os.access('/proc/sys/net/ipv4/conf/lo/rp_filter', os.W_OK) == host_sysctl_writable, 'Changed container mount protection'
        # The root transport can reach the physical interface, SOCKS must not.
        run('ip', 'netns', 'exec', runtime.ns, 'curl', '--fail', '--max-time', '3',
            f'http://{runtime.gateway}:18080')
        blocked = fetch(1081, f'http://{runtime.gateway}:18080')
        assert blocked.returncode != 0, 'SOCKS bypassed the absent VPN'
        # A second veth emulates a tunnel route to the synthetic corporate host.
        run('ip', 'link', 'add', 'testvpn', 'type', 'veth', 'peer', 'name', 'tun-test', 'netns', runtime.ns)
        run('ip', 'addr', 'add', '10.250.0.1/30', 'dev', 'testvpn')
        run('ip', 'link', 'set', 'testvpn', 'up')
        run('ip', 'netns', 'exec', runtime.ns, 'ip', 'addr', 'add', '10.250.0.2/30', 'dev', 'tun-test')
        run('ip', 'netns', 'exec', runtime.ns, 'ip', 'link', 'set', 'tun-test', 'up')
        response = fetch(1081, 'http://10.250.0.1:18080')
        assert response.returncode == 0 and response.stdout == 'synthetic-work-resource', response.stderr
        udp_fetch(1081, '10.250.0.1', 18081)
        run('ip', 'link', 'delete', 'testvpn')
        assert fetch(1081, 'http://10.250.0.1:18080').returncode != 0, 'Tunnel loss leaked traffic'
        try:
            udp_fetch(1081, runtime.gateway, 18081)
        except (TimeoutError, OSError):
            pass
        else:
            raise AssertionError('UDP bypassed the absent VPN')
        print('PASS: '+kind+' TCP/UDP, namespace routing, DNS isolation and tunnel-loss egress block', flush=True)
    finally:
        print('\n'.join(runtime.logs), flush=True)
        runtime.stop()
        echo_stop.set()
        echo_thread.join(timeout=1)
        echo.close()
        http.shutdown()
        http.server_close()
        os.environ['PATH'] = original_path


def primary_xray(base):
    profile = validate(dict(name='Synthetic primary', kind='vless', slot=0,
                            link='vless://12345678-1234-4234-9234-123456789abc@127.0.0.1:9',
                            watchdog_enabled=False))
    runtime = Runtime(profile, base)
    try:
        runtime.start()
        wait_port(1080, runtime)
        with socket.create_connection(('127.0.0.1', 1080), timeout=3) as sock:
            sock.sendall(b'\x05\x01\x00')
            assert sock.recv(2) == b'\x05\x00', 'Primary Xray SOCKS handshake failed'
        deadline = time.monotonic() + 20
        while not (runtime.work / 'xray/config.json').exists() and time.monotonic() < deadline:
            assert runtime.state != 'error', '\n'.join(runtime.logs)
            time.sleep(.25)
        config = json.loads((runtime.work / 'xray/config.json').read_text())
        assert config['inbounds'][0]['settings']['udp'] is True
        print('PASS: original Xray runner, private options and primary TCP/UDP configuration', flush=True)
    finally:
        print('\n'.join(runtime.logs), flush=True)
        runtime.stop()


def isolated_awg(base):
    private = run('awg', 'genkey').stdout.strip()
    other_private = run('awg', 'genkey').stdout
    public = subprocess.run(['awg', 'pubkey'], input=other_private, text=True, capture_output=True, check=True).stdout.strip()
    config = (f'[Interface]\nPrivateKey = {private}\nAddress = 10.99.0.2/32\n'
              f'[Peer]\nPublicKey = {public}\nEndpoint = 127.0.0.1:9\nAllowedIPs = 0.0.0.0/0\n')
    profile = validate(dict(name='Synthetic AWG', kind='amneziawg', slot=2,
                            amneziawg_config=config, watchdog_enabled=False))
    runtime = Runtime(profile, base)
    try:
        runtime.start()
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            assert runtime.state != 'error', '\n'.join(runtime.logs)
            try:
                with socket.create_connection(('127.0.0.1', 1082), timeout=1) as sock:
                    sock.settimeout(1)
                    sock.sendall(b'\x05\x01\x00')
                    if sock.recv(2) == b'\x05\x00':
                        break
            except OSError:
                pass
            time.sleep(.5)
        else:
            raise AssertionError('Isolated AWG/Xray did not start: ' + '\n'.join(runtime.logs))
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if run('ip', 'netns', 'exec', runtime.ns, 'ip', 'link', 'show', 'awg2', check=False).returncode == 0:
                break
            assert runtime.state != 'error', '\n'.join(runtime.logs)
            time.sleep(.25)
        run('ip', 'netns', 'exec', runtime.ns, 'ip', 'link', 'show', 'awg2')
        print('PASS: real AWG userspace interface and isolated Xray SOCKS handshake', flush=True)
    finally:
        print('\n'.join(runtime.logs), flush=True)
        runtime.stop()


if __name__ == '__main__':
    assert sys.platform == 'linux' and Path('/app/server.py').exists(), 'Run only in the built container'
    os.umask(0o077)
    run('snx-rs', '--version')
    run('openvpn', '--version')
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        synthetic_tunnel(base)
        synthetic_tunnel(base / 'checkpoint', kind='checkpoint')
        primary_xray(base)
        isolated_awg(base)
