"""Isolated real OpenVPN handshake and pushed DNS test; run only in Docker."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, '/app')
from model import validate
from runtime import Runtime
from vpn_dns import read_state
from dns_forward import read_exact


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        size = struct.unpack('!H', read_exact(self.request, 2))[0]
        q = read_exact(self.request, size)
        p = 12
        while q[p]:
            p += 1 + q[p]
        end = p + 5
        is_a = q[p+1:p+3] == b'\x00\x01'
        result = q[:2] + b'\x81\x80\x00\x01' + struct.pack('!H', int(is_a)) + bytes(4) + q[12:end]
        if is_a:
            result += b'\xc0\x0c\x00\x01\x00\x01' + struct.pack('!IH', 1, 4) + socket.inet_aton('10.249.0.1')
        self.request.sendall(struct.pack('!H', len(result)) + result)


class HTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'auto-dns-through-openvpn')

    def log_message(self, *_):
        pass


def wait(check, runtime, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        if runtime.state == 'error':
            break
        time.sleep(.2)
    raise AssertionError('\n'.join(runtime.logs))


def main():
    assert sys.platform == 'linux' and Path('/app/server.py').exists()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        cert, key = work / 'cert.pem', work / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=test-vpn', '-addext', 'extendedKeyUsage=serverAuth,clientAuth',
                        '-addext', 'keyUsage=digitalSignature,keyEncipherment,keyCertSign'],
                       check=True, capture_output=True)
        # DNS over TCP is used by both the LAN relay and our SOCKS probe below.
        dns = socketserver.ThreadingTCPServer(('0.0.0.0', 53), DNS)
        http = ThreadingHTTPServer(('0.0.0.0', 18080), HTTP)
        for service in (dns, http):
            threading.Thread(target=service.serve_forever, daemon=True).start()
        args = ['openvpn', '--dev', 'tun-server', '--proto', 'tcp-server', '--port', '11940',
                '--server', '10.249.0.0', '255.255.255.0', '--topology', 'subnet',
                '--dh', 'none', '--cert', str(cert), '--key', str(key), '--ca', str(cert),
                '--keepalive', '2', '10', '--verb', '3',
                '--push', 'dhcp-option DNS 10.249.0.1']
        log = (work / 'server.log').open('w+')
        server = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        time.sleep(.5)
        if server.poll() is not None:
            log.seek(0)
            raise AssertionError(log.read())
        profile = validate(dict(name='Auto DNS test', kind='openvpn', slot=8,
                                ovpn='client\ndev tun\nproto tcp-client\nremote 10.253.8.1 11940\n'
                                     'remote-cert-tls server\n<ca>\n'+cert.read_text()+'</ca>\n'
                                     '<cert>\n'+cert.read_text()+'</cert>\n<key>\n'+key.read_text()+'</key>\n'))
        directory = work / 'profile'
        (directory / 'assets').mkdir(parents=True)
        runtime = Runtime(profile, directory)
        try:
            runtime.start()
            wait(lambda: read_state(runtime.work / 'dns-state.json')['servers'] == ['10.249.0.1'], runtime)
            assert read_state(runtime.work / 'dns-state.json')['source'] == 'openvpn'
            assert 'nameserver 10.249.0.1' in (runtime.work / 'resolv.conf').read_text()
            # Corporate resolver is TCP-only in this fixture. Ask via LAN relay.
            query = b'\x12\x34\x01\x00\x00\x01'+bytes(6)+b'\x04work\x07example\x00\x00\x01\x00\x01'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(5)
                client.sendto(query, ('127.0.0.1', 10538))
                answer, _ = client.recvfrom(2048)
                assert answer[-4:] == socket.inet_aton('10.249.0.1'), answer
            # Add UDP DNS for the system resolver used by Xray.
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('0.0.0.0', 53))
            def relay():
                while True:
                    try:
                        q, peer = udp.recvfrom(2048)
                        with socket.create_connection(('127.0.0.1', 53)) as upstream:
                            upstream.sendall(struct.pack('!H', len(q))+q)
                            a = read_exact(upstream, struct.unpack('!H', read_exact(upstream, 2))[0])
                        udp.sendto(a, peer)
                    except OSError:
                        return
            threading.Thread(target=relay, daemon=True).start()
            result = subprocess.run(['curl', '--silent', '--show-error', '--noproxy', '',
                                     '--proxy', 'socks5h://127.0.0.1:1088', '--max-time', '10',
                                     'http://work.example:18080'], capture_output=True, text=True)
            assert result.returncode == 0 and result.stdout == 'auto-dns-through-openvpn', result.stderr
            vpn = next(p for p in runtime.children if 'openvpn' in p.args)
            vpn.send_signal(signal.SIGUSR1)
            wait(lambda: sum('Initialization Sequence Completed' in line for line in runtime.logs) >= 2, runtime)
            assert read_state(runtime.work / 'dns-state.json')['servers'] == ['10.249.0.1']
            print('PASS: OpenVPN 2.7 pushed DNS, LAN DNS relay, SOCKS hostname and reconnect', flush=True)
            udp.close()
        finally:
            print('\n'.join(runtime.logs)[-9000:], flush=True)
            runtime.stop()
            server.terminate()
            server.wait(timeout=8)
            for service in (dns, http):
                service.shutdown()
                service.server_close()
            log.close()


if __name__ == '__main__':
    main()
