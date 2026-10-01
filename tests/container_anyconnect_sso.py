"""Run inside an Alpine SSO test image, using a local TLS Cisco/IdP fixture only."""
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree as ET


def main():
    os.umask(0o077)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        work.chmod(0o755)
        cert, key = work / 'ca.pem', work / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
            '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        tokens = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, data, content_type, cookie=None):
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(data)))
                if cookie:
                    self.send_header('Set-Cookie', cookie)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                page = b'''<html><body><h1>Local SSO fixture</h1><input id="otp" autofocus>
<button onclick="if(document.getElementById('otp').value==='test-otp'){document.cookie='sso_token=test-sso-token; Secure; path=/';location.href='/done'}">Login</button>
<script>document.getElementById('otp').addEventListener('keydown',e=>{if(e.key==='Enter')document.querySelector('button').click()})</script></body></html>'''
                if self.path == '/done':
                    page = b'<html><body>SSO complete</body></html>'
                self.reply(page, 'text/html')

            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                xml = ET.fromstring(body)
                token = xml.findtext('.//sso-token')
                if token:
                    tokens.append(token)
                    self.reply(b'<config-auth type="complete"><session-token>test-vpn-session</session-token><auth id="success"/></config-auth>',
                               'text/xml', 'webvpn=test-vpn-session; Secure; path=/')
                else:
                    response = f'''<config-auth type="auth-request"><opaque><tunnel-group>SSO</tunnel-group></opaque>
<auth id="main"><sso-v2-login>{url}/login</sso-v2-login><sso-v2-login-final>{url}/done</sso-v2-login-final>
<sso-v2-token-cookie-name>sso_token</sso-v2-token-cookie-name><sso-v2-error-cookie-name>sso_error</sso-v2-error-cookie-name>
<form><input type="sso" name="sso-token"/></form></auth></config-auth>'''
                    self.reply(response.encode(), 'text/xml')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        url = f'https://localhost:{server.server_port}'
        threading.Thread(target=server.serve_forever, daemon=True).start()
        env = dict(os.environ, ANYCONNECT_SSO_WORK=str(work), ANYCONNECT_SSO_UID='64000',
                   ANYCONNECT_SSO_CA=str(cert), LD_PRELOAD='/usr/local/lib/anyconnect-forms.so')
        proc = subprocess.Popen(['openconnect', '--protocol=anyconnect', '--useragent=AnyConnect',
            '--non-inter', '--cookieonly', '--cafile', str(cert), url], env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 40
            while not (work / 'sso-frame.png').exists():
                if proc.poll() is not None or time.monotonic() > deadline:
                    output, error = proc.communicate(timeout=2)
                    raise AssertionError('Browser did not produce a frame: ' + error)
                time.sleep(.1)
            assert (work / 'sso-frame.png').read_bytes().startswith(b'\x89PNG')
            session = json.loads((work / 'sso-state.json').read_text())['session']
            for data in ({'type': 'text', 'text': 'test-otp'}, {'type': 'key', 'key': 'Enter'}):
                path = work / 'sso-input.json'
                data['session'] = session
                path.write_text(json.dumps(data))
                deadline = time.monotonic() + 10
                while path.exists() and time.monotonic() < deadline:
                    time.sleep(.1)
            output, error = proc.communicate(timeout=20)
            assert proc.returncode == 0, error
            assert tokens == ['test-sso-token'], tokens
            assert output.strip() == 'test-vpn-session', 'Wrong VPN session'
            assert 'test-otp' not in error and 'test-sso-token' not in error
            assert not (work / 'sso-state.json').exists()
            assert not (work / 'sso-frame.png').exists()
            assert not (work / 'browser').exists()
            print('PASS: real libopenconnect callback, TLS browser, manual input, SSO token, VPN cookie and cleanup')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
            server.shutdown()


if __name__ == '__main__':
    main()
