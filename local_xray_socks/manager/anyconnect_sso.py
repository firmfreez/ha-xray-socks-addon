"""Ephemeral Chromium webview for libopenconnect; private IPC and Ingress frames."""
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler
import uuid

WIDTH, HEIGHT = 1000, 700
KEYS = {'Enter': 13, 'Tab': 9, 'Backspace': 8, 'Escape': 27,
        'ArrowLeft': 37, 'ArrowUp': 38, 'ArrowRight': 39, 'ArrowDown': 40, 'Delete': 46}


def atomic(path, data):
    tmp = path.with_suffix('.tmp')
    tmp.write_bytes(data)
    tmp.chmod(0o600)
    tmp.replace(path)


def validate_input(data):
    kind = data.get('type')
    if kind == 'click':
        for key, limit in (('x', WIDTH), ('y', HEIGHT)):
            if type(data.get(key)) is not int or not 0 <= data[key] < limit:
                raise ValueError('Координаты вне окна входа')
        return {k: data[k] for k in ('type', 'x', 'y')}
    if kind == 'text' and isinstance(data.get('text'), str) and 0 < len(data['text']) <= 4096:
        return {'type': kind, 'text': data['text']}
    if kind == 'key' and data.get('key') in KEYS:
        return {'type': kind, 'key': data['key']}
    if kind == 'scroll' and type(data.get('delta')) is int and abs(data['delta']) <= 700:
        return {'type': kind, 'delta': data['delta']}
    raise ValueError('Недопустимое действие в окне входа')


class CDP:
    def __init__(self, url):
        from websocket import create_connection
        self.ws = create_connection(url, timeout=10, suppress_origin=True, http_no_proxy=['127.0.0.1'])
        self.sequence = 0

    def call(self, method, **params):
        self.sequence += 1
        self.ws.send(json.dumps({'id': self.sequence, 'method': method, 'params': params}))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            reply = json.loads(self.ws.recv())
            if reply.get('id') == self.sequence:
                if 'error' in reply:
                    raise ValueError('Browser command failed')
                return reply.get('result', {})
        raise TimeoutError('Browser command timed out')

    def input(self, data):
        data = validate_input(data)
        if data['type'] == 'click':
            for event in ('mousePressed', 'mouseReleased'):
                self.call('Input.dispatchMouseEvent', type=event, x=data['x'], y=data['y'], button='left', clickCount=1)
        elif data['type'] == 'text':
            self.call('Input.insertText', text=data['text'])
        elif data['type'] == 'key':
            for event in ('keyDown', 'keyUp'):
                self.call('Input.dispatchKeyEvent', type=event, key=data['key'],
                          windowsVirtualKeyCode=KEYS[data['key']])
        else:
            self.call('Input.dispatchMouseEvent', type='mouseWheel', x=WIDTH // 2,
                      y=HEIGHT // 2, deltaX=0, deltaY=data['delta'])


def browser(work, uri):
    parsed = urlsplit(uri)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('SSO requires an HTTPS login URL')
    session = uuid.uuid4().hex
    directory = work / 'browser'
    directory.mkdir(mode=0o700)
    uid = int(os.environ['ANYCONNECT_SSO_UID'])
    ca = os.environ.get('ANYCONNECT_SSO_CA')
    if ca:
        database = directory / '.pki' / 'nssdb'
        database.mkdir(parents=True, mode=0o700)
        for command in (['certutil', '-N', '--empty-password', '-d', 'sql:' + str(database)],
                        ['certutil', '-A', '-n', 'VPN corporate CA', '-t', 'C,,',
                         '-i', ca, '-d', 'sql:' + str(database)]):
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    for path in [directory, *directory.rglob('*')]:
        os.chown(path, uid, uid)
    browser_env = dict(os.environ, HOME=str(directory))
    browser_env.pop('ANYCONNECT_SSO_CA', None)
    browser_env.pop('ANYCONNECT_SSO_WORK', None)
    proc = subprocess.Popen(['setpriv', '--reuid=' + str(uid), '--regid=' + str(uid), '--clear-groups',
        'chromium', '--headless', '--no-sandbox', '--disable-dev-shm-usage',
        '--disable-background-networking', '--no-first-run', '--no-default-browser-check',
        '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
        '--user-data-dir=' + str(directory), 'about:blank'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=browser_env)
    cdp = None
    try:
        deadline = time.monotonic() + 20
        port_file = directory / 'DevToolsActivePort'
        while not port_file.exists():
            if proc.poll() is not None or time.monotonic() > deadline:
                raise TimeoutError('Browser could not start')
            time.sleep(.1)
        port = int(port_file.read_text().splitlines()[0])
        opener = build_opener(ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{port}/json/list', timeout=10) as response:
            targets = json.load(response)
        target = next(t for t in targets if t['type'] == 'page')
        cdp = CDP(target['webSocketDebuggerUrl'])
        cdp.call('Page.enable')
        cdp.call('Network.enable')
        cdp.call('Emulation.setDeviceMetricsOverride', width=WIDTH, height=HEIGHT, deviceScaleFactor=1, mobile=False)
        cdp.call('Page.navigate', url=uri)
        state = {'session': session, 'width': WIDTH, 'height': HEIGHT, 'expires_at': time.time() + 600}
        atomic(work / 'sso-state.json', json.dumps(state).encode())
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            action = work / 'sso-input.json'
            if action.exists():
                data = json.loads(action.read_text())
                action.unlink(missing_ok=True)
                if data.pop('session', None) == session:
                    cdp.input(data)
            frame = cdp.call('Page.getFrameTree')['frameTree']['frame']['url']
            parsed_frame = urlsplit(frame)
            state['origin'] = (parsed_frame.scheme + '://' + parsed_frame.netloc
                               if parsed_frame.scheme in ('http', 'https') else 'загрузка…')
            atomic(work / 'sso-state.json', json.dumps(state).encode())
            # Only cookies applicable to the current URL, including HttpOnly.
            cookies = cdp.call('Network.getCookies', urls=[frame])['cookies']
            cookies = [c for c in cookies if all('\n' not in c[k] and '\r' not in c[k]
                       and len(c[k]) < 65536 for k in ('name', 'value'))][:256]
            if '\n' in frame or '\r' in frame:
                raise ValueError('Invalid browser URL')
            sys.stdout.write(frame + '\n' + str(len(cookies)) + '\n')
            for cookie in cookies:
                sys.stdout.write(cookie['name'] + '\n' + cookie['value'] + '\n')
            sys.stdout.flush()
            result = int(sys.stdin.readline())
            if result != -11:  # Linux EAGAIN: libopenconnect decides when SSO is complete.
                return
            shot = cdp.call('Page.captureScreenshot', format='png')['data']
            atomic(work / 'sso-frame.png', base64.b64decode(shot))
            time.sleep(.3)
        raise TimeoutError('SSO timed out')
    finally:
        for name in ('sso-state.json', 'sso-frame.png', 'sso-input.json'):
            (work / name).unlink(missing_ok=True)
        if cdp:
            cdp.ws.close()
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        shutil.rmtree(directory, ignore_errors=True)


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    try:
        browser(Path(os.environ['ANYCONNECT_SSO_WORK']), sys.stdin.readline().rstrip('\n'))
    except Exception:
        # Chromium exceptions may contain page URLs or entered credentials.
        print('AnyConnect: SSO authentication failed or timed out', file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
