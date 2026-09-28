"""Ingress-only panel. No administration port is published on the LAN."""
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from model import filename, ovpn_config, validate, PERSONAL
from runtime import Runtime
from migration import migrate

ROOT = Path(os.environ.get('VPN_DATA', '/data/vpn-manager'))
SECRET_FIELDS = ('password', 'cert_password', 'key_password', 'ovpn', 'link', 'amneziawg_config')


class Manager:
    def __init__(self, root=ROOT):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.profiles = {}
        self.runtimes = {}
        self.lock = threading.RLock()
        self.notice = ''
        for file in root.glob('*/profile.json'):
            p = json.loads(file.read_text())
            self.profiles[p['id']] = p

    def public(self, p):
        result = {k: v for k, v in p.items() if k not in SECRET_FIELDS}
        result['has_secrets'] = {k: bool(p.get(k)) for k in SECRET_FIELDS}
        result['files'] = sorted(x.name for x in (self.root / p['id'] / 'assets').iterdir())
        runtime = self.runtimes.get(p['id'])
        result['state'] = runtime.state if runtime else 'stopped'
        result['port'] = 1080 + p['slot']
        result['dns_port'] = None if p['kind'] in PERSONAL else 10530 + p['slot']
        result['udp'] = True
        result['probe'] = runtime.last_probe if runtime else None
        return result

    @staticmethod
    def port_available(port):
        try:
            for family in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                with socket.socket(socket.AF_INET, family) as sock:
                    sock.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False

    def available_ports(self):
        used = {1080 + p['slot'] for p in self.profiles.values()}
        return [p for p in range(1080, 1089) if p not in used and self.port_available(p)]

    def save(self, data):
        with self.lock:
            ident = data.get('id') or uuid.uuid4().hex
            if not isinstance(ident, str) or len(ident) != 32 or any(c not in '0123456789abcdef' for c in ident):
                raise ValueError('Некорректный ID')
            old = self.profiles.get(ident, {})
            runtime = self.runtimes.get(ident)
            if runtime and runtime.state not in ('stopped', 'error'):
                raise ValueError('Сначала остановите профиль')
            data = dict(data)
            for key in SECRET_FIELDS:
                if not data.get(key):
                    data[key] = old.get(key, '')
            for key in data.pop('clear_secrets', []):
                if key in SECRET_FIELDS:
                    data[key] = ''
            uploads = data.pop('uploads', {})
            if not isinstance(uploads, dict) or len(uploads) > 20:
                raise ValueError('Слишком много файлов')
            allowed = {'name', 'kind', 'slot', 'dns', 'server', 'login_type', 'username', 'password',
                       'cert_password', 'key_password', 'ovpn', 'certificate', 'ca_file', 'tunnel', 'autostart',
                       'link', 'amneziawg_config', 'loglevel', 'watchdog_enabled', 'watchdog_urls', 'probe_url'}
            p = validate({k: v for k, v in data.items() if k in allowed})
            if not self.port_available(1080 + p['slot']):
                raise ValueError('Порт занят другим сервисом (TCP или UDP). Выберите свободный.')
            p['id'] = ident
            if any(x['slot'] == p['slot'] and x['id'] != ident for x in self.profiles.values()):
                raise ValueError('Этот порт уже занят другим подключением')
            directory = self.root / ident
            assets = directory / 'assets'
            existing = {x.name for x in assets.iterdir()} if assets.exists() else set()
            decoded = {}
            for name, value in uploads.items():
                name = filename(name)
                try:
                    decoded[name] = base64.b64decode(value, validate=True)
                except Exception:
                    raise ValueError('Некорректный загружаемый файл') from None
                if len(decoded[name]) > 1024 * 1024:
                    raise ValueError('Файл больше 1 МБ')
            if len(existing | decoded.keys()) > 20:
                raise ValueError('Не более 20 файлов в профиле')
            if p['kind'] == 'openvpn':
                ovpn_config(p['ovpn'], existing | decoded.keys())
            elif p['kind'] == 'checkpoint':
                for key in ('certificate', 'ca_file'):
                    if p.get(key) and p[key] not in existing | decoded.keys():
                        raise ValueError('Загрузите файл ' + p[key])
            assets.mkdir(parents=True, exist_ok=True, mode=0o700)
            for name, content in decoded.items():
                path = assets / name
                path.write_bytes(content)
                path.chmod(0o600)
            tmp = directory / 'profile.tmp'
            tmp.write_text(json.dumps(p, ensure_ascii=False))
            tmp.chmod(0o600)
            tmp.replace(directory / 'profile.json')
            self.profiles[ident] = p
            self.runtimes.pop(ident, None)
            return self.public(p)

    def action(self, ident, action, data):
        if action == 'probe':
            with self.lock:
                runtime = self.runtimes.get(ident)
                if not runtime or runtime.state != 'running_unverified':
                    raise ValueError('Сначала запустите профиль')
            return runtime.check_connection()
        with self.lock:
            if ident not in self.profiles:
                raise ValueError('Профиль не найден')
            p = self.profiles[ident]
            if action == 'details':
                result = self.public(p)
                for key in ('link', 'amneziawg_config', 'ovpn'):
                    result[key] = p.get(key, '')
                return result
            if action == 'info':
                if p['kind'] != 'checkpoint':
                    raise ValueError('Только для Check Point')
                args = ['snx-rs', '-m', 'info', '-s', p['server']]
                if p.get('ca_file'):
                    args += ['--ca-cert', str(self.root / ident / 'assets' / p['ca_file'])]
                result = subprocess.run(args, capture_output=True, text=True, timeout=25)
                return {'text': (result.stdout + result.stderr)[-12000:]}
            runtime = self.runtimes.get(ident)
            if action == 'delete':
                if runtime:
                    runtime.stop()
                shutil.rmtree(self.root / ident)
                self.profiles.pop(ident)
                self.runtimes.pop(ident, None)
                return {'ok': True}
            if action == 'start':
                if runtime is None or runtime.state in ('stopped', 'error'):
                    runtime = Runtime(p, self.root / ident)
                    self.runtimes[ident] = runtime
                    runtime.start()
                return self.public(p)
            if action == 'stop':
                if runtime:
                    runtime.stop()
                return self.public(p)
            raise ValueError('Неизвестная операция')


def handler(manager):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, value, content_type='application/json; charset=utf-8'):
            body = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)

        def trusted(self):
            # Supervisor ingress proxy. Never trust a client-supplied forwarding header.
            if self.client_address[0] != '172.30.32.2':
                self.reply(403, {'error': 'Use Home Assistant Ingress'})
                return False
            return True

        def do_GET(self):
            if not self.trusted():
                return
            path = self.path.split('?')[0]
            if path in ('/', '/index.html'):
                return self.reply(200, (Path(__file__).parent / 'index.html').read_bytes(), 'text/html; charset=utf-8')
            with manager.lock:
                if path == '/api/profiles':
                    return self.reply(200, [manager.public(p) for p in manager.profiles.values()])
                if path == '/api/ports':
                    return self.reply(200, manager.available_ports())
                if path == '/api/status':
                    return self.reply(200, {'notice': manager.notice})
                if path.startswith('/api/logs/'):
                    runtime = manager.runtimes.get(path.rsplit('/', 1)[-1])
                    return self.reply(200, {'text': '\n'.join(list(runtime.logs)) if runtime else 'Профиль ещё не запускался'})
            self.reply(404, {'error': 'Not found'})

        def do_POST(self):
            if not self.trusted():
                return
            if self.headers.get('X-VPN-Panel') != '1' or self.headers.get('Content-Type') != 'application/json':
                return self.reply(403, {'error': 'Invalid panel request'})
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 8 * 1024 * 1024:
                    raise ValueError('Размер запроса должен быть меньше 8 МБ')
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict):
                    raise ValueError('Ожидается объект JSON')
                parts = self.path.strip('/').split('/')
                if parts == ['api', 'profiles']:
                    return self.reply(200, manager.save(data))
                if len(parts) == 4 and parts[:2] == ['api', 'profiles']:
                    return self.reply(200, manager.action(parts[2], parts[3], data))
                self.reply(404, {'error': 'Not found'})
            except (ValueError, KeyError, TypeError) as exc:
                self.reply(400, {'error': str(exc)})
            except subprocess.TimeoutExpired:
                self.reply(504, {'error': 'Время ожидания истекло'})
            except Exception:
                self.reply(500, {'error': 'Операция не выполнена; проверьте журнал аддона'})
    return Handler


def main():
    os.umask(0o077)
    manager = Manager()
    try:
        migrate(manager)
    except (ValueError, OSError):
        manager.notice = 'Не все прежние настройки удалось перенести. Исходные options сохранены. Проверьте список профилей перед включением VPN.'
        print('Legacy settings could not be fully imported. Original options retained; check saved profiles.', flush=True)
    server = ThreadingHTTPServer(('0.0.0.0', 8099), handler(manager))
    def stop(*_):
        for runtime in list(manager.runtimes.values()):
            runtime.stop()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    for p in list(manager.profiles.values()):
        if p['autostart']:
            manager.action(p['id'], 'start', {})
    print('Local Xray SOCKS manager ready on Ingress port 8099', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
