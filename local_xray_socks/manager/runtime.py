"""Linux-only runtime. Every profile has its own routes, processes and resolver."""
import base64
import json
import ipaddress
from collections import deque
import os
from pathlib import Path
import shutil
import signal
import shlex
import socket
import subprocess
import threading
import time

from telemetry import Traffic
from model import ovpn_config, PERSONAL, personal_options
from vpn_dns import publish, read_state, resolver_state
from checkpoint import gateway_info
from ha_notify import disconnected
from urllib.parse import urlsplit

NETNS_ROOT = Path('/etc/netns')
HOSTS_FILE = Path('/etc/hosts')
RESOLV_FILE = Path('/etc/resolv.conf')


def run(*args, check=True):
    # Profile workers share the host's xtables lock during concurrent setup.
    if 'iptables' in args:
        args = list(args)
        pos = args.index('iptables') + 1
        args[pos:pos] = ['-w', '5']
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=15)


def endpoint_addresses(host):
    """Bound libc DNS time without leaving a stuck resolver thread behind."""
    try:
        return [str(ipaddress.IPv4Address(host))]
    except ValueError:
        pass
    result = subprocess.run(['python3', '-c',
        'import json,socket,sys\n'
        'try:\n'
        ' print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],None,socket.AF_INET,socket.SOCK_STREAM)})))\n'
        'except socket.gaierror as e:\n'
        ' print(json.dumps({"errno":e.errno,"error":str(e)}))\n', host],
        capture_output=True, text=True, check=True, timeout=12)
    addresses = json.loads(result.stdout)
    if isinstance(addresses, dict):
        raise socket.gaierror(addresses['errno'], addresses['error'])
    if not addresses:
        raise socket.gaierror(socket.EAI_AGAIN, 'No IPv4 addresses')
    return addresses


class Runtime:
    def __init__(self, profile, directory):
        self.p, self.directory = profile, directory
        self.ns = 'wvpn' + str(profile['slot'])
        self.host = 'wvh' + str(profile['slot'])
        self.gateway = f"10.253.{profile['slot']}.1"
        self.peer = f"10.253.{profile['slot']}.2"
        self.work = Path('/run/work-vpn') / self.ns
        self.children = []
        self.logs = deque(maxlen=250)
        self.state = 'stopped'
        self.stopping = threading.Event()
        self.lock = threading.RLock()
        self.networked = False
        self.last_probe = None
        self.probe_lock = threading.Lock()
        self.traffic = Traffic()
        self.external_ip = None
        self.vpn_ip = None
        self.ip_status = 'pending'
        self.started_at = None
        self.cancelled = threading.Event()
        self.worker = None
        self.retryable = True
        self.retry_at = None
        self.auth_failed = threading.Event()
        self.reconnect_count = 0
        self.outage_notified = False

    @property
    def active(self):
        return self.state not in ('stopped', 'error') or bool(self.worker and self.worker.is_alive())

    def start_personal(self, prefix):
        options = self.write('options.json', json.dumps(personal_options(self.p)))
        self.spawn(prefix + ['env', 'S6_KEEP_ENV=1', f'VPN_OPTIONS_FILE={options}',
                            'VPN_MANAGER_SUPERVISED=1',
                            f'VPN_RUNTIME_DIR={self.work}', f"AWG_INTERFACE=awg{self.p['slot']}",
                            f"SOCKS_PORT={1080 + self.p['slot']}",
                            f'SOCKS_UDP_IP={self.peer if prefix else "0.0.0.0"}', '/run.sh'])

    def started(self):
        self.state = 'running_unverified'
        self.started_at = time.time()
        threading.Thread(target=self.monitor_ip, args=(self.stopping,), daemon=True).start()
        self.last_probe = None
        self.log('Подключение запущено.')
        if self.p['kind'] in PERSONAL or self.p.get('probe_url'):
            threading.Thread(target=self.monitor_connection, args=(self.stopping,), daemon=True).start()

    def log(self, text, emit=True):
        for key in ('password', 'cert_password', 'key_password', 'username', 'link'):
            secret = self.p.get(key)
            if secret:
                text = text.replace(secret, '[hidden]')
                text = text.replace(base64.b64encode(secret.encode()).decode(), '[hidden]')
        # Never retain key blocks or bearer/session data in the panel.
        if any(x in text.lower() for x in ('private key', 'auth-token', 'session_id', 'authorization:', 'cookie:')):
            text = '[sensitive log line omitted]'
        entry = time.strftime('%Y-%m-%d %H:%M:%S') + ' ' + text[-2000:]
        self.logs.append(entry)
        if emit:
            print(f'[{self.ns}] {entry}', flush=True)

    def spawn(self, args, log=True):
        child_env = dict(os.environ)
        # VPN engines and namespace hooks do not need the HA bearer token.
        child_env.pop('SUPERVISOR_TOKEN', None)
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True,
                                text=True, bufsize=1, env=child_env)
        self.children.append(proc)
        attempt = self.stopping
        def reader():
            for line in proc.stdout:
                if attempt.is_set():
                    continue
                if log and self.p['kind'] not in PERSONAL and any(marker in line.lower() for marker in
                       ('auth_failed', 'authentication failed', 'authentication failure',
                        'invalid credentials', 'login failed', 'certificate verify failed')):
                    self.auth_failed.set()
                if log and self.p['kind'] == 'anyconnect' and not self.auth_failed.is_set() and any(marker in line.lower() for marker in
                       ('user input required in non-interactive mode', 'failed to complete authentication',
                        'authentication form repeated; automatic submission stopped',
                        'sso authentication failed or timed out', 'no sso handler')):
                    self.auth_failed.set()
                    self.log('AnyConnect: веб-вход SSO не завершён. Откройте журнал, проверьте группу входа и CA, '
                             'затем подключите профиль и откройте SSO-окно снова.'
                             if self.p.get('anyconnect_auth') == 'sso' else
                             'AnyConnect: вход не завершён. Проверьте логин, пароль, группу входа и поле MFA. '
                             'Повторный запрос Password может быть вторым фактором или отказом в первичном входе.', emit=False)
                self.log(('' if log else '[runtime] ') + line.rstrip(), emit=False)
        proc.log_reader = threading.Thread(target=reader, daemon=True)
        proc.log_reader.start()
        return proc

    def write(self, name, value):
        path = self.work / name
        path.write_text(value)
        path.chmod(0o600)
        return str(path)

    def start(self):
        with self.lock:
            self._start()

    def launch(self):
        """Reserve this runtime synchronously; do all slow work in its own worker."""
        if self.worker and self.worker.is_alive():
            return
        self.state = 'starting'
        self.worker = threading.Thread(target=self.supervise, daemon=True)
        self.worker.start()

    def supervise(self):
        try:
            self._supervise()
        except Exception as exc:
            self.log('Ошибка восстановления профиля: ' + str(exc))
            self.retryable = False
            try:
                self._cleanup()
            except Exception as cleanup_error:
                self.log('Не удалось очистить ресурсы профиля: ' + str(cleanup_error))
            self.state = 'error'
            if not self.cancelled.is_set() and self.p.get('notify_disconnect') and not self.outage_notified:
                self.outage_notified = True
                self.notify_disconnect('Ошибка управления подключением. Откройте журнал VPN.')

    def _supervise(self):
        delay = 5
        while not self.cancelled.is_set():
            with self.lock:
                if self.cancelled.is_set():
                    return
                self._start()
            since = time.monotonic()
            failures, checked = 0, None
            reason = 'Не удалось запустить подключение.'
            while self.state in ('running_unverified', 'starting') and not self.cancelled.wait(2):
                if self.auth_failed.is_set():
                    self.retryable = False
                    reason = ('Вход AnyConnect не завершён. Проверьте строки AnyConnect form/field в журнале.'
                              if self.p['kind'] == 'anyconnect' else 'Сервер отклонил авторизацию или сертификат.')
                    self.log(reason + ' Исправьте настройки и подключите профиль снова.')
                    break
                if any(p.poll() is not None for p in self.children):
                    # Read the final AUTH_FAILED line before deciding to retry.
                    for proc in self.children:
                        if proc.poll() is not None and hasattr(proc, 'log_reader'):
                            proc.log_reader.join(timeout=1)
                    self.log('Процесс профиля завершился.')
                    reason = 'Процесс VPN завершился.'
                    break
                if self.p['kind'] == 'anyconnect':
                    marker = self.work / 'tunnel-state'
                    tunnel = marker.read_text() if marker.exists() else ''
                    if tunnel == 'disconnected':
                        reason = 'Туннель AnyConnect отключён.'
                        break
                    if self.state == 'starting':
                        if tunnel == 'connected':
                            self.started()
                        elif time.monotonic() - since > (660 if self.p.get('anyconnect_auth') == 'sso' else 180):
                            reason = 'Истекло время ожидания входа / подтверждения MFA.'
                            self.log(reason)
                            break
                        else:
                            continue
                probe = self.last_probe
                if (self.p.get('watchdog_enabled', True)
                        and probe and probe['checked_at'] != checked):
                    checked = probe['checked_at']
                    failures = 0 if probe['reachable'] else failures + 1
                    if failures >= 3:
                        self.log('Три проверки сайта не прошли.')
                        reason = 'Три проверки связи через VPN не прошли.'
                        break
                if probe and probe['reachable']:
                    self.outage_notified = False
                    self.reconnect_count = 0
                elif self.p['kind'] not in PERSONAL and not self.p.get('probe_url') and time.monotonic() - since >= 120:
                    self.outage_notified = False
                    self.reconnect_count = 0
            with self.lock:
                if self.cancelled.is_set():
                    return
                self._cleanup()
                if self.p.get('notify_disconnect') and not self.outage_notified:
                    self.outage_notified = True
                    threading.Thread(target=self.notify_disconnect, args=(reason,), daemon=True).start()
                if not self.retryable or self.auth_failed.is_set():
                    if self.auth_failed.is_set():
                        self.log('Автоповтор отключён после ошибки авторизации или сертификата.')
                    self.state = 'error'
                    return
                limit = self.p.get('reconnect_attempts', 'always')
                if (not self.p.get('reconnect_enabled', True)
                        or limit != 'always' and self.reconnect_count >= limit):
                    self.log('Переподключение отключено или исчерпан лимит попыток.')
                    self.state = 'error'
                    return
                if time.monotonic() - since >= 120:
                    delay = 5
                self.state = 'retrying'
                self.retry_at = time.time() + delay
                self.log(f'Повторное подключение через {delay} с. Другие профили продолжают работать.')
            if self.cancelled.wait(delay):
                return
            self.reconnect_count += 1
            delay = min(delay * 2, 300)

    def notify_disconnect(self, reason):
        try:
            disconnected(self.p, reason)
            self.log('Уведомление об отключении отправлено в Home Assistant.')
        except (OSError, ValueError):
            self.log('Не удалось отправить уведомление. Проверьте доступ к HA и выбранные телефоны.')

    def _start(self):
        if self.state not in ('stopped', 'error', 'starting', 'retrying'):
            return
        # Never clear an event still held by a previous attempt's probe threads.
        self.stopping = threading.Event()
        self.auth_failed.clear()
        self.retry_at = None
        self.retryable = True
        self.state = 'starting'
        try:
            if self.p['kind'] == 'checkpoint' and not self.p['login_type']:
                ca = self.directory / 'assets' / self.p['ca_file'] if self.p.get('ca_file') else None
                info = gateway_info(self.p['server'], ca)
                certificate = self.p.get('auth_mode', 'certificate' if self.p.get('certificate') else 'password') == 'certificate'
                choices = [m for m in info['methods'] if m['certificate'] == certificate]
                if len(choices) != 1:
                    raise ValueError('Откройте настройки и выберите метод входа, предложенный сервером')
                self.p = dict(self.p, login_type=choices[0]['id'])
            self.work.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Docker's 127.0.0.11 resolver is not reachable from a new namespace.
            # Resolve only VPN endpoints before isolation, preserving hostnames for TLS.
            hosts = []
            if self.p['kind'] == 'checkpoint':
                hosts.append(self.p['server'].split(':')[0])
            elif self.p['kind'] == 'anyconnect':
                hosts.append(urlsplit(self.p['server']).hostname)
            elif self.p['kind'] == 'openvpn':
                block = False
                for line in self.p['ovpn'].splitlines():
                    line = line.strip()
                    if line.startswith('</'):
                        block = False
                        continue
                    if line.startswith('<'):
                        block = True
                    if not block:
                        parts = shlex.split(line, comments=True)
                        if len(parts) > 1 and parts[0].removeprefix('--') == 'remote':
                            hosts.append(parts[1])
            nsdir = NETNS_ROOT / self.ns
            nsdir.mkdir(parents=True, exist_ok=True)
            mappings = HOSTS_FILE.read_text() + '\n'
            for host in set(hosts):
                try:
                    addresses = endpoint_addresses(host)
                except (socket.gaierror, subprocess.TimeoutExpired) as exc:
                    raise OSError(f'Не удалось разрешить имя VPN-сервера {host}: {exc}. Проверьте DNS и доступ в интернет.') from exc
                for address in addresses:
                    mappings += f'{address} {host}\n'
            (nsdir / 'hosts').write_text(mappings)
            if self.cancelled.is_set():
                self._cleanup()
                return
            run('ip', 'netns', 'add', self.ns)
            self.networked = True
            run('ip', 'link', 'add', self.host, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', self.ns)
            run('ip', 'addr', 'add', self.gateway + '/30', 'dev', self.host)
            run('ip', 'link', 'set', self.host, 'up')
            ns = ['ip', 'netns', 'exec', self.ns]
            run(*ns, 'ip', 'addr', 'add', self.peer + '/30', 'dev', 'eth0')
            run(*ns, 'ip', 'link', 'set', 'eth0', 'up')
            run(*ns, 'ip', 'link', 'set', 'lo', 'up')
            run(*ns, 'ip', 'route', 'add', 'default', 'via', self.gateway)
            if run('sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip() != '1':
                run('sysctl', '-qw', 'net.ipv4.ip_forward=1')
            run('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', self.peer + '/32', '-j', 'MASQUERADE')
            if self.p['kind'] in PERSONAL:
                # Relay the container's resolver, including Docker's loopback DNS.
                upstreams = [line.split()[1] for line in RESOLV_FILE.read_text().splitlines()
                             if line.startswith('nameserver ') and len(line.split()) > 1]
                self.spawn(['python3', '/app/dns_forward.py', self.gateway, ','.join(upstreams), '53'], log=False)
                (nsdir / 'resolv.conf').write_text(f'nameserver {self.gateway}\n')
                self.start_personal(ns)
                self.start_bridge()
                self.started()
                return
            if self.p['kind'] == 'anyconnect':
                upstreams = [line.split()[1] for line in RESOLV_FILE.read_text().splitlines()
                             if line.startswith('nameserver ') and len(line.split()) > 1]
                self.spawn(['python3', '/app/dns_forward.py', self.gateway, ','.join(upstreams), '53'], log=False)
                (nsdir / 'resolv.conf').write_text(f'nameserver {self.gateway}\n')
                self.write('transport-resolv.conf', f'nameserver {self.gateway}\n')
            # Only replies on the veth are allowed for the unprivileged SOCKS user.
            # VPN transport runs as root. Direct SOCKS/DNS fallbacks are rejected.
            run(*ns, 'iptables', '-A', 'OUTPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
            run(*ns, 'iptables', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', '65534', '-o', 'eth0', '-j', 'REJECT')
            run(*ns, 'iptables', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', '65534', '-o', 'lo', '-j', 'REJECT')
            # Each process gets its own mount namespace. Only the SOCKS resolver
            # uses corporate DNS; VPN endpoint resolution keeps the container DNS.
            dns = self.p['dns'].split(',') if self.p['dns'] else []
            publish(self.work, dns, 'manual' if dns else 'waiting')
            resolver = str(self.work / 'resolv.conf')
            if self.p['kind'] == 'openvpn':
                config = ovpn_config(self.p['ovpn'], {p.name for p in (self.directory / 'assets').iterdir()})
                config = config.replace('/run/work-vpn/assets/', str(self.directory / 'assets') + '/')
                config = config.replace('/run/work-vpn/auth.txt', str(self.work / 'auth.txt'))
                self.write('auth.txt', self.p['username'] + '\n' + self.p['password'] + '\n')
                conf = self.write('client.ovpn', config)
                self.write('dns-manual', self.p['dns'])
                # OpenVPN 2.7 converts legacy dhcp-option DNS to dns_server_*.
                # Only this manager-owned hook can execute; imports reject scripts.
                hook = self.write('dns-hook', '#!/usr/bin/python3\nimport os, sys\n'
                                  'sys.path.insert(0, "/app")\nfrom vpn_dns import update\n'
                                  f'update({str(self.work)!r}, os.environ)\n')
                Path(hook).chmod(0o755)
                args = ['openvpn', '--config', conf, '--dev', 'tun', '--script-security', '2',
                        '--dns-updown', hook, '--down', hook,
                        '--up-restart', '--verb', '3', '--auth-retry', 'none']
                if self.p.get('key_password'):
                    args += ['--askpass', self.write('key-password', self.p['key_password'] + '\n')]
            elif self.p['kind'] == 'anyconnect':
                sso = self.p.get('anyconnect_auth') == 'sso'
                self.write('password', '' if sso else self.p['password'] + '\n')
                self.write('dns-manual', self.p['dns'])
                (self.work / 'vpnc').mkdir(mode=0o700)
                hook = self.write('anyconnect-hook', '#!/bin/sh\nexec python3 /app/anyconnect_hook.py '
                                  + shlex.quote(str(self.work)) + '\n')
                Path(hook).chmod(0o755)
                args = ['unshare', '--mount', '/bin/sh', '/app/anyconnect-start.sh', str(self.work),
                        '--protocol=anyconnect', '--useragent=AnyConnect', '--non-inter', '--passwd-on-stdin',
                        '--user', self.p['username'], '--interface', 'tun', '--script', hook,
                        '--reconnect-timeout', '1', '--force-dpd', '20', '--disable-ipv6']
                if self.p.get('authgroup'):
                    args += ['--authgroup', self.p['authgroup']]
                if sso:
                    pass
                elif self.p.get('mfa_form') == 'main:password':
                    self.log('Поле main:password содержит основной пароль. Ответ MFA для него отключён, '
                             'чтобы не повторять отправку push в форму входа.')
                elif self.p.get('mfa_form'):
                    args += ['--form-entry', self.p['mfa_form'] + '=' + self.p['mfa_value']]
                else:
                    # Only known secondary-factor fields; never answer a repeated
                    # primary main:password prompt with push or the password.
                    for field in ('main:secondary_password', 'main:password2', 'challenge:password', 'challenge:answer'):
                        args += ['--form-entry', field + '=' + self.p.get('mfa_value', 'push')]
                if self.p.get('anyconnect_ca'):
                    args += ['--cafile', str(self.directory / 'assets' / self.p['anyconnect_ca'])]
                if sso:
                    # No saved account credentials or automatic MFA answers in SSO.
                    args = ['unshare', '--mount', '/bin/sh', '/app/anyconnect-start.sh', str(self.work),
                            '--protocol=anyconnect', '--useragent=AnyConnect', '--non-inter',
                            '--interface', 'tun', '--script', hook, '--reconnect-timeout', '1',
                            '--force-dpd', '20', '--disable-ipv6']
                    if self.p.get('authgroup'):
                        args += ['--authgroup', self.p['authgroup']]
                    if self.p.get('anyconnect_ca'):
                        args += ['--cafile', str(self.directory / 'assets' / self.p['anyconnect_ca'])]
                    args = ['env', 'ANYCONNECT_SSO_WORK=' + str(self.work),
                            'ANYCONNECT_SSO_UID=' + str(64000 + self.p['slot']),
                            'ANYCONNECT_SSO_CA=' + (str(self.directory / 'assets' / self.p['anyconnect_ca'])
                                                   if self.p.get('anyconnect_ca') else '')] + args
                args += [self.p['server']]
                self.log('AnyConnect: откройте окно SSO в панели.' if sso else
                         'AnyConnect: User-Agent=AnyConnect; ожидаем входа; '
                         'подтвердите push на телефоне, если сервер его запросит.')
            else:
                if not self.p['login_type']:
                    raise ValueError('Сначала получите и выберите login-type Check Point')
                values = {
                    'server-name': self.p['server'], 'login-type': self.p['login_type'],
                    'tunnel-type': self.p['tunnel'], 'transport-type': 'udp',
                    'no-dns': 'true' if dns else 'false', 'default-route': 'false',
                    'no-split-dns': 'true',
                    'log-level': 'info', 'keychain': 'false',
                }
                certificate_auth = self.p.get('auth_mode', 'certificate' if self.p.get('certificate') else 'password') == 'certificate'
                if certificate_auth:
                    if not self.p.get('certificate'):
                        raise ValueError('Загрузите личный сертификат .p12/.pfx')
                    values.update({'cert-type': 'pkcs12', 'cert-path': str(self.directory / 'assets' / self.p['certificate']),
                                   'cert-password': self.p['cert_password']})
                else:
                    values.update({'user-name': self.p['username'],
                                   'password': base64.b64encode(self.p['password'].encode()).decode()})
                if self.p.get('ca_file'):
                    values['ca-cert'] = str(self.directory / 'assets' / self.p['ca_file'])
                conf = self.write('snx.conf', '\n'.join(f'{k}={v}' for k, v in values.items()) + '\n')
                # snx-rs writes only this profile's resolver, never the container's.
                args = ['unshare', '--mount', '/bin/sh', '/app/checkpoint-start.sh',
                        resolver, conf]
            self.spawn(ns + args)
            config = self.socks_config(self.peer, {'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}})
            socks_conf = self.write('socks.json', json.dumps(config))
            # This config contains no VPN credentials and is read by nobody.
            self.work.parent.chmod(0o755)
            self.work.chmod(0o755)
            Path(socks_conf).chmod(0o644)
            self.spawn(ns + ['unshare', '--mount', '/bin/sh', '-c',
                'mount --bind "$1" /etc/resolv.conf && exec setpriv --reuid=65534 --regid=65534 --clear-groups xray run -config "$2"',
                'socks', resolver, socks_conf], log=False)
            self.start_bridge()
            dns_input = ('resolv:' + resolver if self.p['kind'] == 'checkpoint' and not dns
                         else '@' + str(self.work / 'dns-state.json'))
            self.spawn(ns + ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
                            'python3', '/app/dns_forward.py', self.peer,
                            dns_input], log=False)
            for incoming, outgoing in [('TCP4-LISTEN', 'TCP4'), ('UDP4-RECVFROM', 'UDP4')]:
                self.spawn(['socat', '-T', '10', f"{incoming}:{10530 + self.p['slot']},fork,reuseaddr", f'{outgoing}:{self.peer}:5353'], log=False)
            if self.p['kind'] != 'anyconnect':
                self.started()
        except Exception as exc:
            self.retryable = not isinstance(exc, ValueError)
            self.log('Ошибка запуска: ' + str(exc))
            if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
                self.log(exc.stderr.strip())
            self._cleanup()
            self.state = 'error'

    def socks_config(self, address, outbound):
        return {'log': {'loglevel': 'warning'},
                'inbounds': [{'listen': address, 'port': 1080 + self.p['slot'],
                              'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True, 'ip': address}}],
                'outbounds': [outbound]}

    def dns_status(self):
        if self.p['kind'] == 'checkpoint' and not self.p['dns']:
            return resolver_state(self.work / 'resolv.conf')
        return read_state(self.work / 'dns-state.json')

    def start_bridge(self):
        config = self.socks_config('0.0.0.0', {
            'protocol': 'socks', 'settings': {'servers': [
                {'address': self.peer, 'port': 1080 + self.p['slot']} ]}})
        path = self.write('bridge.json', json.dumps(config))
        self.spawn(['xray', 'run', '-config', path], log=False)

    def metrics(self):
        if self.state != 'running_unverified':
            return None
        return {'traffic': self.traffic.sample(self.host), 'external_ip': self.external_ip,
                'vpn_ip': self.vpn_ip, 'ip_status': self.ip_status,
                'uptime': max(0, time.time() - self.started_at) if self.started_at else 0}

    def discover_ip(self, attempt):
        if self.p['kind'] not in PERSONAL:
            result = run('ip', '-n', self.ns, '-j', '-4', 'addr', 'show')
            for interface in json.loads(result.stdout):
                if interface.get('ifname') in ('lo', 'eth0'):
                    continue
                for address in interface.get('addr_info', []):
                    if address.get('family') == 'inet' and address.get('scope') == 'global':
                        return str(ipaddress.IPv4Address(address['local']))
            return None
        for url, trace in [('https://www.cloudflare.com/cdn-cgi/trace', True),
                           ('https://api.ipify.org', False),
                           ('https://checkip.amazonaws.com', False)]:
            if attempt.is_set():
                return None
            try:
                result = run('curl', '-4', '--silent', '--fail', '--noproxy', '',
                             '--proxy', f"socks5h://127.0.0.1:{1080 + self.p['slot']}",
                             '--connect-timeout', '3', '--max-time', '6', '--max-filesize', '4096',
                             '--proto', '=https', url, check=False)
                if result.returncode:
                    continue
                value = result.stdout.strip()
                if trace:
                    value = next((line[3:] for line in value.splitlines() if line.startswith('ip=')), '')
                address = ipaddress.ip_address(value)
                if address.is_global:
                    return str(address)
            except (OSError, ValueError, subprocess.SubprocessError):
                continue
        return None

    def monitor_ip(self, attempt):
        if attempt.wait(5):
            return
        while not attempt.is_set():
            address = None
            try:
                address = self.discover_ip(attempt)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            with self.lock:
                if attempt.is_set():
                    return
                self.ip_status = 'available' if address else 'unavailable'
                if self.p['kind'] in PERSONAL:
                    self.external_ip = address
                else:
                    self.vpn_ip = address
            if attempt.wait(300 if address and self.p['kind'] in PERSONAL else 30):
                return

    def monitor_connection(self, attempt):
        if attempt.wait(5):
            return
        while not attempt.is_set():
            try:
                self.check_connection(attempt)
            except (ValueError, OSError, subprocess.SubprocessError):
                pass
            if attempt.wait(30):
                return

    def check_connection(self, attempt=None):
        attempt = attempt or self.stopping
        with self.probe_lock:
            if attempt.is_set():
                return None
            target = self.p.get('probe_url')
            if target:
                urls = [target]
            elif self.p['kind'] in PERSONAL:
                urls = [u.strip() for u in self.p.get('watchdog_urls', '').split(',') if u.strip()]
                urls = urls or ['https://www.cloudflare.com/cdn-cgi/trace', 'https://www.google.com/generate_204']
            else:
                raise ValueError('Укажите рабочий сайт в настройках подключения — он будет использоваться для проверки.')
            for url in urls:
                try:
                    result = self.probe(url)
                except (OSError, subprocess.SubprocessError):
                    result = {'reachable': False, 'http_status': '', 'message': 'Нет ответа через VPN'}
                result.update(url=url, checked_at=time.time())
                if result['reachable']:
                    break
            with self.lock:
                if not attempt.is_set():
                    self.last_probe = result
            return result

    def stop(self):
        self.cancelled.set()
        self.stopping.set()
        with self.lock:
            self._cleanup()
        if self.worker and self.worker is not threading.current_thread():
            self.worker.join(timeout=30)

    def _cleanup(self):
        with self.lock:
            self.stopping.set()
            for proc in self.children:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            for proc in self.children:
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=3)
                # Also reap forked relay workers if their parent exited first.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.children.clear()
            if self.networked:
                run('iptables', '-t', 'nat', '-D', 'POSTROUTING', '-s', self.peer + '/32', '-j', 'MASQUERADE', check=False)
                run('ip', 'link', 'delete', self.host, check=False)
                run('ip', 'netns', 'delete', self.ns, check=False)
                self.networked = False
            shutil.rmtree(NETNS_ROOT / self.ns, ignore_errors=True)
            shutil.rmtree(self.work, ignore_errors=True)
            self.state = 'stopped'
            self.last_probe = None
            self.external_ip = None
            self.vpn_ip = None
            self.ip_status = 'pending'
            self.started_at = None
            self.retry_at = None

    def probe(self, url):
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Нужен HTTP(S) URL без логина и пароля')
        result = run('curl', '--silent', '--output', '/dev/null', '--write-out', '%{http_code}',
                     '--noproxy', '', '--proxy', f"socks5h://127.0.0.1:{1080 + self.p['slot']}",
                     '--connect-timeout', '5', '--max-time', '10', '--proto', '=http,https', url, check=False)
        # A 401/403 still proves HTTP reachability, not application permission.
        return {'reachable': result.returncode == 0, 'http_status': result.stdout,
                'message': 'Ответ получен' if result.returncode == 0 else 'Нет ответа: проверьте VPN, DNS и сертификат сайта'}
