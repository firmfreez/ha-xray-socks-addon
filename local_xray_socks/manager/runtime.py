"""Linux-only runtime. Every profile has its own routes, processes and resolver."""
import base64
import json
from collections import deque
import os
from pathlib import Path
import shutil
import signal
import shlex
import socket
import subprocess
import threading

from model import ovpn_config, PERSONAL, personal_options

NETNS_ROOT = Path('/etc/netns')
HOSTS_FILE = Path('/etc/hosts')
RESOLV_FILE = Path('/etc/resolv.conf')


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=15)


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

    def start_personal(self, prefix):
        options = self.write('options.json', json.dumps(personal_options(self.p)))
        self.spawn(prefix + ['env', f'VPN_OPTIONS_FILE={options}',
                            f'VPN_RUNTIME_DIR={self.work}', f"AWG_INTERFACE=awg{self.p['slot']}",
                            f"SOCKS_PORT={1080 + self.p['slot']}", '/run.sh'])

    def started(self):
        self.state = 'running_unverified'
        self.log('Процессы запущены. Проверьте сайт через SOCKS; это ещё не подтверждение VPN.')
        threading.Thread(target=self.monitor, daemon=True).start()

    def log(self, text):
        for key in ('password', 'cert_password', 'key_password', 'username', 'link'):
            secret = self.p.get(key)
            if secret:
                text = text.replace(secret, '[hidden]')
                text = text.replace(base64.b64encode(secret.encode()).decode(), '[hidden]')
        # Never retain key blocks or bearer/session data in the panel.
        if any(x in text.lower() for x in ('private key', 'auth-token', 'session_id', 'authorization:', 'cookie:')):
            text = '[sensitive log line omitted]'
        self.logs.append(text[-2000:])

    def spawn(self, args, log=True):
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True,
                                text=True, bufsize=1)
        self.children.append(proc)
        def reader():
            for line in proc.stdout:
                self.log(('' if log else '[runtime] ') + line.rstrip())
        threading.Thread(target=reader, daemon=True).start()
        return proc

    def write(self, name, value):
        path = self.work / name
        path.write_text(value)
        path.chmod(0o600)
        return str(path)

    def start(self):
        with self.lock:
            self._start()

    def _start(self):
        if self.state not in ('stopped', 'error'):
            return
        self.stopping.clear()
        self.state = 'starting'
        try:
            self.work.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.p['kind'] in PERSONAL and self.p['slot'] == 0:
                # Preserve the original direct listener, UDP and routing on 1080.
                self.start_personal([])
                self.started()
                return
            run('ip', 'netns', 'add', self.ns)
            self.networked = True
            # Docker's 127.0.0.11 resolver is not reachable from a new namespace.
            # Resolve only VPN endpoints before isolation, preserving hostnames for TLS.
            hosts = []
            if self.p['kind'] == 'checkpoint':
                hosts.append(self.p['server'].split(':')[0])
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
                addresses = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
                for address in sorted({x[4][0] for x in addresses}):
                    mappings += f'{address} {host}\n'
            (nsdir / 'hosts').write_text(mappings)
            run('ip', 'link', 'add', self.host, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', self.ns)
            run('ip', 'addr', 'add', self.gateway + '/30', 'dev', self.host)
            run('ip', 'link', 'set', self.host, 'up')
            ns = ['ip', 'netns', 'exec', self.ns]
            run(*ns, 'ip', 'addr', 'add', self.peer + '/30', 'dev', 'eth0')
            run(*ns, 'ip', 'link', 'set', 'eth0', 'up')
            run(*ns, 'ip', 'link', 'set', 'lo', 'up')
            run(*ns, 'sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1')
            run(*ns, 'ip', 'route', 'add', 'default', 'via', self.gateway)
            run('sysctl', '-qw', 'net.ipv4.ip_forward=1')
            run('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', self.peer + '/32', '-j', 'MASQUERADE')
            if self.p['kind'] in PERSONAL:
                # Relay the container's resolver, including Docker's loopback DNS.
                upstreams = [line.split()[1] for line in RESOLV_FILE.read_text().splitlines()
                             if line.startswith('nameserver ') and len(line.split()) > 1]
                self.spawn(['python3', '/app/dns_forward.py', self.gateway, ','.join(upstreams), '53'], log=False)
                (nsdir / 'resolv.conf').write_text(f'nameserver {self.gateway}\n')
                self.start_personal(ns)
                self.spawn(['socat', f"TCP4-LISTEN:{1080 + self.p['slot']},fork,reuseaddr",
                            f"TCP4:{self.peer}:{1080 + self.p['slot']}"], log=False)
                self.started()
                return
            # Only replies on the veth are allowed for the unprivileged SOCKS user.
            # VPN transport runs as root. Direct SOCKS/DNS fallbacks are rejected.
            run(*ns, 'iptables', '-A', 'OUTPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
            run(*ns, 'iptables', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', '65534', '-o', 'eth0', '-j', 'REJECT')
            run(*ns, 'iptables', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', '65534', '-o', 'lo', '-j', 'REJECT')
            # Each process gets its own mount namespace. Only the SOCKS resolver
            # uses corporate DNS; VPN endpoint resolution keeps the container DNS.
            dns = self.p['dns'].split(',') if self.p['dns'] else []
            resolver = self.write('resolv.conf', ''.join(f'nameserver {x}\n' for x in dns) + 'options timeout:2 attempts:2\n')
            Path(resolver).chmod(0o644)  # Readable by the unprivileged SOCKS process.
            if self.p['kind'] == 'openvpn':
                config = ovpn_config(self.p['ovpn'], {p.name for p in (self.directory / 'assets').iterdir()})
                config = config.replace('/run/work-vpn/assets/', str(self.directory / 'assets') + '/')
                config = config.replace('/run/work-vpn/auth.txt', str(self.work / 'auth.txt'))
                self.write('auth.txt', self.p['username'] + '\n' + self.p['password'] + '\n')
                conf = self.write('client.ovpn', config)
                args = ['openvpn', '--config', conf, '--dev', 'tun', '--script-security', '1', '--verb', '3', '--auth-retry', 'none']
                if self.p.get('key_password'):
                    args += ['--askpass', self.write('key-password', self.p['key_password'] + '\n')]
            else:
                if not self.p['login_type']:
                    raise ValueError('Сначала получите и выберите login-type Check Point')
                values = {
                    'server-name': self.p['server'], 'login-type': self.p['login_type'],
                    'user-name': self.p['username'],
                    'password': base64.b64encode(self.p['password'].encode()).decode(),
                    'tunnel-type': self.p['tunnel'], 'transport-type': 'udp',
                    'no-dns': 'true', 'default-route': 'false',
                    'log-level': 'info', 'keychain': 'false',
                }
                if self.p.get('certificate'):
                    values.update({'cert-type': 'pkcs12', 'cert-path': str(self.directory / 'assets' / self.p['certificate']),
                                   'cert-password': self.p['cert_password']})
                if self.p.get('ca_file'):
                    values['ca-cert'] = str(self.directory / 'assets' / self.p['ca_file'])
                conf = self.write('snx.conf', '\n'.join(f'{k}={v}' for k, v in values.items()) + '\n')
                args = ['snx-rs', '-c', conf]
            self.spawn(ns + args)
            self.spawn(ns + ['unshare', '--mount', '/bin/sh', '-c',
                'mount --bind "$1" /etc/resolv.conf && exec setpriv --reuid=65534 --regid=65534 --clear-groups microsocks -i "$2" -p 1080',
                'socks', resolver, self.peer], log=False)
            self.spawn(['socat', f"TCP4-LISTEN:{1080 + self.p['slot']},fork,reuseaddr", f'TCP4:{self.peer}:1080'], log=False)
            self.spawn(ns + ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
                            'python3', '/app/dns_forward.py', self.peer, self.p['dns']], log=False)
            for incoming, outgoing in [('TCP4-LISTEN', 'TCP4'), ('UDP4-RECVFROM', 'UDP4')]:
                self.spawn(['socat', '-T', '10', f"{incoming}:{10530 + self.p['slot']},fork,reuseaddr", f'{outgoing}:{self.peer}:5353'], log=False)
            self.started()
        except Exception as exc:
            self.log('Ошибка запуска: ' + str(exc))
            if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
                self.log(exc.stderr.strip())
            self.stop()
            self.state = 'error'

    def monitor(self):
        while not self.stopping.wait(2):
            if any(p.poll() is not None for p in self.children):
                self.log('Один из процессов завершился. Профиль остановлен; проверьте журнал и авторизацию.')
                self.stop()
                self.state = 'error'
                return

    def stop(self):
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
                shutil.rmtree(NETNS_ROOT / self.ns, ignore_errors=True)
                self.networked = False
            shutil.rmtree(self.work, ignore_errors=True)
            self.state = 'stopped'

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
