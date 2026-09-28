"""Profile validation. Imported VPN files are configuration, never shell scripts."""
import ipaddress
import re
import shlex
from urllib.parse import urlsplit
from vless import outbound

KINDS = ('vless', 'amneziawg', 'openvpn', 'checkpoint')
PERSONAL = ('vless', 'amneziawg')
SLOTS = range(9)

INLINE = {'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'extra-certs'}
FILES = INLINE | {'pkcs12', 'crl-verify'}
ALLOWED = set('''client dev proto remote remote-random resolv-retry nobind persist-key
persist-tun remote-cert-tls verify-x509-name cipher data-ciphers data-ciphers-fallback
auth auth-nocache auth-user-pass auth-retry ca cert key pkcs12 tls-auth tls-crypt
tls-crypt-v2 key-direction extra-certs crl-verify tls-version-min tls-version-max
tls-cipher tls-ciphersuites reneg-sec hand-window tran-window connect-timeout
connect-retry connect-retry-max server-poll-timeout explicit-exit-notify ping
ping-restart ping-timer-rem mute mute-replay-warnings verb route route-ipv6
route-metric route-delay route-nopull pull pull-filter redirect-gateway
redirect-private dhcp-option tun-mtu mssfix sndbuf rcvbuf fast-io float
allow-compression compress comp-lzo auth-token-user ignore-unknown-option block-outside-dns'''.split())


def filename(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', value):
        raise ValueError('Имя файла: только латинские буквы, цифры, _, - и точка')
    return value


def ovpn_config(text, assets):
    """Normalize a conservative subset; reject includes, scripts and arbitrary paths."""
    output, block = [], None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if block:
            output.append(line)
            if line == f'</{block}>':
                block = None
            continue
        if line.startswith('<'):
            tag = line[1:-1]
            if line != f'<{tag}>' or tag not in INLINE:
                raise ValueError('Неподдерживаемый inline-блок OpenVPN')
            block = tag
            output.append(line)
            continue
        args = shlex.split(line, comments=True)
        if not args:
            continue
        optional = args[:2] == ['setenv', 'opt']
        if optional:
            args = args[2:]
            if not args:
                raise ValueError('После setenv opt нужна директива OpenVPN')
        key = args[0].removeprefix('--')
        if key not in ALLOWED:
            raise ValueError(f'Директива OpenVPN не разрешена: {key}')
        if key == 'dev' and args[1:] != ['tun']:
            raise ValueError('Поддерживается только dev tun')
        if key == 'auth-user-pass':
            output.append('auth-user-pass /run/work-vpn/auth.txt')
            continue
        if key in FILES:
            if len(args) < 2 or filename(args[1]) not in assets:
                raise ValueError(f'Загрузите файл для {key} (имя без каталогов)')
            args[1] = '/run/work-vpn/assets/' + args[1]
        args[0] = key
        if optional:
            args = ['setenv', 'opt'] + args
        # OpenVPN supports double-quoted tokens, not arbitrary shell syntax.
        output.append(' '.join('"' + a.replace('\\', '\\\\').replace('"', '\\"') + '"' for a in args))
    if block:
        raise ValueError('Незакрытый inline-блок OpenVPN')
    if not output:
        raise ValueError('Профиль OpenVPN пуст')
    return '\n'.join(output) + '\n'


def validate(p):
    p = dict(p)
    p['name'] = str(p.get('name', '')).strip()
    if not 1 <= len(p['name']) <= 80:
        raise ValueError('Введите название (до 80 символов)')
    if p.get('kind') not in KINDS:
        raise ValueError('Неизвестный тип VPN')
    p['slot'] = int(p.get('slot', 0))
    if p['slot'] not in SLOTS:
        raise ValueError('Выберите слот 0–8')
    dns = [s.strip() for s in str(p.get('dns', '')).split(',') if s.strip()]
    for addr in dns:
        if ipaddress.ip_address(addr).version != 4:
            raise ValueError('В первой версии DNS должен быть IPv4')
    p['dns'] = ','.join(dns)
    for key in ('link', 'amneziawg_config', 'ovpn'):
        if not isinstance(p.get(key, ''), str):
            raise ValueError(f'Ожидается текст: {key}')
    if p['kind'] == 'vless':
        outbound(p.get('link', ''))
    if p['kind'] == 'amneziawg':
        text = p.get('amneziawg_config', '')
        if '[Interface]' not in text or '[Peer]' not in text:
            raise ValueError('Вставьте конфигурацию AmneziaWG с [Interface] и [Peer]')
    p['loglevel'] = p.get('loglevel', 'warning')
    if p['loglevel'] not in ('none', 'error', 'warning', 'info', 'debug'):
        raise ValueError('Неизвестный уровень журнала')
    p['watchdog_enabled'] = p.get('watchdog_enabled', True) is True
    p['watchdog_urls'] = p.get('watchdog_urls', '')
    if not isinstance(p['watchdog_urls'], str):
        raise ValueError('Ожидаются URL проверки')
    for key in ('server', 'login_type', 'username', 'password', 'cert_password', 'key_password'):
        value = p.get(key, '')
        if not isinstance(value, str) or any(c in value for c in '\r\n\x00'):
            raise ValueError(f'Недопустимое значение: {key}')
        p[key] = value
    if p['kind'] == 'checkpoint':
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?', p['server']):
            raise ValueError('Укажите адрес Check Point без https://')
        if p.get('tunnel', 'ssl') not in ('ssl', 'ipsec'):
            raise ValueError('Выберите ssl или ipsec')
        p['tunnel'] = p.get('tunnel', 'ssl')
        for key in ('certificate', 'ca_file'):
            p[key] = filename(p[key]) if p.get(key) else ''
    target = str(p.get('probe_url', '')).strip()
    if target and '://' not in target:
        target = 'https://' + target
    if target:
        url = urlsplit(target)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
            raise ValueError('Укажите адрес сайта для проверки: https://example.com')
    p['probe_url'] = target
    p['autostart'] = p.get('autostart') is True
    return p


def personal_options(p):
    """Use the established engine and recovery logic with a private options file."""
    return dict(protocol=p['kind'], link=p.get('link', ''), amneziawg_profile='1',
                amneziawg_config=p.get('amneziawg_config', ''), loglevel=p['loglevel'],
                watchdog_enabled=p['watchdog_enabled'], watchdog_urls=p['watchdog_urls'])
