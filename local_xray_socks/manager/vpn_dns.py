"""DNS state shared by the fixed OpenVPN hook, SOCKS resolver and LAN relay."""
import ipaddress
import json
import os
import re
from pathlib import Path
import sys


def ipv4_servers(values):
    result = []
    for value in values:
        try:
            address = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            continue
        if address.is_unspecified or address.is_loopback or address.is_multicast:
            continue
        if str(address) not in result:
            result.append(str(address))
    return result


def pushed_servers(env):
    values = []
    for key in sorted(env):
        match = re.fullmatch(r'dns_server_(\d+)_address_(\d+)', key)
        if match:
            server, address = match.groups()
            if (env.get(f'dns_server_{server}_transport', 'plain') in ('plain', 'unset')
                    and env.get(f'dns_server_{server}_port_{address}', '53') == '53'):
                values.append(env[key])
        if key.startswith('foreign_option_'):
            parts = env[key].split()
            if len(parts) == 3 and parts[:2] == ['dhcp-option', 'DNS']:
                values.append(parts[2])
    return ipv4_servers(values)


def publish(work, servers, source):
    work = Path(work)
    servers = ipv4_servers(servers)
    # Keep the inode: the SOCKS mount namespace bind-mounts this file.
    resolver = work / 'resolv.conf'
    resolver.write_text(''.join(f'nameserver {ip}\n' for ip in servers)
                        + ('' if servers else 'nameserver 127.0.0.1\n')
                        + 'options timeout:2 attempts:2\n')
    resolver.chmod(0o644)
    # The relay reopens this atomic snapshot for every request.
    tmp = work / 'dns-state.tmp'
    tmp.write_text(json.dumps({'servers': servers, 'source': source}))
    tmp.chmod(0o644)
    tmp.replace(work / 'dns-state.json')


def read_state(path):
    try:
        state = json.loads(Path(path).read_text())
        return {'servers': ipv4_servers(state['servers']), 'source': state['source']}
    except (OSError, ValueError, KeyError, TypeError):
        return {'servers': [], 'source': 'unavailable'}


def update(work, env):
    work = Path(work)
    if env.get('script_type') in ('down', 'dns-down', 'route-pre-down'):
        publish(work, [], 'disconnected')
        return
    manual = ipv4_servers((work / 'dns-manual').read_text().split(','))
    servers = manual or pushed_servers(env)
    source = 'manual' if manual else 'openvpn' if servers else 'missing'
    publish(work, servers, source)
    print('DNS: ' + (', '.join(servers) + f' ({source})' if servers
                    else 'сервер не передал IPv4 DNS; укажите корпоративный DNS в профиле'), flush=True)


if __name__ == '__main__':
    # The directory is supplied by the manager, never by an imported profile.
    update(sys.argv[1], os.environ)
