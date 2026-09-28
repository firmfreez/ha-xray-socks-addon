"""Translate VLESS share links into Xray configuration without discarding transport."""
import json
import os
import sys
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import UUID


def outbound(link):
    uri = urlsplit(link)
    try:
        ident = str(UUID(unquote(uri.username or '')))
        if uri.scheme != 'vless' or not uri.hostname or not uri.port:
            raise ValueError()
    except ValueError:
        raise ValueError('Нужна VLESS-ссылка с UUID и адресом host:port') from None
    params = parse_qs(uri.query, keep_blank_values=True)
    q = lambda key, default='': params.get(key, [default])[0]
    network = q('type', 'tcp')
    network = {'raw': 'tcp', 'websocket': 'ws', 'splithttp': 'xhttp'}.get(network, network)
    if network not in ('tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade', 'kcp'):
        raise ValueError('Неподдерживаемый транспорт VLESS: ' + network)
    security = q('security', 'tls')
    if security not in ('tls', 'reality', 'none'):
        raise ValueError('Неподдерживаемая защита VLESS: ' + security)
    stream = {'network': network, 'security': security,
              'sockopt': {'tcpKeepAliveIdle': 45, 'tcpKeepAliveInterval': 15, 'tcpUserTimeout': 10000}}
    if security == 'tls':
        tls = {'serverName': q('sni', uri.hostname)}
        if q('fp'):
            tls['fingerprint'] = q('fp')
        if q('alpn'):
            tls['alpn'] = q('alpn').split(',')
        if q('allowInsecure') in ('1', 'true'):
            tls['allowInsecure'] = True
        stream['tlsSettings'] = tls
    elif security == 'reality':
        if not q('pbk'):
            raise ValueError('В ссылке REALITY отсутствует pbk')
        stream['realitySettings'] = {'serverName': q('sni', uri.hostname),
                                     'fingerprint': q('fp', 'chrome'), 'publicKey': q('pbk'),
                                     'shortId': q('sid'), 'spiderX': q('spx', '/')}
    if network in ('ws', 'httpupgrade', 'xhttp'):
        settings = {'path': q('path', '/')}
        if q('host'):
            if network == 'ws':
                settings['headers'] = {'Host': q('host')}
            else:
                settings['host'] = q('host')
        if network == 'xhttp':
            settings['mode'] = q('mode', 'auto')
            if q('extra'):
                extra = json.loads(q('extra'))
                if not isinstance(extra, dict):
                    raise ValueError('XHTTP extra должен быть объектом JSON')
                settings['extra'] = extra
        stream[network + 'Settings'] = settings
    elif network == 'grpc':
        stream['grpcSettings'] = {'serviceName': q('serviceName'), 'multiMode': q('mode') == 'multi'}
        if q('authority'):
            stream['grpcSettings']['authority'] = q('authority')
    elif network == 'kcp':
        stream['kcpSettings'] = {}
        masks = []
        header = q('headerType', 'none')
        if header != 'none':
            if header not in ('srtp', 'utp', 'wechat-video', 'dtls', 'wireguard'):
                raise ValueError('Неподдерживаемый заголовок mKCP: ' + header)
            masks.append({'type': 'header-' + {'wechat-video': 'wechat'}.get(header, header)})
        masks.append({'type': 'mkcp-aes128gcm', 'settings': {'password': q('seed')}}
                     if q('seed') else {'type': 'mkcp-original'})
        stream['finalmask'] = {'udp': masks}
    elif q('headerType') not in ('', 'none'):
        raise ValueError('Для TCP используйте headerType=none')
    user = {'id': ident, 'encryption': q('encryption', 'none')}
    if q('flow'):
        user['flow'] = q('flow')
    return {'protocol': 'vless', 'tag': 'proxy',
            'settings': {'vnext': [{'address': uri.hostname, 'port': uri.port, 'users': [user]}]},
            'streamSettings': stream}


def config(options, port, udp_ip):
    return {'log': {'loglevel': options.get('loglevel', 'warning'), 'access': '/dev/stdout', 'error': '/dev/stderr'},
            'inbounds': [{'listen': '0.0.0.0', 'port': port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': True, 'ip': udp_ip},
                          'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic']}}],
            'outbounds': [outbound(options['link'])]}


if __name__ == '__main__':
    try:
        with open(os.environ.get('VPN_OPTIONS_FILE', '/data/options.json')) as source:
            options = json.load(source)
        print(json.dumps(config(options, int(os.environ.get('SOCKS_PORT', '1080')),
                                os.environ.get('SOCKS_UDP_IP', '0.0.0.0'))))
    except (ValueError, OSError, KeyError) as exc:
        print('VLESS: ' + str(exc), file=sys.stderr)
        sys.exit(1)
