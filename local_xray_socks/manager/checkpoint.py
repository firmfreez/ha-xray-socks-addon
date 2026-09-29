"""Read the gateway's advertised login choices without sending credentials."""
import re
import subprocess


def parse_methods(text):
    methods = []
    for label, ident, factors in re.findall(r'^\s*\[([^\]]+)\]:\s*(vpn_[^\s]+)\s*\(([^)]*)\)', text, re.M):
        methods.append({'id': ident, 'label': label,
                        'factors': [s.strip() for s in factors.split(',')],
                        'certificate': factors.strip() == 'certificate'})
    return methods


def gateway_info(server, ca=None):
    args = ['snx-rs', '-m', 'info', '-s', server]
    if ca:
        args += ['--ca-cert', str(ca)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=25)
    text = (result.stdout + result.stderr)[-12000:]
    if result.returncode:
        raise OSError('Не удалось получить методы входа. Проверьте адрес сервера и его CA-сертификат. ' + text[-1500:])
    return {'text': text, 'methods': parse_methods(text)}
