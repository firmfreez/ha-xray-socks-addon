"""Mobile app notification services through the Supervisor Core proxy."""
import json
import os
import re
from urllib.request import Request, urlopen


def request(path, data=None):
    token = os.environ.get('SUPERVISOR_TOKEN')
    if not token:
        raise OSError('Home Assistant API доступен только внутри аддона')
    req = Request('http://supervisor/core/api/' + path,
                  data=None if data is None else json.dumps(data).encode(),
                  headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with urlopen(req, timeout=10) as response:
        return json.load(response)


def phones():
    result = []
    for domain in request('services'):
        if domain.get('domain') == 'notify':
            for name, details in domain.get('services', {}).items():
                if re.fullmatch(r'mobile_app_[a-z0-9_]+', name):
                    result.append({'id': name, 'name': details.get('name') or name.removeprefix('mobile_app_')})
    return sorted(result, key=lambda x: x['name'])


def disconnected(profile, reason):
    errors = []
    for target in profile.get('notify_targets', []):
        try:
            request('services/notify/' + target, {
                'title': 'VPN отключён',
                'message': f'Подключение «{profile["name"]}» отключено. {reason}',
                'data': {'tag': 'vpn-disconnect-' + profile.get('id', str(profile['slot']))}})
        except (OSError, ValueError):
            errors.append(target)
    if errors:
        raise OSError('Не доставлено уведомление: ' + ', '.join(errors))
