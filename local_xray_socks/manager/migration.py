"""One-time, restartable migration from Supervisor options to named profiles."""
import json
from pathlib import Path
import uuid


def legacy_profiles(options):
    candidates = []
    selected = str(options.get('amneziawg_profile', '1'))
    common = {k: options[k] for k in ('loglevel', 'watchdog_enabled', 'watchdog_urls') if k in options}
    link = options.get('link', '')
    if link.startswith('vless://'):
        candidates.append(dict(common, legacy_key='vless', kind='vless', name='VLESS', link=link,
                               autostart=options.get('protocol', 'vless') == 'vless'))
    for index in range(1, 5):
        key = 'amneziawg_config' + (f'_{index}' if index > 1 else '')
        config = options.get(key, '')
        # Retain the old runner's compatibility with configs pasted into link.
        if str(index) == selected and options.get('protocol') == 'amneziawg' and '[Interface]' not in config and '[Interface]' in link:
            config = link
        if config.strip():
            candidates.append(dict(common, legacy_key=f'awg-{index}', kind='amneziawg',
                                   name=f'AmneziaWG {index}', amneziawg_config=config,
                                   autostart=options.get('protocol') == 'amneziawg' and selected == str(index)))
    # Active legacy connection always retains 1080; inactive profiles never auto-start.
    candidates.sort(key=lambda p: not p['autostart'])
    for slot, profile in enumerate(candidates):
        profile['id'] = uuid.uuid5(uuid.NAMESPACE_URL, 'local_xray_socks/options-v1/' + profile.pop('legacy_key')).hex
        profile['slot'] = slot
    return candidates


def migrate(manager, options_file=Path('/data/options.json')):
    marker = manager.root / 'migration-v1.json'
    if marker.exists() or not options_file.exists():
        return
    raw = options_file.read_bytes()
    options = json.loads(raw)
    backup = manager.root / 'options-before-0.6.json'
    if not backup.exists():
        with backup.open('xb') as output:
            output.write(raw)
        backup.chmod(0o600)
    for profile in legacy_profiles(options):
        # Deterministic IDs permit retry after a crash without duplicates or overwrites.
        if profile['id'] not in manager.profiles:
            manager.save(profile)
    tmp = marker.with_suffix('.tmp')
    tmp.write_text(json.dumps({'version': 1}))
    tmp.chmod(0o600)
    tmp.replace(marker)
