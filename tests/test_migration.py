import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from migration import migrate, legacy_profiles
from server import Manager
from model import validate
from runtime import Runtime

LINK = 'vless://12345678-1234-4234-9234-123456789abc@vpn.example:443?type=tcp&security=tls'
AWG = '[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = public\nEndpoint = vpn.example:443\n'


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.options = self.base / 'options.json'
        self.old = dict(protocol='amneziawg', link=LINK, amneziawg_profile='3',
                        amneziawg_config=AWG, amneziawg_config_2=AWG+'#2',
                        amneziawg_config_3=AWG+'#3', amneziawg_config_4=AWG+'#4',
                        loglevel='info', watchdog_enabled=False, watchdog_urls='https://probe.example')
        self.options.write_text(json.dumps(self.old))
        self.manager = Manager(self.base / 'profiles')

    def tearDown(self):
        self.tmp.cleanup()

    def test_all_profiles_migrated_active_keeps_port_and_watchdog(self):
        original = self.options.read_bytes()
        migrate(self.manager, self.options)
        profiles = list(self.manager.profiles.values())
        self.assertEqual(len(profiles), 5)
        active = [p for p in profiles if p['autostart']]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]['slot'], 0)
        self.assertEqual(active[0]['amneziawg_config'], AWG+'#3')
        self.assertFalse(active[0]['watchdog_enabled'])
        self.assertEqual(active[0]['watchdog_urls'], 'https://probe.example')
        self.assertEqual(self.options.read_bytes(), original)
        backup = self.manager.root / 'options-before-0.6.json'
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)

    def test_restart_never_recreates_deleted_or_overwrites_edited_profile(self):
        migrate(self.manager, self.options)
        profiles = list(self.manager.profiles.values())
        ident = profiles[0]['id']
        self.manager.save(dict(profiles[0], name='Renamed'))
        self.manager.action(profiles[1]['id'], 'delete', {})
        reloaded = Manager(self.manager.root)
        migrate(reloaded, self.options)
        self.assertEqual(len(reloaded.profiles), 4)
        self.assertEqual(reloaded.profiles[ident]['name'], 'Renamed')

    def test_interrupted_migration_resumes_without_duplicate(self):
        self.manager.save(legacy_profiles(self.old)[0])
        migrate(self.manager, self.options)
        self.assertEqual(len(self.manager.profiles), 5)

    def test_vless_active_keeps_1080_and_fresh_install_stays_empty(self):
        profiles = legacy_profiles(dict(self.old, protocol='vless'))
        self.assertEqual(profiles[0]['kind'], 'vless')
        self.assertEqual(profiles[0]['slot'], 0)
        self.assertTrue(profiles[0]['autostart'])
        self.assertEqual(legacy_profiles(dict(protocol='vless', link='')), [])

    def test_legacy_config_in_link(self):
        profiles = legacy_profiles(dict(protocol='amneziawg', link=AWG, amneziawg_profile='1'))
        self.assertEqual(profiles[0]['amneziawg_config'], AWG)


class RuntimeIntegrationContractTests(unittest.TestCase):
    def test_primary_reuses_original_runner_without_network_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            profile = validate(dict(name='Primary', kind='vless', slot=0, link=LINK,
                                    watchdog_enabled=False, autostart=True))
            runtime = Runtime(profile, directory)
            runtime.work = directory / 'run'
            with patch('runtime.run') as commands, patch.object(runtime, 'spawn') as spawn, patch.object(runtime, 'started'):
                runtime.start()
            commands.assert_not_called()
            args = spawn.call_args.args[0]
            self.assertIn('SOCKS_PORT=1080', args)
            self.assertEqual(args[-1], '/run.sh')
            options = json.loads((runtime.work / 'options.json').read_text())
            self.assertEqual(options['link'], LINK)
            self.assertFalse(options['watchdog_enabled'])

    def test_additional_personal_profile_has_isolated_files_routes_and_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            resolver = directory / 'resolver'
            resolver.write_text('nameserver 127.0.0.11\n')
            profile = validate(dict(name='Second', kind='amneziawg', slot=2, amneziawg_config=AWG))
            runtime = Runtime(profile, directory)
            runtime.work = directory / 'run'
            with patch('runtime.NETNS_ROOT', directory / 'netns'), patch('runtime.RESOLV_FILE', resolver), \
                 patch('runtime.run') as commands, patch.object(runtime, 'spawn') as spawn, patch.object(runtime, 'started'):
                runtime.start()
            commands.assert_any_call('ip', 'netns', 'add', 'wvpn2')
            calls = [c.args[0] for c in spawn.call_args_list]
            runner = next(c for c in calls if c[-1] == '/run.sh')
            self.assertEqual(runner[:4], ['ip', 'netns', 'exec', 'wvpn2'])
            self.assertIn('SOCKS_PORT=1082', runner)
            self.assertIn('AWG_INTERFACE=awg2', runner)
            self.assertIn(['socat', 'TCP4-LISTEN:1082,fork,reuseaddr', 'TCP4:10.253.2.2:1082'], calls)
            self.assertTrue(runtime.networked)

    def test_openvpn_installs_egress_block_before_starting_proxy(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'assets').mkdir()
            profile = validate(dict(name='Work', kind='openvpn', slot=1, ovpn='client\ndev tun\n', dns='10.2.0.53'))
            runtime = Runtime(profile, directory)
            runtime.work = directory / 'run'
            events = []
            with patch('runtime.NETNS_ROOT', directory / 'netns'), \
                 patch('runtime.run', side_effect=lambda *a, **k: events.append(('run', a))), \
                 patch.object(runtime, 'spawn', side_effect=lambda a, **k: events.append(('spawn', a))), \
                 patch.object(runtime, 'started'):
                runtime.start()
            reject = next(i for i, (kind, args) in enumerate(events) if kind == 'run' and 'REJECT' in args)
            proxy = next(i for i, (kind, args) in enumerate(events) if kind == 'spawn' and any('microsocks' in s for s in args))
            self.assertLess(reject, proxy)
            self.assertEqual((runtime.work / 'resolv.conf').stat().st_mode & 0o777, 0o644)


if __name__ == '__main__':
    unittest.main()
