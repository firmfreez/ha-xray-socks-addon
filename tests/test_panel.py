import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from server import Manager
from runtime import Runtime
from migration import migrate
from model import validate
from vless import outbound

LINK = 'vless://12345678-1234-4234-9234-123456789abc@vpn.example:443'


class PanelTests(unittest.TestCase):
    def test_config_revealed_only_by_details_and_password_stays_hidden(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(Manager, 'port_available', return_value=True):
            manager = Manager(Path(tmp))
            profile = manager.save(dict(name='VPN', kind='openvpn', slot=0, ovpn='client\ndev tun\n', password='secret'))
            self.assertNotIn('ovpn', profile)
            details = manager.action(profile['id'], 'details', {})
            self.assertEqual(details['ovpn'], 'client\ndev tun\n')
            self.assertNotIn('password', details)

    def test_ports_exclude_saved_profiles_and_external_listeners(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(Manager, 'port_available', return_value=True):
            manager = Manager(Path(tmp))
            manager.save(dict(name='VPN', kind='vless', slot=3, link=LINK))
            with patch.object(Manager, 'port_available', side_effect=lambda p: p != 1087):
                self.assertEqual(manager.available_ports(), [1080,1081,1082,1084,1085,1086,1088])
            with self.assertRaises(ValueError):
                manager.save(dict(name='Other', kind='openvpn', slot=3, ovpn='client\ndev tun\n'))

    def test_check_records_success_failure_and_stop_clears_result(self):
        profile = validate(dict(name='VPN', kind='vless', slot=2, link=LINK, probe_url='example.com'))
        runtime = Runtime(profile, Path('/tmp/test-vpn-not-created'))
        runtime.state = 'running_unverified'
        with patch('runtime.run', return_value=MagicMock(returncode=0, stdout='403')) as command:
            result = runtime.check_connection()
            self.assertTrue(result['reachable'])
            self.assertEqual(result['url'], 'https://example.com')
            self.assertIn('socks5h://127.0.0.1:1082', command.call_args.args)
        with patch('runtime.run', return_value=MagicMock(returncode=7, stdout='000')):
            self.assertFalse(runtime.check_connection()['reachable'])
        with patch('runtime.shutil.rmtree'):
            runtime.stop()
        self.assertIsNone(runtime.last_probe)

    def test_hidden_legacy_options_migrate_from_supervisor(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(Manager, 'port_available', return_value=True):
            root = Path(tmp)
            options = root / 'options.json'
            options.write_text('{}')
            manager = Manager(root / 'profiles')
            response = MagicMock()
            response.__enter__.return_value.read.return_value = json.dumps({'data': {'options': {'link': LINK, 'protocol': 'vless'}}})
            with patch.dict('os.environ', {'SUPERVISOR_TOKEN': 'test'}), patch('migration.urlopen', return_value=response):
                migrate(manager, options)
            self.assertEqual(len(manager.profiles), 1)
            self.assertEqual(next(iter(manager.profiles.values()))['link'], LINK)
            self.assertEqual(json.loads((manager.root / 'options-before-0.6.json').read_text())['link'], LINK)

    def test_vless_transports_keep_settings(self):
        ws = outbound(LINK+'?type=ws&security=tls&host=edge.example&path=%2Fws&alpn=h2,http%2F1.1')
        self.assertEqual(ws['streamSettings']['wsSettings'], {'headers': {'Host': 'edge.example'}, 'path': '/ws'})
        reality = outbound(LINK+'?security=reality&pbk=public&sid=ab&fp=chrome')
        self.assertEqual(reality['streamSettings']['realitySettings']['publicKey'], 'public')
        grpc = outbound(LINK+'?type=grpc&serviceName=vpn&mode=multi')
        self.assertEqual(grpc['streamSettings']['grpcSettings'], {'serviceName': 'vpn', 'multiMode': True})
        with self.assertRaises(ValueError):
            outbound(LINK+'?security=reality')


if __name__ == '__main__':
    unittest.main()
