"""Public IP fallback and persistent display order regressions."""
from pathlib import Path
import json
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from model import validate
from runtime import Runtime
from server import Manager


class IPTests(unittest.TestCase):
    def personal(self):
        return Runtime(validate(dict(name='Personal', kind='vless', slot=1,
            link='vless://12345678-1234-4234-9234-123456789abc@vpn.example:443')), Path('/tmp/unused'))

    def test_cloudflare_trace_uses_profile_socks(self):
        with patch('runtime.run', return_value=MagicMock(returncode=0, stdout='fl=abc\nip=8.8.4.4\nloc=US\n')) as run:
            self.assertEqual(self.personal().discover_ip(threading.Event()), '8.8.4.4')
        self.assertIn('socks5h://127.0.0.1:1081', run.call_args.args)
        self.assertIn('--noproxy', run.call_args.args)
        self.assertEqual(run.call_count, 1)

    def test_tls_failure_and_invalid_reply_try_next_source(self):
        with patch('runtime.run', side_effect=[MagicMock(returncode=35, stdout=''),
                MagicMock(returncode=0, stdout='<html>blocked</html>'),
                MagicMock(returncode=0, stdout='8.8.4.4\n')]) as run:
            self.assertEqual(self.personal().discover_ip(threading.Event()), '8.8.4.4')
        self.assertEqual(run.call_count, 3)
        self.assertTrue(all('socks5h://127.0.0.1:1081' in call.args for call in run.call_args_list))

    def test_private_ip_and_cancelled_lookup_are_not_published(self):
        with patch('runtime.run', return_value=MagicMock(returncode=0, stdout='127.0.0.1')) as run:
            runtime = self.personal()
            self.assertIsNone(runtime.discover_ip(threading.Event()))
            attempt = threading.Event()
            attempt.set()
            run.reset_mock()
            self.assertIsNone(runtime.discover_ip(attempt))
            run.assert_not_called()

    def test_corporate_ip_is_tunnel_address_not_veth_or_public_exit(self):
        runtime = Runtime(validate(dict(name='Work', kind='checkpoint', slot=4,
            server='vpn.example', login_type='vpn_Test')), Path('/tmp/unused'))
        interfaces = [{'ifname': 'eth0', 'addr_info': [{'family': 'inet', 'scope': 'global', 'local': '10.253.4.2'}]},
                      {'ifname': 'snx-tun', 'addr_info': [{'family': 'inet', 'scope': 'global', 'local': '10.9.16.96'}]}]
        with patch('runtime.run', return_value=MagicMock(stdout=json.dumps(interfaces))) as run:
            self.assertEqual(runtime.discover_ip(threading.Event()), '10.9.16.96')
            self.assertEqual(run.call_args.args[:3], ('ip', '-n', 'wvpn4'))


class OrderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manager = Manager(self.root)
        with patch.object(Manager, 'port_available', return_value=True):
            self.ids = [self.manager.save(dict(name=f'Work {i}', kind='openvpn', slot=i, ovpn='client\n'))['id'] for i in range(3)]

    def test_order_persists_without_touching_profiles_or_processes(self):
        original = {p: (self.root / p / 'profile.json').read_bytes() for p in self.ids}
        runtime = MagicMock()
        self.manager.runtimes[self.ids[0]] = runtime
        order = self.ids[::-1]
        self.manager.reorder(order)
        self.assertEqual(list(self.manager.profiles), order)
        self.assertEqual(list(Manager(self.root).profiles), order)
        runtime.stop.assert_not_called()
        runtime.start.assert_not_called()
        for p in self.ids:
            self.assertEqual((self.root / p / 'profile.json').read_bytes(), original[p])

    def test_stale_and_duplicate_lists_are_rejected_without_changing_order(self):
        for order in [None, self.ids[:2], self.ids + ['bad'], [self.ids[0]] * 3, [[], *self.ids[:2]]]:
            with self.subTest(order=order), self.assertRaises(ValueError):
                self.manager.reorder(order)
        self.assertEqual(list(self.manager.profiles), self.ids)
        self.assertFalse((self.root / 'order.json').exists())

    def test_removed_ids_and_new_profiles_do_not_break_saved_order(self):
        self.manager.reorder(self.ids[::-1])
        self.manager.action(self.ids[1], 'delete', {})
        with patch.object(Manager, 'port_available', return_value=True):
            added = self.manager.save(dict(name='New', kind='openvpn', slot=1, ovpn='client\n'))['id']
        self.assertEqual(list(Manager(self.root).profiles), [self.ids[2], self.ids[0], added])


if __name__ == '__main__':
    unittest.main()
