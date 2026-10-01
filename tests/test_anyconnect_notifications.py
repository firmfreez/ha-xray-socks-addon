"""Recovery policies, notification API and AnyConnect isolation without credentials."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
import ha_notify
from anyconnect_hook import update
from model import validate
from runtime import Runtime
from server import Manager


def profile(**changes):
    return validate(dict(dict(name='Cisco', kind='anyconnect', server='vpn.example/group',
                              username='employee', password='secret'), **changes))


class AnyConnectTests(unittest.TestCase):
    def test_validation_and_round_trip(self):
        self.assertEqual(profile()['server'], 'https://vpn.example/group')
        for changes in ({'server': 'http://vpn.example'}, {'server': 'https://user:pass@vpn.example'},
                        {'server': 'https://vpn.example:wrong'}, {'mfa_form': 'main:field\nup=x'},
                        {'reconnect_attempts': 0}, {'reconnect_attempts': True},
                        {'notify_targets': ['../bad']}, {'notify_disconnect': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                profile(**changes)
        with tempfile.TemporaryDirectory() as tmp, patch.object(Manager, 'port_available', return_value=True):
            manager = Manager(Path(tmp))
            p = manager.save(profile(notify_disconnect=True, notify_targets=['mobile_app_phone'],
                reconnect_enabled=False, reconnect_attempts=3, mfa_form='main:secondary_password'))
            self.assertNotIn('password', p)
            loaded = Manager(Path(tmp)).profiles[p['id']]
            self.assertFalse(loaded['reconnect_enabled'])
            self.assertEqual(loaded['reconnect_attempts'], 3)
            self.assertEqual(loaded['notify_targets'], ['mobile_app_phone'])

    def test_spawn_password_not_in_argv_and_tunnel_is_not_ready_at_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'assets').mkdir()
            r = Runtime(profile(mfa_form='main:secondary_password'), root)
            r.work = root / 'run'
            with patch('runtime.NETNS_ROOT', root / 'netns'), \
                 patch('runtime.endpoint_addresses', return_value=['192.0.2.1']), \
                 patch('runtime.run', return_value=MagicMock(stdout='1')), \
                 patch.object(r, 'spawn') as spawn:
                r.start()
                commands = [c.args[0] for c in spawn.call_args_list]
                command = next(c for c in commands if '/app/anyconnect-start.sh' in c)
                self.assertIn('main:secondary_password=push', command)
                self.assertNotIn('secret', ' '.join(command))
                self.assertEqual(r.state, 'starting')
                self.assertEqual((r.work / 'password').stat().st_mode & 0o777, 0o600)
                self.assertEqual((r.work / 'password').read_text(), 'secret\n')
                self.assertIn('10.253.0.1', (r.work / 'transport-resolv.conf').read_text())
                self.assertNotEqual((r.work / 'resolv.conf').read_text(), (r.work / 'transport-resolv.conf').read_text())

    def test_dns_hook_preserves_inode_manual_override_and_disconnect(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'dns-manual').write_text('')
            update(work, {'reason': 'connect', 'INTERNAL_IP4_DNS': '10.1.2.3 10.1.2.4'})
            inode = (work / 'resolv.conf').stat().st_ino
            self.assertEqual(json.loads((work / 'dns-state.json').read_text())['source'], 'anyconnect')
            self.assertEqual((work / 'tunnel-state').read_text(), 'connected')
            (work / 'dns-manual').write_text('10.5.0.53')
            update(work, {'reason': 'reconnect', 'INTERNAL_IP4_DNS': '10.1.2.3'})
            self.assertIn('10.5.0.53', (work / 'resolv.conf').read_text())
            self.assertEqual((work / 'resolv.conf').stat().st_ino, inode)
            update(work, {'reason': 'disconnect'})
            self.assertEqual((work / 'tunnel-state').read_text(), 'disconnected')
            self.assertEqual(json.loads((work / 'dns-state.json').read_text())['servers'], [])

    def test_child_has_no_supervisor_token(self):
        r = Runtime(profile(), Path('/unused'))
        with patch.dict('os.environ', {'SUPERVISOR_TOKEN': 'bearer-secret'}), \
             patch('runtime.subprocess.Popen') as popen:
            popen.return_value.stdout = iter([])
            r.spawn(['example'])
            popen.return_value.log_reader.join(1)
            self.assertNotIn('SUPERVISOR_TOKEN', popen.call_args.kwargs['env'])

    def test_extra_input_is_terminal_and_does_not_retry(self):
        for message in ('User input required in non-interactive mode', 'Failed to complete authentication'):
            with self.subTest(message=message):
                r = Runtime(profile(), Path('/unused'))
                with patch('runtime.subprocess.Popen') as popen:
                    popen.return_value.stdout = iter([message + '\n'])
                    r.spawn(['openconnect'])
                    popen.return_value.log_reader.join(1)
                self.assertTrue(r.auth_failed.is_set())
                with patch.object(r, '_start', side_effect=lambda: setattr(r, 'state', 'running_unverified')), \
                     patch.object(r, '_cleanup'), patch.object(r.cancelled, 'wait', return_value=False) as wait:
                    r.supervise()
                self.assertEqual(r.state, 'error')
                self.assertEqual(wait.call_args_list, [unittest.mock.call(2)])

    def test_default_mfa_only_answers_secondary_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            r = Runtime(profile(), root)
            r.work = root / 'run'
            with patch('runtime.NETNS_ROOT', root / 'netns'), \
                 patch('runtime.endpoint_addresses', return_value=['192.0.2.1']), \
                 patch('runtime.run', return_value=MagicMock(stdout='1')), patch.object(r, 'spawn') as spawn:
                r.start()
            commands = [c.args[0] for c in spawn.call_args_list]
            command = next(c for c in commands if '/app/anyconnect-start.sh' in c)
            self.assertIn('challenge:password=push', command)
            self.assertIn('main:secondary_password=push', command)
            self.assertFalse(any(arg.startswith('main:password=') for arg in command))
            self.assertNotIn('secret', ' '.join(command))


class PolicyTests(unittest.TestCase):
    def runtime(self, **changes):
        return Runtime(validate(dict(name='VPN', kind='openvpn', ovpn='client\n', **changes)), Path('/unused'))

    def failed_starts(self, r):
        def start():
            r.state = 'error'
        def cleanup():
            r.state = 'stopped'
        with patch.object(r, '_start', side_effect=start) as starts, \
             patch.object(r, '_cleanup', side_effect=cleanup), \
             patch.object(r.cancelled, 'wait', return_value=False):
            r.supervise()
        return starts.call_count

    def test_disabled_retry_and_exact_limit(self):
        self.assertEqual(self.failed_starts(self.runtime(reconnect_enabled=False)), 1)
        r = self.runtime(reconnect_attempts=3)
        self.assertEqual(self.failed_starts(r), 4)  # Initial start + three retries.
        self.assertEqual(r.reconnect_count, 3)
        self.assertEqual(r.state, 'error')

    def test_single_notification_per_outage(self):
        r = self.runtime(reconnect_attempts=3, notify_disconnect=True, notify_targets=['mobile_app_phone'])
        with patch('runtime.threading.Thread') as thread:
            self.assertEqual(self.failed_starts(r), 4)
            thread.assert_called_once()

    def test_success_resets_limit_and_notification_episode(self):
        r = self.runtime(reconnect_attempts=1)
        r.reconnect_count = 1
        r.outage_notified = True
        def start():
            r.state = 'running_unverified'
            r.last_probe = {'reachable': True, 'checked_at': 1}
        calls = 0
        def wait(delay):
            nonlocal calls
            calls += 1
            if calls == 2:
                r.cancelled.set()
                return True
            return False
        with patch.object(r, '_start', side_effect=start), patch.object(r, '_cleanup'), \
             patch.object(r.cancelled, 'wait', side_effect=wait):
            r.supervise()
        self.assertEqual(r.reconnect_count, 0)
        self.assertFalse(r.outage_notified)

    def test_cancelled_start_does_not_notify_or_retry(self):
        r = self.runtime(notify_disconnect=True, notify_targets=['mobile_app_phone'])
        r.cancelled.set()
        with patch.object(r, '_start') as start, patch('runtime.threading.Thread') as thread:
            r.supervise()
            start.assert_not_called()
            thread.assert_not_called()


class NotificationTests(unittest.TestCase):
    def test_only_mobile_app_services_discovered(self):
        with patch('ha_notify.request', return_value=[{'domain': 'notify', 'services': {
                'mobile_app_phone': {'name': 'Phone'}, 'persistent_notification': {}, '../bad': {}}},
                {'domain': 'light', 'services': {'mobile_app_fake': {}}}]):
            self.assertEqual(ha_notify.phones(), [{'id': 'mobile_app_phone', 'name': 'Phone'}])

    def test_payload_has_name_but_no_credentials_and_delivery_continues(self):
        p = profile(notify_disconnect=True, notify_targets=['mobile_app_one', 'mobile_app_two'])
        with patch('ha_notify.request', side_effect=[OSError(), []]) as request:
            with self.assertRaises(OSError):
                ha_notify.disconnected(p, 'Процесс VPN завершился.')
            self.assertEqual(request.call_count, 2)
            payload = request.call_args.args[1]
            self.assertIn('Cisco', payload['message'])
            self.assertNotIn('secret', json.dumps(payload))

    def test_supervisor_proxy_auth_and_timeout(self):
        with patch.dict('os.environ', {'SUPERVISOR_TOKEN': 'test'}), patch('ha_notify.urlopen') as open_url:
            open_url.return_value.__enter__.return_value.read.return_value = b'[]'
            self.assertEqual(ha_notify.request('services'), [])
            request = open_url.call_args.args[0]
            self.assertEqual(request.full_url, 'http://supervisor/core/api/services')
            self.assertEqual(request.get_header('Authorization'), 'Bearer test')
            self.assertEqual(open_url.call_args.kwargs['timeout'], 10)


if __name__ == '__main__':
    unittest.main()
