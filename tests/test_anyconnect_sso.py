import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from anyconnect_sso import validate_input
from model import validate
from runtime import Runtime
from server import Manager


class SSOTests(unittest.TestCase):
    def profile(self, **values):
        return validate(dict(dict(name='Cisco SSO', kind='anyconnect', server='vpn.example',
                                  anyconnect_auth='sso'), **values))

    def test_saved_mode_and_credentials_are_optional(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(Manager, 'port_available', return_value=True):
            manager = Manager(Path(tmp))
            public = manager.save(self.profile())
            self.assertEqual(Manager(Path(tmp)).profiles[public['id']]['anyconnect_auth'], 'sso')
            self.assertNotIn('password', public)
        with self.assertRaises(ValueError):
            self.profile(anyconnect_auth='unknown')

    def test_sso_never_passes_saved_password_or_mfa(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = Runtime(self.profile(username='employee', password='saved-secret', mfa_form='main:password'), root)
            runtime.work = root / 'run'
            with patch('runtime.NETNS_ROOT', root / 'netns'), \
                 patch('runtime.endpoint_addresses', return_value=['192.0.2.1']), \
                 patch('runtime.run', return_value=MagicMock(stdout='1')), patch.object(runtime, 'spawn') as spawn:
                runtime.start()
            command = next(c.args[0] for c in spawn.call_args_list if '/app/anyconnect-start.sh' in c.args[0])
            self.assertNotIn('--passwd-on-stdin', command)
            self.assertNotIn('--user', command)
            self.assertNotIn('--form-entry', command)
            self.assertEqual((runtime.work / 'password').read_text(), '')
            self.assertTrue(any(x.startswith('ANYCONNECT_SSO_WORK=') for x in command))

    def test_session_expiry_replay_and_pending_input(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(Manager, 'port_available', return_value=True):
            manager = Manager(Path(tmp))
            p = manager.save(self.profile())
            runtime = Runtime(manager.profiles[p['id']], Path(tmp))
            runtime.work = Path(tmp)
            runtime.state = 'starting'
            manager.runtimes[p['id']] = runtime
            state = {'session': 'current', 'expires_at': time.time() + 600}
            (runtime.work / 'sso-state.json').write_text(json.dumps(state))
            with self.assertRaises(ValueError):
                manager.action(p['id'], 'sso-input', dict(type='text', text='private', session='old'))
            manager.action(p['id'], 'sso-input', dict(type='text', text='private', session='current'))
            path = runtime.work / 'sso-input.json'
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('private', str(manager.public(manager.profiles[p['id']])))
            with self.assertRaises(ValueError):
                manager.action(p['id'], 'sso-input', dict(type='key', key='Enter', session='current'))
            state['expires_at'] = time.time() - 1
            (runtime.work / 'sso-state.json').write_text(json.dumps(state))
            self.assertIsNone(manager.sso_state(runtime))
            with self.assertRaises(ValueError):
                manager.action(p['id'], 'sso-input', dict(type='key', key='Enter', session='current'))

    def test_network_files_readable_under_production_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = Runtime(self.profile(password='saved-secret'), root)
            runtime.work = root / 'run'
            old_umask = os.umask(0o077)
            try:
                with patch('runtime.NETNS_ROOT', root / 'netns'), \
                     patch('runtime.endpoint_addresses', return_value=['192.0.2.1']), \
                     patch('runtime.run', return_value=MagicMock(stdout='1')), patch.object(runtime, 'spawn'):
                    runtime.start()
            finally:
                os.umask(old_umask)
            for path in (runtime.work / 'transport-resolv.conf',
                         root / 'netns' / runtime.ns / 'hosts',
                         root / 'netns' / runtime.ns / 'resolv.conf'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o644, str(path))
            self.assertIn('192.0.2.1 vpn.example', (root / 'netns' / runtime.ns / 'hosts').read_text())
            self.assertEqual((runtime.work / 'password').stat().st_mode & 0o777, 0o600)

    def test_input_is_bounded_and_cannot_execute_browser_commands(self):
        for data in ({'type': 'navigate', 'url': 'file:///data'}, {'type': 'text', 'text': 'x' * 4097},
                     {'type': 'click', 'x': True, 'y': 0}, {'type': 'click', 'x': 1000, 'y': 0},
                     {'type': 'key', 'key': 'F12'}, {'type': 'scroll', 'delta': 701}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_input(data)


if __name__ == '__main__':
    unittest.main()
