import base64
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from checkpoint import parse_methods
from model import validate
from runtime import Runtime
from server import Manager
from vpn_dns import resolver_state
from dns_forward import upstream_servers

INFO = ' [Personal Certificate]: vpn_Personal_Certificate (certificate)\n'


class CheckPointTests(unittest.TestCase):
    def test_server_choices_are_parsed_and_mfa_is_not_certificate_only(self):
        choices = parse_methods(INFO+' [MFA]: vpn_MFA (password, sms)\n')
        self.assertEqual(choices[0]['id'], 'vpn_Personal_Certificate')
        self.assertTrue(choices[0]['certificate'])
        self.assertFalse(choices[1]['certificate'])
        self.assertEqual(parse_methods('TLS error'), [])

    def test_certificate_validation_and_https_server(self):
        p = dict(name='Work', kind='checkpoint', auth_mode='certificate', server='https://vpn.example/')
        with self.assertRaisesRegex(ValueError, 'p12'):
            validate(p)
        self.assertEqual(validate(dict(p, certificate='test.p12'))['server'], 'vpn.example')
        with self.assertRaises(ValueError):
            validate(dict(p, certificate='test.cer'))
        with self.assertRaises(ValueError):
            validate(dict(p, certificate='test.p12', server='https://user:secret@vpn.example/path'))

    def test_auto_method_and_certificate_password_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(Manager, 'port_available', return_value=True):
            manager = Manager(Path(tmp))
            p = manager.save(dict(name='Work', kind='checkpoint', auth_mode='certificate',
                                  server='vpn.example.com', certificate='personal.p12', cert_password='secret',
                                  uploads={'personal.p12': base64.b64encode(b'test-only').decode()}))
            self.assertNotIn('cert_password', p)
            self.assertTrue(p['has_secrets']['cert_password'])
            manager.save(dict(p, cert_password=''))
            self.assertEqual(manager.profiles[p['id']]['cert_password'], 'secret')
            with patch('server.gateway_info', return_value={'text': INFO, 'methods': parse_methods(INFO)}), \
                 patch('server.Runtime') as cls:
                manager.action(p['id'], 'start', {})
                active = cls.call_args.args[0]
                self.assertEqual(active['login_type'], 'vpn_Personal_Certificate')
                self.assertEqual(manager.profiles[p['id']]['login_type'], '')

    def test_multiple_certificate_choices_require_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = Manager(Path(tmp))
            p = validate(dict(name='Work', kind='checkpoint', server='vpn.example', certificate='test.p12'))
            p['id'] = '1'*32
            manager.profiles[p['id']] = p
            methods = parse_methods(INFO+' [Other]: vpn_Other (certificate)\n')
            with patch('server.gateway_info', return_value={'methods': methods}):
                with self.assertRaisesRegex(ValueError, 'выберите'):
                    manager.action(p['id'], 'start', {})

    def test_certificate_runtime_and_private_auto_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'assets').mkdir()
            p = validate(dict(name='Work', kind='checkpoint', server='vpn.example',
                              auth_mode='certificate', certificate='personal.p12', cert_password='p12-secret',
                              username='unused', password='unused', login_type='vpn_Personal_Certificate'))
            runtime = Runtime(p, directory)
            runtime.work = directory / 'run'
            with patch('runtime.NETNS_ROOT', directory / 'netns'), patch('runtime.run', return_value=MagicMock(stdout='1')), \
                 patch('runtime.socket.getaddrinfo', return_value=[(None,None,None,None,('192.0.2.1',0))]), \
                 patch.object(runtime, 'spawn') as spawn, patch.object(runtime, 'started'):
                runtime.start()
            config = (runtime.work / 'snx.conf').read_text()
            self.assertIn('cert-type=pkcs12\n', config)
            self.assertIn('cert-password=p12-secret\n', config)
            self.assertNotIn('user-name=', config)
            self.assertNotIn('\npassword=', config)
            self.assertIn('no-dns=false', config)
            self.assertNotIn('ignore-server-cert', config)
            self.assertTrue(any('checkpoint' in call.args[0] and 'unshare' in call.args[0] for call in spawn.call_args_list))
            resolver = runtime.work / 'resolv.conf'
            self.assertEqual(runtime.dns_status()['servers'], [])
            resolver.write_text('nameserver 10.20.0.53\nnameserver 127.0.0.1\n')
            self.assertEqual(resolver_state(resolver)['servers'], ['10.20.0.53'])
            self.assertEqual(upstream_servers('resolv:'+str(resolver)), ['10.20.0.53'])


if __name__ == '__main__':
    unittest.main()
