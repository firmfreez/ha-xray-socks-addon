import base64
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from model import ovpn_config, validate
from server import Manager
from dns_forward import forward, read_exact, minimal_reply


class ProfileTests(unittest.TestCase):
    def setUp(self):
        ports = patch.object(Manager, 'port_available', return_value=True)
        ports.start()
        self.addCleanup(ports.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = Manager(Path(self.tmp.name))
        self.profile = dict(name='Работа', slot=1, kind='openvpn',
                            ovpn='client\ndev tun\nremote vpn.example 1194\n',
                            password='secret', dns='10.1.2.3')

    def tearDown(self):
        self.tmp.cleanup()

    def test_secrets_preserved_but_not_returned(self):
        p = self.manager.save(self.profile)
        self.assertNotIn('password', p)
        self.assertNotIn('ovpn', p)
        self.assertTrue(p['has_secrets']['password'])
        p['name'] = 'Renamed'
        self.manager.save(p)
        self.assertEqual(self.manager.profiles[p['id']]['password'], 'secret')
        self.assertEqual(self.manager.profiles[p['id']]['ovpn'], self.profile['ovpn'])
        self.manager.save(dict(p, clear_secrets=['password']))
        self.assertEqual(self.manager.profiles[p['id']]['password'], '')

    def test_unique_slots_and_reload(self):
        p = self.manager.save(self.profile)
        with self.assertRaises(ValueError):
            self.manager.save(self.profile)
        loaded = Manager(Path(self.tmp.name))
        self.assertEqual(loaded.profiles[p['id']]['name'], 'Работа')
        path = Path(self.tmp.name) / p['id'] / 'profile.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_import_inline_and_external_certificates(self):
        text = 'client\n<key>\nFAKE KEY DATA\n</key>\nca company.pem\nauth-user-pass old-secret.txt\n'
        result = ovpn_config(text, {'company.pem'})
        self.assertIn('/run/work-vpn/assets/company.pem', result)
        self.assertIn('/run/work-vpn/auth.txt', result)
        self.assertNotIn('old-secret.txt', result)
        self.assertIn('FAKE KEY DATA', result)

    def test_reject_executable_directives_and_path_escape(self):
        for line in ('up /tmp/x', 'plugin evil.so', 'config another.ovpn', 'management 0.0.0.0 9999',
                     'log /data/options.json', 'script-security 2', 'ca ../../secret',
                     'ca /etc/passwd', '<connection>\nremote x\n</connection>'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                ovpn_config(line, set())

    def test_upload_validation(self):
        encoded = base64.b64encode(b'certificate').decode()
        p = self.manager.save(dict(self.profile, ovpn='client\nca company.pem', uploads={'company.pem': encoded}))
        self.assertEqual(p['files'], ['company.pem'])
        for name in ('../oops', '/etc/passwd', 'a\nb', '.hidden'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.manager.save(dict(self.profile, slot=2, uploads={name: encoded}))

    def test_checkpoint_and_dns_validation(self):
        p = dict(name='CP', kind='checkpoint', slot=2, server='vpn.example', dns='10.1.2.3')
        self.assertEqual(validate(p)['tunnel'], 'ssl')
        for changes in ({'dns': 'not-an-ip'}, {'password': 'x\nignore-server-cert=true'},
                        {'server': '--help'}, {'slot': 9}, {'certificate': '../key'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate(dict(p, **changes))

    def test_missing_files_and_unclosed_inline(self):
        for text in ('ca missing.pem', '<key>\nnot closed'):
            with self.assertRaises(ValueError):
                ovpn_config(text, set())

    def test_delete_removes_credentials(self):
        p = self.manager.save(self.profile)
        self.manager.action(p['id'], 'delete', {})
        self.assertFalse((Path(self.tmp.name) / p['id']).exists())
        self.assertEqual(Manager(Path(self.tmp.name)).profiles, {})


class DNSTests(unittest.TestCase):
    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x04work\x00\x00\x01\x00\x01'

    def test_failure_never_uses_public_dns(self):
        with patch('dns_forward.socket.create_connection', side_effect=OSError) as connect:
            reply = forward(self.query, ['10.1.1.1', '10.2.2.2'])
        self.assertEqual(reply[:2], self.query[:2])
        self.assertEqual(reply[3] & 15, 2)
        self.assertEqual([x.args[0] for x in connect.call_args_list], [('10.1.1.1', 53), ('10.2.2.2', 53)])

    def test_dns_reply_and_fragmented_tcp(self):
        response = self.query[:2] + b'\x81\x80' + self.query[4:]
        sock = MagicMock()
        sock.recv.side_effect = [b'\x00', bytes([len(response)]), response[:8], response[8:]]
        with patch('dns_forward.socket.create_connection') as connect:
            connect.return_value.__enter__.return_value = sock
            self.assertEqual(forward(self.query, ['10.1.1.1']), response)

    def test_bad_query_or_eof(self):
        with self.assertRaises(ValueError):
            forward(b'bad', [])
        sock = MagicMock()
        sock.recv.return_value = b''
        with self.assertRaises(OSError):
            read_exact(sock, 2)

    def test_truncated_reply_keeps_question_for_tcp_retry(self):
        answer = minimal_reply(self.query, truncated=True)
        self.assertTrue(answer[2] & 2)
        self.assertEqual(answer[4:6], b'\x00\x01')
        self.assertEqual(answer[12:], self.query[12:])


if __name__ == '__main__':
    unittest.main()
