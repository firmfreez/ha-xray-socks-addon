from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from vpn_dns import publish, pushed_servers, update, read_state
from dns_forward import upstream_servers


class VPNDNSTests(unittest.TestCase):
    def test_openvpn_27_dns_environment(self):
        self.assertEqual(pushed_servers({'dns_server_1_address_1': '172.31.0.200',
                                         'dns_server_1_address_2': '10.0.0.53',
                                         'dns_server_2_address_1': '1.1.1.1',
                                         'dns_server_2_transport': 'DoH',
                                         'dns_server_3_address_1': '10.0.0.54',
                                         'dns_server_3_port_1': '5353'}),
                         ['172.31.0.200', '10.0.0.53'])

    def test_only_ipv4_dns_options_are_accepted(self):
        env = {'foreign_option_1': 'dhcp-option DNS 172.31.0.200',
               'foreign_option_2': 'dhcp-option DOMAIN corp.example',
               'foreign_option_3': 'dhcp-option DNS 127.0.0.1',
               'foreign_option_4': 'dhcp-option DNS ::1',
               'foreign_option_5': 'dhcp-option DNS 172.31.0.200',
               'foreign_option_6': 'dhcp-option DNS bad;command',
               'password': 'secret'}
        self.assertEqual(pushed_servers(env), ['172.31.0.200'])

    def test_dns_arrival_reconnect_and_disconnect_without_restarting_relay(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'dns-manual').write_text('')
            publish(work, [], 'waiting')
            resolver = work / 'resolv.conf'
            inode = resolver.stat().st_ino
            relay_arg = '@' + str(work / 'dns-state.json')
            self.assertEqual(upstream_servers(relay_arg), [])
            for address in ('172.31.0.200', '10.2.0.53'):
                update(work, {'script_type': 'route-up', 'foreign_option_1': 'dhcp-option DNS '+address})
                self.assertEqual(upstream_servers(relay_arg), [address])
                self.assertIn('nameserver '+address, resolver.read_text())
                self.assertEqual(resolver.stat().st_ino, inode)
            update(work, {'script_type': 'down'})
            self.assertEqual(upstream_servers(relay_arg), [])
            self.assertNotIn('10.2.0.53', resolver.read_text())
            update(work, {'script_type': 'route-up'})
            self.assertEqual(read_state(work / 'dns-state.json')['source'], 'missing')

    def test_manual_dns_overrides_push_and_invalid_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'dns-manual').write_text('10.0.0.53')
            update(work, {'script_type': 'route-up', 'foreign_option_1': 'dhcp-option DNS 172.31.0.200'})
            state = work / 'dns-state.json'
            self.assertEqual(read_state(state), {'servers': ['10.0.0.53'], 'source': 'manual'})
            state.write_text('broken')
            self.assertEqual(upstream_servers('@'+str(state)), [])
            state.unlink()
            self.assertEqual(upstream_servers('@'+str(state)), [])


if __name__ == '__main__':
    unittest.main()
