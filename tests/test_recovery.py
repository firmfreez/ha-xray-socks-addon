"""Regressions for DNS outages, isolated recovery and cancellation races."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from model import validate
from runtime import Runtime, endpoint_addresses
from server import Manager


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime = Runtime(validate(dict(name='Test', kind='openvpn', slot=4,
            ovpn='client\nremote vpn.example 1194\n', probe_url='http://work.example')), self.root)
        self.runtime.work = self.root / 'run'
        p = patch('runtime.NETNS_ROOT', self.root / 'netns')
        p.start()
        self.addCleanup(p.stop)

    def test_corrupt_profile_does_not_prevent_loading_healthy_profile(self):
        with patch.object(Manager, 'port_available', return_value=True):
            manager = Manager(self.root)
            saved = manager.save(dict(name='Healthy', kind='openvpn', slot=1, ovpn='client\n'))
        broken = self.root / ('a' * 32)
        broken.mkdir()
        (broken / 'profile.json').write_text('{broken json')
        manager = Manager(self.root)
        self.assertEqual(list(manager.profiles), [saved['id']])
        self.assertTrue(manager.notice)
        self.assertEqual((broken / 'profile.json').read_text(), '{broken json')

    def test_dns_error_before_network_changes_and_readable_log(self):
        with patch('runtime.endpoint_addresses', side_effect=socket.gaierror(-3, 'Try again')), \
             patch('runtime.run') as run:
            self.runtime.start()
        run.assert_not_called()
        self.assertTrue(self.runtime.retryable)
        self.assertFalse(self.runtime.networked)
        self.assertFalse(self.runtime.work.exists())
        self.assertIn('vpn.example', '\n'.join(self.runtime.logs))
        self.assertIn('DNS', '\n'.join(self.runtime.logs))

    def test_dns_worker_has_timeout_and_numeric_endpoint_needs_no_dns(self):
        with patch('runtime.subprocess.run', side_effect=subprocess.TimeoutExpired('resolver', 12)) as run:
            self.assertEqual(endpoint_addresses('192.0.2.1'), ['192.0.2.1'])
            run.assert_not_called()
            with self.assertRaises(subprocess.TimeoutExpired):
                endpoint_addresses('vpn.example')
            self.assertEqual(run.call_args.kwargs['timeout'], 12)

    def test_retry_backoff_is_capped_and_stop_cancels_it(self):
        delays = []
        def wait(delay):
            delays.append(delay)
            if len(delays) == 9:
                self.runtime.cancelled.set()
                return True
            return False
        with patch('runtime.endpoint_addresses', side_effect=socket.gaierror(-3, 'Try again')), \
             patch('runtime.run') as run, patch.object(self.runtime.cancelled, 'wait', side_effect=wait):
            self.runtime.supervise()
        self.assertEqual(delays, [5,10,20,40,80,160,300,300,300])
        run.assert_not_called()
        self.runtime.stop()
        self.assertEqual(self.runtime.state, 'stopped')
        self.assertIsNone(self.runtime.retry_at)

    def test_dns_recovers_on_second_attempt(self):
        (self.root / 'assets').mkdir()
        attempted = []
        def started():
            attempted.append(True)
            self.runtime.state = 'running_unverified'
        def wait(delay):
            if delay == 2:
                self.runtime.cancelled.set()
                return True
            return False
        with patch('runtime.endpoint_addresses', side_effect=[socket.gaierror(-3, 'Try again'), ['192.0.2.1']]) as dns, \
             patch('runtime.run', return_value=MagicMock(stdout='1')), \
             patch.object(self.runtime, 'spawn'), patch.object(self.runtime, 'started', side_effect=started), \
             patch.object(self.runtime.cancelled, 'wait', side_effect=wait):
            self.runtime.supervise()
            self.runtime.stop()
        self.assertEqual(dns.call_count, 2)
        self.assertEqual(attempted, [True])

    def test_dead_process_retries_but_auth_failure_does_not(self):
        for auth_failed in (False, True):
            with self.subTest(auth_failed=auth_failed):
                runtime = self.runtime
                runtime.cancelled.clear()
                runtime.auth_failed.clear()
                waits = []
                def start():
                    runtime.state = 'running_unverified'
                    if auth_failed:
                        runtime.auth_failed.set()
                def wait(delay):
                    waits.append(delay)
                    if delay != 2:
                        runtime.cancelled.set()
                        return True
                    return False
                with patch.object(runtime, '_start', side_effect=start), \
                     patch.object(runtime, '_cleanup'), \
                     patch.object(runtime.cancelled, 'wait', side_effect=wait):
                    runtime.children = [MagicMock()]
                    runtime.supervise()
                self.assertEqual(waits, [2] if auth_failed else [2, 5])
                if auth_failed:
                    self.assertEqual(runtime.state, 'error')
        runtime.children = []

    def test_three_failed_checks_restart_only_corporate_profile(self):
        runtime = self.runtime
        checks = iter([False, False, True, False, False, False])
        rounds = []
        def start():
            runtime.state = 'running_unverified'
        def wait(delay):
            if delay != 2:
                runtime.cancelled.set()
                return True
            value = next(checks)
            rounds.append(value)
            runtime.last_probe = {'checked_at': len(rounds), 'reachable': value}
            return False
        with patch.object(runtime, '_start', side_effect=start), \
             patch.object(runtime, '_cleanup'), \
             patch.object(runtime.cancelled, 'wait', side_effect=wait):
            runtime.supervise()
        self.assertEqual(rounds, [False, False, True, False, False, False])

    def test_old_probe_cannot_overwrite_new_attempt(self):
        runtime = self.runtime
        old = runtime.stopping
        def probe(url):
            old.set()
            runtime.stopping = threading.Event()
            runtime.last_probe = {'reachable': True, 'checked_at': 999}
            return {'reachable': False}
        with patch.object(runtime, 'probe', side_effect=probe):
            runtime.check_connection(old)
        self.assertEqual(runtime.last_probe, {'reachable': True, 'checked_at': 999})

    def test_slow_gateway_does_not_block_other_profiles_or_panel(self):
        entered, release = threading.Event(), threading.Event()
        with patch.object(Manager, 'port_available', return_value=True):
            manager = Manager(self.root / 'profiles')
            first = manager.save(dict(name='CP', kind='checkpoint', server='vpn.example', slot=0))
            second = manager.save(dict(name='Other', kind='openvpn', slot=1, ovpn='client\n'))
        def info(*args):
            entered.set()
            release.wait(3)
            raise OSError('DNS unavailable')
        with patch('runtime.gateway_info', side_effect=info), \
             patch('runtime.shutil.rmtree'), patch('runtime.run'):
            manager.action(first['id'], 'start', {})
            self.assertTrue(entered.wait(1))
            runtime = manager.runtimes[first['id']]
            self.addCleanup(release.set)
            # Starting a second profile must acquire the same Manager lock immediately.
            with patch.object(Runtime, 'launch') as launch:
                manager.action(second['id'], 'start', {})
                launch.assert_called_once()
            self.assertEqual(manager.action(first['id'], 'details', {})['state'], 'starting')
            manager.action(first['id'], 'start', {})
            self.assertIs(manager.runtimes[first['id']], runtime)
            runtime.cancelled.set()
            release.set()
            runtime.stop()
            self.assertFalse(runtime.worker.is_alive())

    def test_stop_during_backoff_prevents_resurrection(self):
        with patch('runtime.endpoint_addresses', side_effect=socket.gaierror(-3, 'Try again')), \
             patch('runtime.run') as run:
            entered = threading.Event()
            real_wait = self.runtime.cancelled.wait
            def wait(delay):
                entered.set()
                return real_wait(delay)
            with patch.object(self.runtime.cancelled, 'wait', side_effect=wait):
                self.runtime.launch()
                self.assertTrue(entered.wait(2))
                self.runtime.stop()
            self.assertFalse(self.runtime.worker.is_alive())
            self.assertEqual(self.runtime.state, 'stopped')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
