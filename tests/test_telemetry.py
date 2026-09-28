from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'local_xray_socks' / 'manager'))
from telemetry import Traffic, Load


class TelemetryTests(unittest.TestCase):
    def test_rates_reset_and_missing_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stats = root / 'veth' / 'statistics'
            stats.mkdir(parents=True)
            def counters(rx, tx):
                (stats / 'rx_bytes').write_text(str(rx))
                (stats / 'tx_bytes').write_text(str(tx))
            meter = Traffic()
            counters(100, 200)
            self.assertIsNone(meter.sample('veth', root, 1)['rx_rate'])
            counters(300, 500)
            result = meter.sample('veth', root, 3)
            self.assertEqual((result['rx_rate'], result['tx_rate']), (100, 150))
            counters(1, 2)
            self.assertIsNone(meter.sample('veth', root, 4)['rx_rate'])
            self.assertIsNone(meter.sample('missing', root, 5))

    def test_container_cpu_memory_and_unlimited_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'cpu.stat').write_text('usage_usec 1000000\n')
            (root / 'memory.current').write_text('12345')
            (root / 'memory.max').write_text('max')
            meter = Load(root)
            with patch('telemetry.time.monotonic', side_effect=[1, 3]):
                self.assertIsNone(meter.sample()['cpu_percent'])
                (root / 'cpu.stat').write_text('usage_usec 2000000\n')
                result = meter.sample()
            self.assertEqual(result['cpu_percent'], 50)
            self.assertEqual(result['memory_bytes'], 12345)
            self.assertIsNone(result['memory_limit'])
            self.assertIsNone(Load(root / 'absent').sample()['memory_bytes'])
