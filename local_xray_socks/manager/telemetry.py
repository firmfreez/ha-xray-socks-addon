"""Read-only Linux counters. Missing metrics stay unavailable, never fake zero."""
from pathlib import Path
import time


class Traffic:
    def __init__(self):
        self.previous = None

    def sample(self, interface, root=Path('/sys/class/net'), now=None):
        now = time.monotonic() if now is None else now
        try:
            # Host veth RX comes from the profile, TX goes into the profile.
            received = int((root / interface / 'statistics/rx_bytes').read_text())
            sent = int((root / interface / 'statistics/tx_bytes').read_text())
        except (OSError, ValueError):
            self.previous = None
            return None
        rates = [None, None]
        if self.previous:
            stamp, rx, tx = self.previous
            if now > stamp and received >= rx and sent >= tx:
                rates = [(received-rx)/(now-stamp), (sent-tx)/(now-stamp)]
        self.previous = (now, received, sent)
        return dict(rx_bytes=received, tx_bytes=sent, rx_rate=rates[0], tx_rate=rates[1])


class Load:
    def __init__(self, root=Path('/sys/fs/cgroup')):
        self.root, self.previous = root, None

    def sample(self):
        result = dict(cpu_percent=None, memory_bytes=None, memory_limit=None)
        try:
            stats = dict(line.split() for line in (self.root / 'cpu.stat').read_text().splitlines())
            usage, now = int(stats['usage_usec']), time.monotonic()
            if self.previous:
                old, stamp = self.previous
                if now > stamp and usage >= old:
                    result['cpu_percent'] = round((usage-old)/(now-stamp)/10000, 1)
            self.previous = usage, now
        except (OSError, ValueError, KeyError):
            pass
        for name, key in [('memory.current', 'memory_bytes'), ('memory.max', 'memory_limit')]:
            try:
                result[key] = int((self.root / name).read_text())
            except (OSError, ValueError):
                pass
        return result
