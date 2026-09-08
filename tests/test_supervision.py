"""Exercise recovery decisions without a VPN, network access, or root privileges."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRELUDE = r'''
set -euo pipefail
source local_xray_socks/supervise.sh
bashio::log.warning() { echo "$*"; }
bashio::log.info() { echo "$*"; }
XRAY_PID=123
AWG_PID=456
PROTOCOL=vless
WATCHDOG_ENABLED=true
sleep() { :; }
kill() { return 0; }
'''


class SupervisionTests(unittest.TestCase):
    def run_shell(self, script):
        return subprocess.run(
            ["bash", "-c", PRELUDE + script], cwd=ROOT,
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout

    def test_three_failed_rounds(self):
        output = self.run_shell('proxy_healthy() { return 1; }; supervise_runtime')
        self.assertEqual(output.count('check failed'), 3)
        self.assertIn('(3/3)', output)

    def test_success_resets_failures(self):
        output = self.run_shell('''
round=0
proxy_healthy() { round=$((round + 1)); [ "$round" -eq 3 ]; }
supervise_runtime
echo "rounds=$round"
''')
        self.assertIn('connectivity recovered', output)
        self.assertEqual(output.count('(1/3)'), 2)
        self.assertIn('rounds=6', output)

    def test_dead_xray_even_with_checks_disabled(self):
        output = self.run_shell('''
WATCHDOG_ENABLED=false
kill() { return 1; }
supervise_runtime
''')
        self.assertIn('Xray process exited', output)

    def test_dead_awg_with_live_xray(self):
        output = self.run_shell('''
PROTOCOL=amneziawg
kill() { [ "$2" = "$XRAY_PID" ]; }
supervise_runtime
''')
        self.assertIn('AmneziaWG process exited', output)

    def test_probe_fallback_and_socks_dns(self):
        output = self.run_shell('''
SOCKS_PORT=1080
WATCHDOG_URLS=unused
split_csv() { printf '%s\\n' https://first.invalid https://second.invalid https://third.invalid; }
curl() {
  echo "$*"
  [[ "$*" == *"--noproxy  --proxy socks5h://127.0.0.1:1080"* ]] || exit 20
  [[ "$*" == *"--connect-timeout 5 --max-time 10"* ]] || exit 21
  [[ "$*" == *https://second.invalid ]]
}
proxy_healthy
''')
        self.assertIn('https://first.invalid', output)
        self.assertIn('https://second.invalid', output)
        self.assertNotIn('https://third.invalid', output)

    def test_cleanup_reaps_children(self):
        self.run_shell('''
unset -f kill sleep
sleep 60 &
XRAY_PID=$!
sleep 60 &
AWG_PID=$!
first=$XRAY_PID
second=$AWG_PID
cleanup_runtime
! kill -0 "$first" 2>/dev/null
! kill -0 "$second" 2>/dev/null
[ -z "$XRAY_PID$AWG_PID" ]
cleanup_runtime
''')


if __name__ == '__main__':
    unittest.main()
