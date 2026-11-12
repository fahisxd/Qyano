import subprocess
import unittest
from unittest.mock import patch

from qyano import vpn


class VPNTests(unittest.TestCase):
    def profile(self, name="lab"):
        return {"name": name, "ssh": {"target": "", "port": 22, "key": ""},
                "vpn": {"start": "wg-quick up lab", "stop": "wg-quick down lab"}}

    def test_start_uses_detached_profile_terminal(self):
        profile = self.profile()
        responses = [subprocess.CompletedProcess([], 1, "", ""),
                     subprocess.CompletedProcess([], 0, "", ""),
                     subprocess.CompletedProcess([], 0, "", "")]
        with patch.object(vpn.shutil, "which", return_value="/usr/bin/tmux"), \
             patch.object(vpn, "_tmux", side_effect=responses) as tmux, \
             patch.object(vpn.time, "sleep"):
            self.assertIn("qyano-vpn-lab", vpn.start(profile))
        self.assertEqual(tmux.call_args_list[1].args[:4],
                         (profile, "new-session", "-d", "-s"))
        self.assertEqual(tmux.call_args_list[1].args[4], "qyano-vpn-lab")
        self.assertIn("wg-quick up lab", tmux.call_args_list[1].args[5])
        self.assertNotEqual(vpn.session_name(profile), vpn.session_name(self.profile("other")))

    def test_disconnect_kills_terminal_and_runs_stop_command(self):
        profile = self.profile()
        success = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(vpn, "is_running", return_value=True), \
             patch.object(vpn, "_tmux", return_value=success) as tmux, \
             patch.object(vpn, "_run", return_value=success) as run:
            self.assertEqual(vpn.stop(profile), "VPN disconnected.")
        self.assertEqual(tmux.call_args.args[1:], ("kill-session", "-t", "=qyano-vpn-lab"))
        self.assertEqual(run.call_args.args[1], ["/bin/sh", "-lc", "wg-quick down lab"])


if __name__ == "__main__":
    unittest.main()
