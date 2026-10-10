import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/macos_fixture_cleanup.py"
SPEC = importlib.util.spec_from_file_location("macos_fixture_cleanup_test", SCRIPT)
CLEANUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEANUP)


@unittest.skipUnless(sys.platform == "darwin", "Darwin audit identities and process events are required")
class SeparateSessionCleanupTests(unittest.TestCase):
    def test_descendants_in_separate_sessions_exit_and_parent_reaps_its_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.py"
            target.write_text("import signal, threading\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                              "print('READY', flush=True)\nthreading.Event().wait()\n")
            monitor = root / "monitor.py"
            monitor.write_text("import pathlib, signal, subprocess, sys\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "child = subprocess.Popen([sys.executable, sys.argv[1]], stdout=subprocess.PIPE, start_new_session=True)\n"
                "assert child.stdout.readline() == b'READY\\n'\n"
                "print('READY', flush=True)\n"
                "child.wait()\nchild.stdout.close()\npathlib.Path(sys.argv[2]).write_text('REAPED')\n")
            authority = root / "authority.py"
            authority.write_text("import json, signal, subprocess, sys, threading\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "monitor = subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2], sys.argv[3]], "
                "stdout=subprocess.PIPE, start_new_session=True)\n"
                "other = subprocess.Popen([sys.executable, sys.argv[2]], stdout=subprocess.PIPE, start_new_session=True)\n"
                "assert monitor.stdout.readline() == b'READY\\n'\n"
                "assert other.stdout.readline() == b'READY\\n'\n"
                "print(json.dumps([monitor.pid, other.pid]), flush=True)\n"
                "monitor.wait()\nother.wait()\nthreading.Event().wait()\n")
            reaped = root / "reaped"
            api = CLEANUP._Darwin()
            process = subprocess.Popen([sys.executable, str(authority), str(monitor), str(target), str(reaped)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            known = []
            try:
                readable, _, _ = select.select([process.stdout], [], [], 10)
                self.assertTrue(readable, "Every helper must start before cleanup")
                direct = json.loads(process.stdout.readline())
                self.assertEqual(len(direct), 2)
                # Preserve safe emergency cleanup even if this regression fails against an older implementation.
                for pid in direct:
                    known.append(api.token(pid))
                    known.extend(api.token(child) for child in api.children(pid))
                self.assertEqual(len(known), 3)
                result = CLEANUP.retire_owned_tree(process)
                self.assertEqual(result, {"trackedDescendants": 3, "observedExits": 3})
                self.assertEqual(process.returncode, -signal.SIGKILL)
                self.assertEqual(reaped.read_text(), "REAPED")
                for token in known:
                    self.assertFalse(api.send(token, signal.SIGCONT), "The recorded helper incarnation must have retired")
                with self.assertRaises(ChildProcessError):
                    os.waitpid(process.pid, os.WNOHANG)
            finally:
                for token in known:
                    api.send(token, signal.SIGKILL)
                if process.poll() is None:
                    process.send_signal(signal.SIGCONT)
                    process.kill()
                    process.wait(timeout=10)
                process.stdout.close()
                process.stderr.close()

    def test_stale_audit_incarnation_cannot_signal_the_live_child(self):
        api = CLEANUP._Darwin()
        process = subprocess.Popen([sys.executable, "-c", "import threading; threading.Event().wait()"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            original = api.token(process.pid)
            changed = api.Token.from_buffer_copy(bytes(original))
            changed[7] ^= 0x40000000
            self.assertFalse(api.send(changed, signal.SIGKILL))
            self.assertIsNone(process.poll())
        finally:
            process.kill()
            process.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
