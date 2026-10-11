import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-macos-presence-xpc-experiment.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("presence_xpc_runner", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class DiagnosticRetentionTests(unittest.TestCase):
    def check_failure(self, outcome, message):
        source = []

        def run(_arguments, _environment, output):
            source.append(Path(output.name))
            output.write("partial fixture diagnostic\n")
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            with patch.object(sys, "argv", [str(SCRIPT), "--evidence", str(evidence)]), \
                    patch.object(RUNNER.platform, "system", return_value="Darwin"), \
                    patch.object(RUNNER.platform, "machine", return_value="arm64"), \
                    patch.object(RUNNER.platform, "mac_ver", return_value=("26.0", (), "")), \
                    patch.object(RUNNER, "run_fixture", side_effect=run):
                with self.assertRaises(SystemExit) as raised:
                    RUNNER.main()
            self.assertIn(message, str(raised.exception))
            retained = Path(str(raised.exception).split("Diagnostics: ", 1)[1])
            try:
                self.assertTrue(retained.read_text().startswith("partial fixture diagnostic\n"))
                self.assertFalse(source[0].parent.exists())
                self.assertFalse(evidence.exists())
            finally:
                retained.unlink(missing_ok=True)

    def test_timeout_retains_partial_log_after_fixture_directory_removal(self):
        self.check_failure(subprocess.TimeoutExpired(["swift", "test"], 300), "timed out")

    def test_failed_or_skipped_fixture_retains_log_without_success_evidence(self):
        for code in [0, 1]:
            with self.subTest(code=code):
                self.check_failure(code, "failed or lacked a supported GUI session")

    def test_interruption_retains_partial_log(self):
        self.check_failure(KeyboardInterrupt(), "was interrupted")

    def test_cleanup_failure_also_retains_partial_log(self):
        self.check_failure(RuntimeError("owned fixture cleanup failed"), "failed to run or clean up")


@unittest.skipUnless(sys.platform == "darwin", "Native audit-token cleanup requires Darwin")
class OwnedTimeoutTests(unittest.TestCase):
    def test_timeout_retires_and_reaps_the_owned_fixture(self):
        real_popen = subprocess.Popen
        children = []

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "fixture.log"

            def factory(_arguments, **kwargs):
                child = real_popen([sys.executable, "-c", "import signal, threading; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('partial diagnostic', flush=True); threading.Event().wait()"], **kwargs)
                children.append(child)
                deadline = time.monotonic() + 10
                while log.read_text() != "partial diagnostic\n":
                    if child.poll() is not None or time.monotonic() >= deadline:
                        self.fail("Fixture did not reach its timeout barrier")
                    time.sleep(0.01)

                class BoundedWait:
                    def __getattr__(self, name):
                        return getattr(child, name)

                    def wait(self, timeout=None):
                        return child.wait(timeout=0.05 if timeout == 300 else timeout)

                return BoundedWait()

            try:
                with log.open("w") as output, patch.object(RUNNER.subprocess, "Popen", side_effect=factory):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        RUNNER.run_fixture(["unused"], os.environ.copy(), output)
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0].returncode, -signal.SIGKILL)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(children[0].pid, os.WNOHANG)
                self.assertEqual(log.read_text(), "partial diagnostic\n")
            finally:
                for child in children:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
