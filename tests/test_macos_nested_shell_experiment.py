import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-macos-nested-shell-experiment.py"
spec = importlib.util.spec_from_file_location("nested_shell_experiment", SCRIPT)
experiment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(experiment)


class NestedShellExperimentTests(unittest.TestCase):
    def test_launch_frame_uses_fixture_scope_without_ambient_environment(self):
        with patch.dict(experiment.os.environ, {"HOME": "/ambient", "PATH": "/ambient",
                                                "REMOZIO_SECRET": "do-not-copy"}, clear=True):
            with patch.object(experiment.os, "getuid", return_value=123), patch.object(experiment.os, "getgid", return_value=456):
                frame = experiment.launch_frame(Path("/private/fixture"))
        header = struct.unpack(">10I", frame[:40])
        self.assertEqual(header, (0x524D4331, len(frame) - 40, 123, 456, 0, 6, 5, 5000, 0o077, 1))
        fields, offset = [], 40
        while offset < len(frame):
            length = struct.unpack(">I", frame[offset:offset + 4])[0]
            offset += 4
            fields.append(frame[offset:offset + length])
            offset += length
        self.assertEqual(offset, len(frame))
        self.assertEqual(fields[:7], [b"/bin/bash", b"/bin/bash", b"--noprofile", b"--norc", b"-i", b"-c",
                                     b"printf 'READY_MARKER\\n'; exec /bin/bash --noprofile --norc -i"])
        self.assertEqual(fields[7:], [b"HOME=/private/fixture", b"LC_ALL=C", b"PATH=/usr/bin:/bin", b"PS1=TEST> ", b"TERM=dumb"])

    def test_changed_or_incomplete_evidence_cannot_be_reported_as_success(self):
        experiment.require_observation(dict(experiment.EXPECTED), "typed", 0)
        for key, value in experiment.EXPECTED.items():
            actual = dict(experiment.EXPECTED)
            actual[key] = not value if type(value) is bool else value + 1
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                experiment.require_observation(actual, "typed", 1)
        for actual in [None, {}, {**experiment.EXPECTED, "extra": True},
                       {**experiment.EXPECTED, "nestedStopped": 1},
                       {**experiment.EXPECTED, "failure": False}]:
            with self.subTest(actual=actual), self.assertRaises(RuntimeError):
                experiment.require_observation(actual, "signal", 2)

    def test_elevation_is_rejected_before_compilation_or_spawn(self):
        with patch.object(experiment.platform, "system", return_value="Darwin"), patch.object(experiment.platform, "machine", return_value="arm64"):
            with patch.object(experiment.os, "geteuid", return_value=0), patch.object(experiment, "compile_fixture") as compile_fixture:
                with self.assertRaisesRegex(RuntimeError, "without elevation"):
                    experiment.measure()
                compile_fixture.assert_not_called()

    def test_unsupported_host_is_rejected_before_compilation_or_spawn(self):
        for system, architecture in [("Linux", "arm64"), ("Darwin", "x86_64")]:
            with self.subTest(system=system, architecture=architecture):
                with patch.object(experiment.platform, "system", return_value=system), patch.object(experiment.platform, "machine", return_value=architecture):
                    with patch.object(experiment, "compile_fixture") as compile_fixture:
                        with self.assertRaisesRegex(RuntimeError, "Apple Silicon Mac"):
                            experiment.measure()
                        compile_fixture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
