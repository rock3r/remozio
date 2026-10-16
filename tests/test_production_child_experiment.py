import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("production_child_experiment", Path(__file__).resolve().parents[1] / "scripts/run-production-child-experiment.py")
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


class ProductionChildPreparationTests(unittest.TestCase):
    def test_concurrent_source_change_cannot_publish_a_frozen_command_or_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            invocations = []

            def run(command, **kwargs):
                invocations.append(command)
                if "-o" in command:
                    Path(command[command.index("-o") + 1]).write_bytes(b"fixture")
                    return subprocess.CompletedProcess(command, 0)
                self.assertEqual(Path(command[0]).name, "owner-controls")
                return subprocess.CompletedProcess(command, 0, json.dumps({"schemaVersion": 1, "ownerControls": 20,
                    "privilegedControlsRun": False, "realProcessesSpawned": 0}), "")

            with patch.object(EXPERIMENT, "source_hashes", side_effect=[{"input.c": "before"}, {"input.c": "after"}]), \
                 patch.object(EXPERIMENT.subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(RuntimeError, "sources changed"):
                    EXPERIMENT.prepare(directory)
            self.assertEqual(len(invocations), 6)
            self.assertFalse((directory / "manifest.json").exists())
            self.assertFalse((directory / "administrator-command.txt").exists())
            self.assertFalse(any("--privileged-controls" in command for command in invocations))

    def test_invalid_frozen_authority_inputs_cannot_emit_a_command(self):
        binaries = {name: {"sha256": "0" * 64} for name in EXPERIMENT.SOURCES}
        for uid in [0, -1, 2**32 - 1, True, "501; touch /tmp/foreign"]:
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                EXPERIMENT.administrator_command(Path("/tmp/fixture"), binaries, uid)
        for changed in [dict(binaries, foreign={"sha256": "0" * 64}),
                        {name: value for name, value in binaries.items() if name != "child"},
                        dict(binaries, child={"sha256": "x" * 64}),
                        dict(binaries, child={"sha256": "0" * 63 + "\n"})]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                EXPERIMENT.administrator_command(Path("/tmp/fixture"), changed, 501)


if __name__ == "__main__":
    unittest.main()
