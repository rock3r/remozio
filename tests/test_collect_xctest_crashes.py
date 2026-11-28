"""Crash summaries must keep the crashed thread and drop everything that could identify the runner."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("collect_xctest_crashes", ROOT / "scripts/collect-xctest-crashes.py")
CRASHES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CRASHES)

SECRET = "ghs_secretTokenValue"


def report(process="xctest", faulting=1):
    header = {"app_name": process, "os_version": "macOS 26.1 (25B78)", "timestamp": "2026-11-28 05:19:52.00 +0000"}
    body = {
        "procName": process,
        "procPath": "/Users/runner/work/remozio/.build/xctest",
        "captureTime": "2026-11-28 05:19:52.0000 +0000",
        "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV", "subtype": "KERN_PROTECTION_FAILURE"},
        "termination": {"namespace": "SIGNAL", "indicator": "Segmentation fault: 11"},
        "faultingThread": faulting,
        "environment": {"GITHUB_TOKEN": SECRET},
        "usedImages": [
            {"name": "RemozioCorePackageTests", "path": "/Users/runner/work/remozio/RemozioCorePackageTests"},
            {"name": "libswiftCore.dylib", "path": "/usr/lib/swift/libswiftCore.dylib"},
        ],
        "threads": [
            {"name": "main", "frames": [{"imageIndex": 1, "symbol": "otherThreadSymbol", "symbolLocation": 4}]},
            {"queue": "com.apple.main-thread", "threadState": {"x": [{"value": 42}]},
             "frames": [
                 {"imageIndex": 0, "symbol": "Verification.require()", "symbolLocation": 12},
                 {"imageIndex": 1, "imageOffset": 4096},
                 {"imageIndex": 9, "symbol": "unknownImage"},
             ]},
        ],
    }
    return json.dumps(header) + "\n" + json.dumps(body, indent=2)


class CollectXCTestCrashesTests(unittest.TestCase):
    def collect(self, files, since=0, mtime=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory, output = Path(temporary) / "reports", Path(temporary) / "out"
            directory.mkdir()
            for name, content in files.items():
                path = directory / name
                path.write_text(content)
                if mtime is not None:
                    os.utime(path, (mtime, mtime))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = CRASHES.main(["--since", str(since), "--output", str(output), "--directory", str(directory)])
            written = {path.name: path.read_text() for path in output.glob("*")} if output.exists() else {}
            return status, written, stdout.getvalue()

    def test_summary_keeps_the_crashed_thread_and_drops_identifying_fields(self):
        status, written, _ = self.collect({"xctest-2026-11-28-051952.ips": report()})
        self.assertEqual(status, 0)
        summary = written["xctest-2026-11-28-051952.txt"]
        self.assertIn("exception: EXC_BAD_ACCESS SIGSEGV KERN_PROTECTION_FAILURE", summary)
        self.assertIn("termination: SIGNAL Segmentation fault: 11", summary)
        self.assertIn("crashed thread 1: com.apple.main-thread", summary)
        self.assertIn("RemozioCorePackageTests", summary)
        self.assertIn("Verification.require() + 12", summary)
        self.assertIn("libswiftCore.dylib", summary)
        self.assertIn("??? + 4096", summary)
        self.assertIn("unknownImage", summary)
        for dropped in (SECRET, "GITHUB_TOKEN", "/Users/runner", "otherThreadSymbol", "threadState", "procPath"):
            self.assertNotIn(dropped, summary)

    def test_other_processes_old_reports_and_missing_reports_write_nothing(self):
        self.assertEqual(self.collect({"Finder-2026.ips": report("Finder")})[:2], (0, {}))
        self.assertEqual(self.collect({"xctest-old.ips": report()}, since=2_000, mtime=1_000)[:2], (0, {}))
        self.assertEqual(self.collect({})[:2], (0, {}))
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            missing = Path(temporary) / "missing"
            self.assertEqual(CRASHES.main(["--since", "0", "--output", str(Path(temporary) / "out"),
                                           "--directory", str(missing)]), 0)
            self.assertFalse((Path(temporary) / "out").exists())

    def test_an_unreadable_report_is_a_warning_and_not_copied(self):
        status, written, stdout = self.collect({"xctest-bad.ips": "not json " + SECRET,
                                                "xctest-good.ips": report()})
        self.assertEqual(status, 0)
        self.assertEqual(list(written), ["xctest-good.txt"])
        self.assertIn("::warning::Could not read crash report xctest-bad.ips", stdout)
        self.assertNotIn(SECRET, stdout)

    def test_a_report_without_the_faulting_thread_still_names_the_exception(self):
        _, written, _ = self.collect({"xctest-x.ips": report(faulting=7)})
        summary = written["xctest-x.txt"]
        self.assertIn("SIGSEGV", summary)
        self.assertIn("crashed thread: not in the report", summary)
        self.assertNotIn("otherThreadSymbol", summary)


if __name__ == "__main__":
    unittest.main()
