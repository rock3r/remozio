import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-protected-launch-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_protected_launch_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def first(expected):
    return {key: sorted(allowed)[0] for key, allowed in expected.items()}


def attacker_report(case, alternative=0, **changes):
    values = first(EXPERIMENT.CASES[case]["attacker"][alternative])
    values.update(changes)
    return json.dumps(values).encode()


def monitor_report(case, **changes):
    values = first(EXPERIMENT.CASES[case]["monitor"])
    values.update(monitorAppArmor="unconfined", frontendAppArmor="unconfined")
    values.update(changes)
    return json.dumps(values).encode()


def evaluate(case, attacker=None, monitor=None, attacker_rc=0, monitor_rc=0, queued="no"):
    attacker = attacker_report(case) if attacker is None else attacker
    if EXPERIMENT.CASES[case]["monitor"] is None:
        return EXPERIMENT.evaluate_case(case, attacker, attacker_rc, queued=queued)
    return EXPERIMENT.evaluate_case(case, attacker, attacker_rc,
                                    monitor_report(case) if monitor is None else monitor, monitor_rc)


@contextlib.contextmanager
def linux_root():
    with contextlib.ExitStack() as stack:
        for owner, name, value in ((EXPERIMENT.platform, "system", "Linux"), (EXPERIMENT.platform, "machine", "x86_64"),
                                   (EXPERIMENT.os, "geteuid", 0), (EXPERIMENT.os, "getuid", 0)):
            stack.enter_context(patch.object(owner, name, return_value=value))
        yield


class CaseTableTests(unittest.TestCase):
    def test_every_plan_case_is_measured_and_replacement_runs_last(self):
        # P1-P3 and N11 are the p1 monitor report; N9 has an untraced and a traced member.
        self.assertEqual(set(EXPERIMENT.CASES), {"p1", "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n9-untraced",
                                                 "n9-traced", "n10", "n12", "n8"})
        self.assertEqual(list(EXPERIMENT.CASES)[-1], "n8")

    def test_monitor_tables_require_every_property_except_observed_labels(self):
        for case, spec in EXPERIMENT.CASES.items():
            if spec["monitor"] is not None:
                with self.subTest(case=case):
                    self.assertEqual(set(spec["monitor"]), set(EXPERIMENT.MONITOR_KEYS) - EXPERIMENT.OBSERVED_ONLY)

    def test_fixture_sources_match_the_runner_vocabulary(self):
        monitor = EXPERIMENT.MONITOR.read_text()
        emitted = set(re.findall(r'(?:field|flag)\("([A-Za-z]+)"', monitor))
        self.assertEqual(emitted, set(EXPERIMENT.MONITOR_KEYS) | {"error"})
        attacker = EXPERIMENT.ATTACKER.read_text()
        dispatched = set(re.findall(r'!strcmp\(name, "([a-z0-9-]+)"\)', attacker))
        self.assertEqual(dispatched, {spec["argument"] for spec in EXPERIMENT.CASES.values()})

    def test_controls_isolate_the_refusal_they_measure(self):
        admitted = EXPERIMENT._expect(EXPERIMENT.ADMITTED)
        for case, differing in (("n8", {"exeIsCurrentInstalledImage", "mapsAllowed", "accepted"}),
                                ("n9-untraced", {"groupsExcludeFrontendGroup", "accepted"}),
                                ("n9-traced", {"groupsExcludeFrontendGroup", "accepted"})):
            with self.subTest(case=case):
                monitor = EXPERIMENT.CASES[case]["monitor"]
                self.assertEqual({key for key in admitted if monitor[key] != admitted[key]}, differing)
        self.assertTrue(EXPERIMENT.CASES["n9-untraced"]["member"])
        self.assertFalse(EXPERIMENT.CASES["p1"]["member"])
        self.assertEqual(EXPERIMENT.CASES["n10"]["monitorMode"], "nocap")


class EvaluateCaseTests(unittest.TestCase):
    def test_expected_outcome_passes_for_every_case(self):
        for case in EXPERIMENT.CASES:
            with self.subTest(case=case):
                result = evaluate(case)
                self.assertTrue(result["passed"], result)
                self.assertEqual(result["mismatches"], [])

    def test_user_namespace_case_accepts_refusal_or_an_unmapped_launch(self):
        self.assertTrue(evaluate("n12", attacker_report("n12", 0))["passed"])
        self.assertTrue(evaluate("n12", attacker_report("n12", 1))["passed"])
        elevated = evaluate("n12", attacker_report("n12", 1, effectiveGidElevated="yes"))
        self.assertEqual(elevated["mismatches"], ["attacker.effectiveGidElevated"])

    def test_admitted_launch_fails_on_any_failed_property(self):
        for key in EXPERIMENT.STOP_CHECKS:
            with self.subTest(key=key):
                result = evaluate("p1", monitor=monitor_report("p1", **{key: "no"}))
                self.assertFalse(result["passed"])
                self.assertEqual(result["mismatches"], [f"monitor.{key}"])

    def test_missing_peer_pidfd_fails_closed(self):
        refused = {"peerPidfd": "ENOPROTOOPT", "seize": "not-attempted", "pidfdAssociated": "no", "stopHeld": "no",
                   **dict.fromkeys(EXPERIMENT.STOP_CHECKS, "no"), "fdDirectoryListing": "not-attempted",
                   "frontendAppArmor": "not-attempted", "accepted": "no"}
        result = evaluate("p1", attacker_report("p1", frontendExit="rejected"), monitor_report("p1", **refused))
        self.assertFalse(result["passed"])
        self.assertIn("monitor.peerPidfd", result["mismatches"])
        self.assertIn("attacker.frontendExit", result["mismatches"])

    def test_apparmor_labels_are_recorded_not_required(self):
        result = evaluate("p1", monitor=monitor_report("p1", monitorAppArmor="confined", frontendAppArmor="confined"))
        self.assertTrue(result["passed"])
        self.assertEqual(result["monitor"]["monitorAppArmor"], "confined")

    def test_reports_reject_duplicates_non_strings_and_bounds(self):
        for raw in (b'{"frontendExit":"accepted","frontendExit":"accepted"}', b'{"frontendExit":0}',
                    b'{"frontendExit":NaN}', b'["accepted"]', b"not json",
                    b'{"frontendExit":"' + b"a" * EXPERIMENT.MAX_OUTPUT_BYTES + b'"}', "text"):
            with self.subTest(raw=raw[:40]):
                result = evaluate("p1", attacker=raw)
                self.assertEqual(result, {"passed": False, "error_type": "InvalidAttackerReport"})

    def test_unknown_keys_or_values_publish_nothing(self):
        for raw in (json.dumps({"frontendExit": "accepted", "path": "ok"}).encode(),
                    json.dumps({"frontendExit": "/home/someone"}).encode()):
            with self.subTest(raw=raw):
                self.assertEqual(evaluate("p1", attacker=raw),
                                 {"passed": False, "error_type": "InvalidAttackerReport"})
        extra = json.loads(monitor_report("p1"))
        extra["uid"] = "yes"
        result = evaluate("p1", monitor=json.dumps(extra).encode())
        self.assertEqual(result["error_type"], "InvalidMonitorReport")
        self.assertNotIn("monitor", result)
        result = evaluate("p1", monitor=monitor_report("p1", seize="1234"))
        self.assertEqual(result["error_type"], "InvalidMonitorReport")

    def test_monitor_error_publishes_a_known_category_only(self):
        known = evaluate("p1", monitor=b'{"monitorCredentialsExact":"yes","error":"accept-timeout"}')
        self.assertEqual((known["error_type"], known["monitorError"]), ("MonitorError", "accept-timeout"))
        unknown = evaluate("p1", monitor=b'{"error":"/etc/private"}')
        self.assertEqual(unknown, {"passed": False, "error_type": "MonitorError", "attacker": {"frontendExit": "accepted"}})

    def test_cases_without_a_monitor_require_an_empty_queue(self):
        self.assertEqual(evaluate("n1", queued="yes")["mismatches"], ["connectionQueued"])
        self.assertEqual(evaluate("n1", queued=None)["error_type"], "MissingConnectionCheck")

    def test_exit_statuses_must_be_zero(self):
        self.assertEqual(evaluate("p1", attacker_rc=1)["mismatches"], ["attacker.exitStatus"])
        self.assertEqual(evaluate("p1", monitor_rc=3)["mismatches"], ["monitor.exitStatus"])

    def test_spawn_failure_is_published_as_a_key_mismatch(self):
        result = evaluate("n2", attacker=b'{"spawn":"failed"}')
        self.assertEqual((result["passed"], result["mismatches"], result["attacker"]),
                         (False, ["attacker.keys"], {"spawn": "failed"}))
        result = evaluate("n1", attacker=b'{"installed.spawn":"failed","control.spawn":"failed"}')
        self.assertEqual(result["mismatches"], ["attacker.keys"])

    def test_same_uid_attack_must_fail_on_the_installed_image_and_work_on_the_copy(self):
        result = evaluate("n1", attacker_report("n1", **{"installed.vmWrite": "ok"}))
        self.assertEqual(result["mismatches"], ["attacker.installed.vmWrite"])
        result = evaluate("n1", attacker_report("n1", **{"control.seize": "EPERM"}))
        self.assertEqual(result["mismatches"], ["attacker.control.seize"])


def elf_header(e_type=2, program_types=(1,)):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:18] = e_type.to_bytes(2, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = len(program_types).to_bytes(2, "little")
    return bytes(header) + b"".join(kind.to_bytes(4, "little") + bytes(52) for kind in program_types)


class HelperTests(unittest.TestCase):
    def test_static_non_pie_requires_an_executable_without_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image"
            for data, expected in ((elf_header(), True), (elf_header(program_types=(1, 3)), False),
                                   (elf_header(e_type=3), False), (elf_header()[:80], False), (b"#!/bin/sh\n", False)):
                with self.subTest(expected=expected, size=len(data)):
                    path.write_bytes(data)
                    self.assertEqual(EXPERIMENT.static_non_pie(path), expected)

    def test_root_owned_ancestry_refuses_user_owned_or_writable_components(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(EXPERIMENT.root_owned_ancestry(Path(directory).resolve()))
        if os.lstat("/usr").st_uid == 0:
            self.assertTrue(EXPERIMENT.root_owned_ancestry(Path("/usr")))

    def test_host_metadata_publishes_numbers_and_closed_values_only(self):
        settings = {"/proc/sys/kernel/yama/ptrace_scope": b"1\n", "/proc/sys/fs/suid_dumpable": b"2\n",
                    "/proc/sys/fs/protected_hardlinks": b"1\n", "/sys/module/apparmor/parameters/enabled": b"Y\n",
                    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": b"1\n",
                    "/proc/sys/kernel/unprivileged_userns_clone": b"/proc/self\n",
                    "/etc/os-release": b'NAME="Private Host"\nID=ubuntu\nVERSION_ID="25.10"\n'}
        with patch.object(EXPERIMENT, "_policy_bytes", side_effect=lambda path, limit=4096: settings.get(path)), \
             patch.object(EXPERIMENT.platform, "release", return_value="6.17.0-41-generic-private-host"):
            host = EXPERIMENT.host_metadata()
        self.assertEqual(host["kernelVersion"], "6.17.0")
        self.assertEqual(host["osRelease"], {"id": "ubuntu", "versionId": "25.10"})
        self.assertEqual(host["settings"], {"ptraceScope": 1, "suidDumpable": 2, "protectedHardlinks": 1,
                                            "apparmorEnabled": True, "apparmorRestrictUnprivilegedUserns": 1,
                                            "unprivilegedUsernsClone": "unavailable"})
        self.assertNotIn("private", json.dumps(host).lower())

    def test_os_release_refuses_paths(self):
        with patch.object(EXPERIMENT, "_policy_bytes", return_value=b"ID=../../etc/x\nVERSION_ID=1\n"):
            self.assertEqual(EXPERIMENT._os_release(), {"id": "unknown", "versionId": "1"})

    def test_source_hashes_are_repository_relative(self):
        hashes = EXPERIMENT.source_hashes()
        self.assertEqual(set(hashes), {"scripts/run-linux-protected-launch-experiment.py",
                                       "experiments/linux-protected-launch/frontend.c",
                                       "experiments/linux-protected-launch/monitor.c",
                                       "experiments/linux-protected-launch/attacker.c",
                                       "scripts/run-linux-caller-experiment.py"})
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()))


class PreconditionTests(unittest.TestCase):
    def test_measure_refuses_without_root(self):
        with patch.object(EXPERIMENT.platform, "system", return_value="Linux"), \
             patch.object(EXPERIMENT.platform, "machine", return_value="x86_64"), \
             patch.object(EXPERIMENT.os, "geteuid", return_value=1000), \
             patch.object(EXPERIMENT, "Run") as run:
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                EXPERIMENT.measure()
        run.assert_not_called()

    def test_measure_refuses_a_bad_timeout(self):
        for timeout in (4, 61, float("nan"), "15", True):
            with self.subTest(timeout=timeout), linux_root(), patch.object(EXPERIMENT, "Run") as run:
                with self.assertRaises(ValueError):
                    EXPERIMENT.measure(timeout)
                run.assert_not_called()

    def test_operator_must_be_an_ordinary_sudo_caller(self):
        with patch.dict(EXPERIMENT.os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "through sudo"):
                EXPERIMENT.operator_account()
        account = SimpleNamespace(pw_uid=0, pw_gid=0, pw_name="root")
        with patch.dict(EXPERIMENT.os.environ, {"SUDO_UID": "0", "SUDO_GID": "0"}, clear=True), \
             patch.object(EXPERIMENT.pwd, "getpwuid", return_value=account):
            with self.assertRaisesRegex(RuntimeError, "ordinary account"):
                EXPERIMENT.operator_account()
        account = SimpleNamespace(pw_uid=1000, pw_gid=1001, pw_name="operator")
        with patch.dict(EXPERIMENT.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}, clear=True), \
             patch.object(EXPERIMENT.pwd, "getpwuid", return_value=account):
            with self.assertRaisesRegex(RuntimeError, "ordinary account"):
                EXPERIMENT.operator_account()

    def test_nosuid_or_untrusted_parent_is_refused_before_any_change(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        for ancestry, flags in ((True, EXPERIMENT.os.ST_NOSUID), (False, 0)):
            with self.subTest(ancestry=ancestry), linux_root(), \
                 patch.object(EXPERIMENT, "operator_account", return_value=operator), \
                 patch.object(EXPERIMENT, "root_owned_ancestry", return_value=ancestry), \
                 patch.object(EXPERIMENT.os, "statvfs", return_value=SimpleNamespace(f_flag=flags)), \
                 patch.object(EXPERIMENT, "Run") as run:
                with self.assertRaisesRegex(RuntimeError, "set-ID execution"):
                    EXPERIMENT.measure()
                run.assert_not_called()

    def test_cleanup_runs_after_a_failed_setup_and_warns_when_incomplete(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = Mock()
        run.setup.side_effect = RuntimeError("fixture build failed")
        run.cleanup.return_value = {"filesRemoved": True, "monitorUserRemoved": False, "frontendGroupRemoved": True}
        stderr = io.StringIO()
        with linux_root(), patch.object(EXPERIMENT, "operator_account", return_value=operator), \
             patch.object(EXPERIMENT, "root_owned_ancestry", return_value=True), \
             patch.object(EXPERIMENT.os, "statvfs", return_value=SimpleNamespace(f_flag=0)), \
             patch.object(EXPERIMENT, "Run", return_value=run), \
             patch.object(EXPERIMENT, "subreaper", contextlib.nullcontext), \
             patch.object(EXPERIMENT.sys, "stderr", stderr):
            with self.assertRaisesRegex(RuntimeError, "fixture build failed"):
                EXPERIMENT.measure()
        run.cleanup.assert_called_once_with()
        self.assertIn("not fully removed", stderr.getvalue())

    def test_cleanup_touches_only_state_this_run_created(self):
        run = EXPERIMENT.Run(SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator"), 15)
        with patch.object(EXPERIMENT.shutil, "rmtree") as remove, patch.object(EXPERIMENT, "run_owned") as tool:
            state = run.cleanup()
        remove.assert_not_called()
        tool.assert_not_called()
        self.assertEqual(set(state), {"filesRemoved", "monitorUserRemoved", "frontendGroupRemoved"})

    def test_cleanup_continues_after_a_failed_step(self):
        run = EXPERIMENT.Run(SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator"), 15)
        run.base_created = run.monitor_created = run.group_created = True
        with patch.object(EXPERIMENT.shutil, "rmtree", side_effect=OSError()), \
             patch.object(EXPERIMENT, "run_owned", side_effect=RuntimeError()) as tool, \
             patch.object(EXPERIMENT, "_absent", return_value=False):
            state = run.cleanup()
        self.assertEqual([call.args[0][0] for call in tool.call_args_list], ["userdel", "groupdel", "groupdel"])
        self.assertEqual(state["monitorUserRemoved"], False)

    def test_main_reports_no_raw_data_on_failure(self):
        stderr = io.StringIO()
        with patch.object(EXPERIMENT, "measure", side_effect=OSError("/private/path")), \
             patch.object(sys, "argv", ["runner"]), patch.object(sys, "stderr", stderr):
            with self.assertRaises(SystemExit) as raised:
                EXPERIMENT.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertNotIn("/private/path", stderr.getvalue())


@unittest.skipUnless(platform.system() == "Linux", "Linux owned-process cleanup")
class OwnedProcessTests(unittest.TestCase):
    def spawn(self, code):
        return subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True)

    def test_output_bound_and_deadline_are_enforced_and_groups_reaped(self):
        process = self.spawn(f"import sys; sys.stdout.write('x' * {EXPERIMENT.MAX_OUTPUT_BYTES + 10})")
        with self.assertRaises(EXPERIMENT.OutputLimitError):
            EXPERIMENT._read_output(process, EXPERIMENT.time.monotonic() + 10)
        self.assertTrue(EXPERIMENT._retire(process))
        process = self.spawn("import time; time.sleep(30)")
        with self.assertRaises(subprocess.TimeoutExpired):
            EXPERIMENT._read_output(process, EXPERIMENT.time.monotonic() + 0.2)
        self.assertTrue(EXPERIMENT._retire(process))
        self.assertIsNotNone(process.returncode)


FIXTURE_FLAGS = ("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror")


@unittest.skipUnless(os.environ.get("REMOZIO_LINUX_PROTECTED_LAUNCH_LIVE") == "1", "explicit live fixture controls")
@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86_64 fixtures")
class LiveFixtureTests(unittest.TestCase):
    """Unprivileged mechanics only. The set-group-ID measurement is the supervised runner."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        build = Path(cls.directory.name)
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("no C compiler")
        cls.frontend, cls.attacker = build / "frontend", build / "attacker"
        for output, source, extra in ((cls.frontend, EXPERIMENT.FRONTEND, ("-static", "-no-pie")),
                                      (build / "monitor", EXPERIMENT.MONITOR, ()),
                                      (cls.attacker, EXPERIMENT.ATTACKER, ())):
            subprocess.run([compiler, *FIXTURE_FLAGS, *extra, "-o", str(output), str(source)], check=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def attack(self, case):
        output = subprocess.run([str(self.attacker), case, str(self.frontend), str(self.frontend), "/nonexistent/s",
                                 "4294967294", "10"], stdin=subprocess.DEVNULL, capture_output=True, check=True,
                                timeout=30).stdout
        return EXPERIMENT.parse_report(output)

    def test_frontend_is_static_and_dumps_a_whole_filter(self):
        self.assertTrue(EXPERIMENT.static_non_pie(self.frontend))
        output = subprocess.run([str(self.frontend), "dump-filter"], capture_output=True, check=True, timeout=10).stdout
        self.assertTrue(output and len(output) % 8 == 0)

    def test_forbidden_operations_are_killed_by_the_filter(self):
        self.assertEqual(self.attack("n7"), dict.fromkeys(("exec", "mprotect", "shared", "clone", "x32"), "SIGSYS"))

    def test_same_uid_attacks_work_on_a_copy_without_set_id(self):
        expected = {f"{prefix}.{key}": value for prefix in ("installed", "control")
                    for key, value in EXPERIMENT.WORKING_ATTACK.items()}
        self.assertEqual(self.attack("n1"), expected)

    def test_unprivileged_launch_paths_reach_the_socket_step(self):
        for case in ("n2", "n3", "n4"):
            with self.subTest(case=case):
                result = self.attack(case)
                self.assertEqual((result["ready"], result["effectiveGidElevated"], result["frontendExit"]),
                                 ("yes", "no", "socket-failure"))


if __name__ == "__main__":
    unittest.main()
