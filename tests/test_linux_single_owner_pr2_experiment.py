import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-single-owner-pr2-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_single_owner_pr2_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)
ROOT = SCRIPT.parents[1]
DESIGN = ROOT / "docs/linux-single-owner-design.md"
EXPERIMENT_DOC = ROOT / "docs/experiments/linux-single-owner.md"
TAG = "0123abcd"
LINUX = sys.platform.startswith("linux")

START = b'{"ownerCapabilitiesExact":"yes","generation":"yes","authorityAccepted":"yes"}'


def dispatch_line(number, result="dispatched"):
    return (b'{"dispatch":"%d","admitted":"yes","permit":"yes","finalCheck":"yes","result":"%s",'
            b'"execErrno":"none","requesterLostBeforeCheck":"no","requesterLostAfterCheck":"no","goWritten":"yes",'
            b'"killedAtDeadline":"no","reported":"yes","kSetup":"ok","kEnd":"exited","restartLogComplete":"yes"}'
            % (number, result.encode()))


def command_report(**changes):
    report = {"capPrm": "0000000000000000", "capEff": "0000000000000000", "capInh": "0000000000000000",
              "capAmb": "0000000000000000", "capBnd": "000001ffffffffff", "noNewPrivs": "0",
              "mntNs": "mnt:[4026531832]", "label": "unconfined", "fds": "0 1 2", "sudo": "not-run"}
    report.update(changes)
    return json.dumps(report, separators=(",", ":")).encode() + b"\n"


class TemplateTests(unittest.TestCase):
    def test_profile_renders_one_profile_with_the_ux_rule(self):
        name, text = EXPERIMENT.render_profile(EXPERIMENT.APPARMOR_TEMPLATE.read_text(), TAG, EXPERIMENT.base_for(TAG))
        self.assertEqual(name, "rmzso-owner-" + TAG)
        self.assertTrue(text.startswith("abi <abi/4.0>,\n"))
        self.assertIn(f"  {EXPERIMENT.base_for(TAG)}/run/cmd-* ux,", text)
        self.assertNotIn("@@", text)
        self.assertNotIn("include", text)

    def test_profile_refuses_other_tags_paths_and_a_missing_ux_rule(self):
        template = EXPERIMENT.APPARMOR_TEMPLATE.read_text()
        with self.assertRaises(ValueError):
            EXPERIMENT.render_profile(template, "XYZ", EXPERIMENT.base_for(TAG))
        with self.assertRaises(ValueError):
            EXPERIMENT.render_profile(template, TAG, Path("/tmp/elsewhere"))
        with self.assertRaises(ValueError):
            EXPERIMENT.render_profile(template.replace("cmd-* ux,", "cmd-* ix,"), TAG, EXPERIMENT.base_for(TAG))
        with self.assertRaises(ValueError):
            EXPERIMENT.render_profile(template + "\n@@OTHER@@\n", TAG, EXPERIMENT.base_for(TAG))

    def test_unit_uses_only_the_design_options(self):
        properties = EXPERIMENT.unit_properties("svc", "svc")
        names = {item.split("=", 1)[0] for item in properties}
        allowed = {"User", "Group", "AmbientCapabilities", "KillMode", "OOMPolicy", "TasksMax", "RemainAfterExit",
                   *(f"Limit{name}" for name in EXPERIMENT.LIMITS)}
        self.assertEqual(names, allowed)
        self.assertIn("KillMode=process", properties)
        self.assertIn("OOMPolicy=continue", properties)
        self.assertIn("TasksMax=infinity", properties)
        self.assertIn("AmbientCapabilities=CAP_SYS_PTRACE CAP_SETUID CAP_SETGID", properties)
        # Options that set no_new_privs or a mount namespace for a service user that is not Root.
        forbidden = ("NoNewPrivileges", "SystemCallFilter", "SystemCallArchitectures", "RestrictSUIDSGID",
                     "RestrictNamespaces", "RestrictRealtime", "RestrictAddressFamilies", "MemoryDenyWriteExecute",
                     "LockPersonality", "ProtectKernel", "ProtectClock", "ProtectHostname", "ProtectSystem",
                     "ProtectHome", "PrivateTmp", "PrivateDevices", "ReadOnlyPaths", "CapabilityBoundingSet")
        self.assertFalse([item for item in properties if item.startswith(forbidden)])

    def test_case_additions_are_explicit(self):
        self.assertIn("NoNewPrivileges=yes", EXPERIMENT.unit_properties("s", "s", ("nnp",)))
        self.assertIn("PrivateTmp=yes", EXPERIMENT.unit_properties("s", "s", ("privatetmp",)))
        self.assertIn("MemoryMax=64M", EXPERIMENT.unit_properties("s", "s", ("oom",)))
        self.assertIn("AppArmorProfile=rmzso-owner-x", EXPERIMENT.unit_properties("s", "s", ("apparmor",),
                                                                                  "rmzso-owner-x"))
        with self.assertRaises(ValueError):
            EXPERIMENT.unit_properties("s", "s", ("apparmor",))

    def test_unit_command_has_no_collect_and_checks_the_name(self):
        command = EXPERIMENT.unit_command("/usr/bin/systemd-run", f"rmzso-{TAG}-unit-report.service", ["A=b"], ["x"])
        self.assertEqual(command[:4], ["/usr/bin/systemd-run", f"--unit=rmzso-{TAG}-unit-report.service", "--quiet",
                                       "--service-type=exec"])
        self.assertNotIn("--collect", command)
        self.assertEqual(command[-2:], ["--", "x"])
        for name in ("other.service", f"rmzso-{TAG}-x.socket", f"rmzso-{TAG}-../x.service"):
            with self.assertRaises(ValueError):
                EXPERIMENT.unit_command("systemd-run", name, [], [])

    def test_owner_images_are_static_and_unchanged(self):
        for name, (source, flags) in EXPERIMENT.BUILDS.items():
            self.assertIn("-static", flags, name)
        self.assertEqual(EXPERIMENT.BUILDS["owner"][0], EXPERIMENT.SO.OWNER)


class ReadbackTests(unittest.TestCase):
    SHOW = "\n".join([f"{key}={value}" for key, value in EXPERIMENT.SHOW_EXPECTED.items()])

    def test_readback_accepts_the_design_settings(self):
        values = EXPERIMENT.parse_show(self.SHOW)
        self.assertTrue(EXPERIMENT.readback_matches(values))
        values["AmbientCapabilities"] = "cap_sys_ptrace cap_setgid cap_setuid"
        self.assertTrue(EXPERIMENT.readback_matches(values))

    def test_readback_refuses_any_difference(self):
        for key, value in (("KillMode", "control-group"), ("OOMPolicy", "stop"), ("TasksMax", "4915"),
                           ("NoNewPrivileges", "yes"), ("PrivateTmp", "yes"), ("LimitNOFILE", "1024"),
                           ("AmbientCapabilities", "cap_sys_ptrace")):
            values = EXPERIMENT.parse_show(self.SHOW)
            values[key] = value
            self.assertFalse(EXPERIMENT.readback_matches(values), key)
        values = EXPERIMENT.parse_show(self.SHOW)
        del values["KillMode"]
        self.assertFalse(EXPERIMENT.readback_matches(values))

    def test_show_output_must_be_well_formed(self):
        for text in ("KillMode=process\nKillMode=process", "no separator", "Bad Key=x"):
            with self.assertRaises(ValueError):
                EXPERIMENT.parse_show(text)

    def test_owner_limits_at_max(self):
        top = ",".join(["inf/inf"] * 7 + ["1048576/1048576"] + ["inf/inf"] * 8)
        self.assertTrue(EXPERIMENT.limits_at_max(top, 1048576))
        self.assertTrue(EXPERIMENT.limits_at_max(",".join(["inf/inf"] * 16), 1048576))
        self.assertFalse(EXPERIMENT.limits_at_max(top.replace("1048576/1048576", "1024/1048576"), 1048576))
        self.assertFalse(EXPERIMENT.limits_at_max(",".join(["inf/inf"] * 15), 1048576))
        self.assertFalse(EXPERIMENT.limits_at_max(top.replace("inf/inf", "8388608/inf", 1), 1048576))


class CommandReportTests(unittest.TestCase):
    MNT = "mnt:[4026531832]"

    def test_clean_command(self):
        checks = EXPERIMENT.command_checks(command_report(), 40, self.MNT, TAG)
        self.assertEqual(checks, {"capsEmpty": "yes", "boundingFull": "yes", "noNewPrivs": "0",
                                  "hostMountNamespace": "yes", "commandLabel": "unconfined", "commandFds": "exact",
                                  "sudo": "not-run"})

    def test_negative_controls_change_the_values(self):
        self.assertEqual(EXPERIMENT.command_checks(command_report(noNewPrivs="1"), 40, self.MNT, TAG)["noNewPrivs"],
                         "1")
        self.assertEqual(EXPERIMENT.command_checks(command_report(mntNs="mnt:[4026532999]"), 40, self.MNT,
                                                   TAG)["hostMountNamespace"], "no")
        self.assertEqual(EXPERIMENT.command_checks(command_report(capEff="0000000000200000"), 40, self.MNT,
                                                   TAG)["capsEmpty"], "no")
        self.assertEqual(EXPERIMENT.command_checks(command_report(fds="0 1 2 3"), 40, self.MNT, TAG)["commandFds"],
                         "other")

    def test_labels_and_sudo_categories(self):
        label = EXPERIMENT.command_checks(command_report(label=f"rmzso-owner-{TAG} (enforce)"), 40, self.MNT, TAG)
        self.assertEqual(label["commandLabel"], "owner-profile")
        self.assertEqual(EXPERIMENT.command_checks(command_report(label="snap.x (enforce)"), 40, self.MNT,
                                                   TAG)["commandLabel"], "other")
        for category in ("password-required", "allowed", "no-new-privs", "timeout"):
            self.assertEqual(EXPERIMENT.command_checks(command_report(sudo=category), 40, self.MNT, TAG)["sudo"],
                             category)

    def test_missing_and_invalid_reports(self):
        self.assertEqual(set(EXPERIMENT.command_checks(b"", 40, self.MNT, TAG).values()), {"not-reported"})
        for raw in (command_report(sudo="maybe"), command_report(noNewPrivs="2"), command_report() * 2,
                    command_report(capPrm="xyz"), command_report().replace(b'"fds"', b'"extra"')):
            with self.assertRaises(ValueError):
                EXPERIMENT.command_checks(raw, 40, self.MNT, TAG)


class OwnerAndAuthorityTests(unittest.TestCase):
    def test_owner_reports_number_the_dispatches(self):
        start, reports = EXPERIMENT.owner_reports(START + b"\n" + dispatch_line(1) + b"\n" + dispatch_line(2), 2)
        self.assertEqual(start["generation"], "yes")
        self.assertEqual([report["result"] for report in reports], ["dispatched", "dispatched"])
        self.assertNotIn("dispatch", reports[0])
        for raw in (START + b"\n" + dispatch_line(2), START + b"\n" + dispatch_line(1) * 1 + b"\n" + dispatch_line(1),
                    START + b"\n" + dispatch_line(1) + b"\n" + dispatch_line(2) + b"\n" + dispatch_line(3)):
            with self.assertRaises(ValueError):
                EXPERIMENT.owner_reports(raw, 2)

    def test_authority_events_are_a_closed_vocabulary(self):
        raw = (b'{"event":"start"}\n{"event":"peer","result":"owner"}\n{"event":"hello","result":"accepted"}\n'
               b'{"event":"submit","phase":"executing","result":"permit"}\n'
               b'{"event":"outcome","phase":"succeeded","reported":"dispatched","requesterLost":"no",'
               b'"result":"recorded"}\n{"event":"end"}\n')
        events = EXPERIMENT.authority_events(raw)
        summary, per_dispatch = EXPERIMENT.authority_summary(events, 1)
        self.assertEqual(summary, {"authorityHello": "accepted"})
        self.assertEqual(per_dispatch, [{"authorityPermit": "yes", "authorityPhaseAfterPermit": "executing",
                                         "authorityOutcome": "dispatched", "authorityPhase": "succeeded"}])
        for bad in (b'{"event":"other"}', b'{"event":"hello","result":"maybe"}',
                    b'{"event":"submit","result":"permit","token":"00"}', b'{"event":"hello","result":1}'):
            with self.assertRaises(ValueError):
                EXPERIMENT.authority_events(bad)

    def test_an_owner_that_died_leaves_the_request_executing(self):
        events = EXPERIMENT.authority_events(b'{"event":"hello","result":"accepted"}\n'
                                             b'{"event":"submit","phase":"executing","result":"permit"}\n')
        _summary, per_dispatch = EXPERIMENT.authority_summary(events, 1)
        self.assertEqual(per_dispatch[0]["authorityOutcome"], "missing")
        self.assertEqual(per_dispatch[0]["authorityPhase"], "executing")

    def test_outcome_phases_follow_the_lifecycle(self):
        # beginDispatch is durable before the permit, so a dispatch without a command can only fail.
        self.assertEqual(EXPERIMENT.OUTCOME_PHASE, {"dispatched": "succeeded", "unknown": "unknown",
                                                    "execFailed": "failed", "notStarted": "failed",
                                                    "refused": "failed"})
        authority = (ROOT / "experiments/linux-single-owner/authority/Sources/LinuxSingleOwnerAuthority/main.swift")
        text = authority.read_text()
        self.assertIn('case "dispatched": try permit.store.succeeded()', text)
        self.assertIn('case "unknown": try permit.store.lostOutcome()', text)
        self.assertIn("default: try permit.store.failed()", text)
        self.assertIn("try store.dispatched(token)", text)

    def test_restart_log_per_dispatch(self):
        log = b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 GO\n4 1 DETACH\n5 2 SEIZE\n6 2 INTERRUPT\n7 2 GO\n"
        self.assertEqual(EXPERIMENT.restart_log_clean_all(log, 2), "yes")
        self.assertEqual(EXPERIMENT.restart_log_clean_all(log + b"8 2 DETACH\n9 2 GO\n", 2), "no")
        self.assertEqual(EXPERIMENT.restart_log_clean_all(b"1 3 SEIZE\n", 2), "no")
        self.assertEqual(EXPERIMENT.restart_log_clean_all(b"", 2), EXPERIMENT.NA)


class DescriptorTests(unittest.TestCase):
    FIRST = {"owner": {0: "/dev/null", 1: "pipe:[10]", 3: "socket:[11]", 7: "pipe:[20]", 8: "pipe:[21]"},
             "k": {0: "pipe:[30]", 1: "pipe:[31]", 2: "pipe:[32]", 3: "pipe:[20]", 4: "pipe:[21]"},
             "c": {0: "pipe:[30]", 1: "pipe:[31]", 2: "pipe:[32]", 3: "socket:[33]"}}
    SECOND = {"owner": {0: "/dev/null", 1: "pipe:[10]", 3: "socket:[11]", 7: "pipe:[40]", 8: "pipe:[41]"},
              "k": {0: "pipe:[50]", 1: "pipe:[51]", 2: "pipe:[52]", 3: "pipe:[40]", 4: "pipe:[41]"},
              "c": {0: "pipe:[50]", 1: "pipe:[51]", 2: "pipe:[52]", 3: "socket:[53]"},
              "command1": {0: "pipe:[30]", 1: "pipe:[31]", 2: "pipe:[32]"}}

    def test_each_dispatch_holds_only_its_own_descriptors(self):
        self.assertEqual(set(EXPERIMENT.fd_checks(self.FIRST, self.SECOND).values()), {"yes"})

    def test_a_leak_fails_its_check(self):
        cases = {
            "k2FdsExact": lambda s: s["k"].update({5: "pipe:[30]"}),
            "k2StreamsAreC2": lambda s: s["k"].update({1: "pipe:[31]"}),
            "ownerHoldsNothingOfDispatch1": lambda s: s["owner"].update({9: "pipe:[21]"}),
            "command1HoldsOnlyItsStreams": lambda s: s["command1"].update({3: "pipe:[40]"}),
        }
        for key, change in cases.items():
            second = json.loads(json.dumps(self.SECOND), object_hook=lambda d: {int(k) if k.isdigit() else k: v
                                                                                for k, v in d.items()})
            change(second)
            self.assertEqual(EXPERIMENT.fd_checks(self.FIRST, second)[key], "no", key)

    def test_missing_snapshots(self):
        self.assertEqual(set(EXPERIMENT.fd_checks(None, self.SECOND).values()), {EXPERIMENT.NA})


class CaseTableTests(unittest.TestCase):
    def test_expectations_use_the_vocabulary(self):
        for case, spec in EXPERIMENT.CASES.items():
            if spec["kind"] == "controls":
                continue
            for key, allowed in spec["expectCase"].items():
                self.assertLessEqual(allowed, EXPERIMENT.CASE_KEYS[key], (case, key))
            self.assertEqual(len(spec["expectDispatches"]), len(spec["modes"]), case)
            for expected in spec["expectDispatches"]:
                for key, allowed in expected.items():
                    self.assertLessEqual(allowed, EXPERIMENT.DISPATCH_KEYS[key], (case, key))
            for _barrier, action in spec["actions"]:
                self.assertIn(action, EXPERIMENT.ACTIONS)
            self.assertIn(spec["command"], EXPERIMENT.COMMANDS)

    def test_plan_review_answers_are_in_the_table(self):
        cases = EXPERIMENT.CASES
        # 1: a second dispatch while the first command runs, with the descriptor checks.
        self.assertEqual(cases["second-dispatch-fds"]["modes"], ("sleep", "normal"))
        # 2: sudo -n true, password required (or allowed); no sudoers change anywhere in the runner.
        self.assertEqual(set(cases["unit-sudo"]["expectDispatches"][0]["sudo"]), {"password-required", "allowed"})
        self.assertNotIn("/etc/sudoers", SCRIPT.read_text())
        self.assertNotIn("visudo", SCRIPT.read_text())
        # 3: a real out-of-memory kill under MemoryMax=, not SIGKILL to O.
        self.assertIn("oom", cases["unit-oom"]["extra"])
        self.assertNotIn("kill-owner", [action for _b, action in cases["unit-oom"]["actions"]])
        # 4: the password prompt is a known limit and does not gate strictAdmission.
        self.assertEqual([case for case, spec in cases.items() if not spec["gating"]], ["unit-sudo-prompt"])

    def test_the_pr1_runner_is_imported_not_changed(self):
        self.assertIn("spec_from_file_location", SCRIPT.read_text())
        self.assertEqual(EXPERIMENT.PR1_RUNNER.name, "run-linux-single-owner-experiment.py")

    def test_every_case_is_documented(self):
        text = EXPERIMENT_DOC.read_text()
        for case in EXPERIMENT.CASES:
            self.assertIn(f"`{case}`", text, case)
        self.assertIn("run-linux-single-owner-pr2-experiment.py", DESIGN.read_text())


def observed_for(case, **changes):
    spec = EXPERIMENT.CASES[case]
    observed = {key: next(iter(sorted(values))) for key, values in EXPERIMENT.CASE_KEYS.items()}
    observed.update({key: next(iter(allowed)) for key, allowed in spec["expectCase"].items()})
    items = []
    for expected in spec["expectDispatches"]:
        item = {key: next(iter(sorted(values))) for key, values in EXPERIMENT.DISPATCH_KEYS.items()}
        item.update({key: next(iter(allowed)) for key, allowed in expected.items()})
        items.append(item)
    observed["dispatches"] = items
    observed.update(changes)
    return observed


class EvaluateTests(unittest.TestCase):
    def test_a_case_passes_only_with_its_expectations(self):
        result = EXPERIMENT.evaluate("unit-report", observed_for("unit-report"))
        self.assertTrue(result["passed"], result)
        result = EXPERIMENT.evaluate("unit-report", observed_for("unit-report", unitReadback="no"))
        self.assertEqual(result["mismatches"], ["unitReadback"])
        observed = observed_for("unit-report")
        observed["dispatches"][0]["noNewPrivs"] = "1"
        self.assertEqual(EXPERIMENT.evaluate("unit-report", observed)["mismatches"], ["d1.noNewPrivs"])

    def test_invalid_observations(self):
        observed = observed_for("unit-report", ownerExit="crashed")
        self.assertEqual(EXPERIMENT.evaluate("unit-report", observed), {"passed": False,
                                                                         "error_type": "InvalidObservation"})
        observed = observed_for("unit-report")
        observed["dispatches"] = []
        self.assertFalse(EXPERIMENT.evaluate("unit-report", observed)["passed"])
        observed = observed_for("unit-report")
        observed["dispatches"][0]["pid"] = "1234"
        self.assertEqual(EXPERIMENT.evaluate("unit-report", observed)["error_type"], "InvalidObservation")

    def test_controls_case(self):
        observed = {**EXPERIMENT.CONTROL_EXPECT, "operatorConnect": EXPERIMENT.NA}
        self.assertTrue(EXPERIMENT.evaluate("authority-controls", observed)["passed"])
        result = EXPERIMENT.evaluate("authority-controls", {**observed, "replaySubmit": "PERMIT"})
        self.assertEqual(result["mismatches"], ["replaySubmit"])

    def test_strict_admission_ignores_only_the_known_limit(self):
        setup, cleanup = {"a": True}, {"b": True}
        cases = {case: {"passed": True} for case in EXPERIMENT.CASES}
        self.assertEqual(EXPERIMENT.admission(cases, setup, cleanup), (True, True))
        cases["unit-sudo-prompt"] = {"passed": False}
        self.assertEqual(EXPERIMENT.admission(cases, setup, cleanup), (False, True))
        cases["unit-apparmor"] = {"passed": False, "status": "not-run"}
        self.assertEqual(EXPERIMENT.admission(cases, setup, cleanup), (False, False))
        cases = {case: {"passed": True} for case in EXPERIMENT.CASES}
        self.assertEqual(EXPERIMENT.admission(cases, setup, {"b": False}), (False, False))
        self.assertEqual(EXPERIMENT.admission({}, setup, cleanup), (False, False))

    def test_measure_needs_root_and_never_claims_production(self):
        if os.geteuid() == 0:
            self.skipTest("runs as Root")
        with self.assertRaises(RuntimeError):
            EXPERIMENT.measure(30, "/bin/true")
        self.assertIn('"productionAdmission": False', SCRIPT.read_text())
        self.assertNotIn('"productionAdmission": True', SCRIPT.read_text())


class FakeAuthority:
    """The authority's line protocol in Python, for the client: generation, one-use permit, replay."""

    def __init__(self, path, owner_uid):
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.listener.bind(str(path))
        self.listener.listen(8)
        self.owner_uid = owner_uid
        self.events, self.permits, self.nonces = [], {}, set()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    @staticmethod
    def start_time(pid):
        text = Path(f"/proc/{pid}/stat").read_text()
        return int(text[text.rindex(")") + 2:].split()[19])

    def serve(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.session, args=(connection,), daemon=True).start()

    def session(self, connection):
        pid, uid, _gid = (int.from_bytes(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)[i:i + 4],
                                         sys.byteorder) for i in (0, 4, 8))
        generation = None
        with connection:
            while True:
                message = connection.recv(1024).decode()
                if not message:
                    return
                words = message.split(" ")
                reply = "REFUSED"
                if uid != self.owner_uid:
                    self.events.append({"event": "message", "result": "wrong-peer"})
                elif words[0] == "HELLO" and generation is None:
                    if int(words[2]) == pid and int(words[3]) == self.start_time(pid):
                        generation, reply = tuple(words[1:4]), "OK"
                elif words[0] == "SUBMIT" and generation:
                    if words[1] in self.nonces:
                        self.events.append({"event": "submit", "result": "replay-refused", "ledger": "refused"})
                    else:
                        self.nonces.add(words[1])
                        token = secrets.token_hex(16)
                        self.permits[token] = [generation, False]
                        reply = f"PERMIT {token} 1 1 normal 0"
                elif words[0] == "OUTCOME" and generation and words[1] in self.permits:
                    permit = self.permits[words[1]]
                    if permit[0] != generation:
                        self.events.append({"event": "outcome", "result": "generation-refused"})
                    elif not permit[1]:
                        permit[1], reply = True, "OK"
                connection.send(reply.encode())

    def close(self):
        self.listener.close()


@unittest.skipUnless(LINUX, "needs Linux procfs and SEQPACKET sockets")
class ClientTests(unittest.TestCase):
    def test_controls_against_a_protocol_double(self):
        with tempfile.TemporaryDirectory() as directory:
            good, wrong = FakeAuthority(Path(directory) / "a.sock", os.getuid()), \
                FakeAuthority(Path(directory) / "b.sock", os.getuid() + 1)
            try:
                first, later, wrong_reply, operator = EXPERIMENT.run_controls(
                    Path(directory) / "a.sock", {}, {}, wrong_socket=Path(directory) / "b.sock")
            finally:
                good.close()
                wrong.close()
            observed = EXPERIMENT.control_observations(first, later, wrong_reply, good.events + wrong.events)
            result = EXPERIMENT.evaluate("authority-controls", observed)
            self.assertTrue(result["passed"], result)
            self.assertEqual(operator, EXPERIMENT.NA)
            self.assertNotIn("kept", first)
            self.assertFalse([value for value in observed.values() if re.fullmatch(r"[0-9a-f]{32}", value)])

    def test_operator_connect_category(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.sock"
            self.assertEqual(EXPERIMENT.run_client("connect", path)["operatorConnect"], "other")


class StaticFixtureTests(unittest.TestCase):
    def test_c_fixtures_compile(self):
        compiler = shutil.which("cc")
        if not LINUX or compiler is None:
            self.skipTest("needs a Linux C compiler")
        with tempfile.TemporaryDirectory() as directory:
            for name, (source, _flags) in EXPERIMENT.BUILDS.items():
                subprocess.run([compiler, *EXPERIMENT.SO.CC_FLAGS, "-o", f"{directory}/{name}", str(source)],
                               check=True, capture_output=True)
            support = EXPERIMENT.AUTHORITY_PACKAGE / "Sources/CSingleOwnerAuthority"
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-c", "-I", str(support / "include"),
                            str(support / "single_owner_authority.c"), "-o", f"{directory}/support.o"],
                           check=True, capture_output=True)

    def test_command_fixture_reports_without_sudo(self):
        compiler = shutil.which("cc")
        if not LINUX or compiler is None:
            self.skipTest("needs a Linux C compiler")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "cmd-report"
            subprocess.run([compiler, *EXPERIMENT.SO.CC_FLAGS, "-o", str(binary), str(EXPERIMENT.COMMAND)],
                           check=True, capture_output=True)
            marker = Path(directory) / "marker"
            result = subprocess.run([str(binary), "normal", str(marker)], capture_output=True, timeout=10,
                                    stdin=subprocess.DEVNULL)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), "ran\n")
            mnt = os.readlink("/proc/self/ns/mnt")
            last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
            checks = EXPERIMENT.command_checks(result.stdout, last_cap, mnt, TAG)
            self.assertEqual(checks["sudo"], "not-run")
            self.assertEqual(checks["hostMountNamespace"], "yes")
            # The command's own reserved-free exit codes: never 120-123.
            self.assertIsNone(re.search(r"return 12[0-3]|_exit\(12[0-3]\)", EXPERIMENT.COMMAND.read_text()))


class _Fake:
    def __init__(self, **values):
        self.__dict__.update(values)


class CleanupTests(unittest.TestCase):
    def make_run(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = EXPERIMENT.Run(operator, 30, "/bin/true", {name: f"/usr/bin/{name}" for name in EXPERIMENT.TOOLS})
        return run

    def test_every_cleanup_step_runs_when_an_earlier_one_fails(self):
        run = self.make_run()
        run.units = [f"rmzso-{run.tag}-a.service", f"rmzso-{run.tag}-b.service"]
        run.owner_created = run.authority_created = True
        calls = []

        def retire(unit):
            calls.append(("retire", unit))
            raise RuntimeError("systemctl failed")

        with patch.object(run, "retire_unit", side_effect=retire), \
                patch.object(run, "_remove_profile", side_effect=lambda: calls.append(("profile",)) or True), \
                patch.object(EXPERIMENT.SO, "_kill_user",
                             side_effect=lambda uid: calls.append(("kill", uid)) or True), \
                patch.object(EXPERIMENT.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=4242)), \
                patch.object(EXPERIMENT.PL, "_absent", return_value=False), \
                patch.object(EXPERIMENT.PL, "run_owned", side_effect=lambda args, timeout: calls.append(
                    ("tool", args[0].rsplit("/", 1)[-1])) or (0, b"")):
            result = run.cleanup()
        self.assertEqual([call[0] for call in calls[:3]], ["retire", "retire", "profile"])
        self.assertEqual([call for call in calls if call[0] == "kill"], [("kill", 4242), ("kill", 4242)])
        self.assertIn(("tool", "userdel"), calls)
        self.assertIn(("tool", "groupdel"), calls)
        self.assertFalse(result["unitsRemoved"])

    def test_a_shared_uid_is_never_killed(self):
        run = self.make_run()
        run.owner_created = run.authority_created = True
        run.uid_shared = True
        with patch.object(EXPERIMENT.SO, "_kill_user") as kill, \
                patch.object(EXPERIMENT.PL, "_absent", return_value=True):
            result = run.cleanup()
        kill.assert_not_called()
        self.assertFalse(result["serviceProcessesGone"])

    def test_setup_refuses_a_uid_that_already_has_processes(self):
        run = self.make_run()
        with tempfile.TemporaryDirectory() as directory:
            run.base = Path(directory) / "base"
            accounts = {run.owner_name: SimpleNamespace(pw_uid=5001, pw_gid=5001),
                        run.authority_name: SimpleNamespace(pw_uid=5002, pw_gid=5002)}
            with patch.object(EXPERIMENT, "BUILDS", {}), \
                    patch.object(EXPERIMENT.os, "getgrouplist", return_value=[1000]), \
                    patch.object(EXPERIMENT.PL, "write_root_file"), \
                    patch.object(EXPERIMENT.PL, "run_owned", return_value=(0, b"")), \
                    patch.object(EXPERIMENT.SO, "read_bounded", return_value=b"authority"), \
                    patch.object(EXPERIMENT.PL.Run, "_create",
                                 side_effect=lambda self, flag, args, names: setattr(self, flag, True)), \
                    patch.object(EXPERIMENT.pwd, "getpwnam", side_effect=lambda name: accounts[name]), \
                    patch.object(EXPERIMENT.SO, "_user_processes",
                                 side_effect=lambda uid, proc: [123] if uid == 5002 else []), \
                    patch.object(EXPERIMENT.sys, "stderr"):
                with self.assertRaises(RuntimeError):
                    run.setup()
            self.assertTrue(run.uid_shared)
            self.assertTrue(run.owner_created and run.authority_created)

    def test_a_failed_case_still_retires_what_it_started(self):
        with tempfile.TemporaryDirectory() as directory:
            run = _Fake(timeout=5, operator=SimpleNamespace(pw_gid=os.getgid()), owner_gid=os.getgid(),
                        start_authority=lambda *args: (_ for _ in ()).throw(OSError("no authority")))
            with patch.object(EXPERIMENT, "_retire_case", wraps=EXPERIMENT._retire_case) as retire:
                result = EXPERIMENT.drive_case("unit-report", run, Path(directory), 40, "mnt:[1]")
            self.assertEqual(result["error_type"], "CaseFailure")
            retire.assert_called_once()
            sockets = retire.call_args[0][5]
            self.assertTrue(sockets and all(item.fileno() == -1 for item in sockets))


class DocumentTests(unittest.TestCase):
    def test_docs_name_the_unverified_rows(self):
        text = EXPERIMENT_DOC.read_text()
        for phrase in ("Not verified", "sudo", "password prompt", "MemoryMax=", "KillMode=process",
                       "OOMPolicy=continue", "ux"):
            self.assertIn(phrase, text)
        design = DESIGN.read_text()
        self.assertIn("Cases in PR2", design)
        self.assertIn("controlling terminal", design)


if __name__ == "__main__":
    unittest.main()
