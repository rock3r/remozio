import contextlib
import fcntl
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
import time
import unittest
from types import SimpleNamespace
import unittest.mock
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-single-owner-pr2-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_single_owner_pr2_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)
ROOT = SCRIPT.parents[1]
COMMAND_SOURCE = (ROOT / "experiments/linux-single-owner/command2.c").read_text()
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
              "mntNs": "mnt:[4026531832]", "label": "unconfined", "fds": "0 1 2", "sudo": "not-run",
              "passwd": "not-run"}
    report.update(changes)
    return json.dumps(report, separators=(",", ":")).encode() + b"\n"


class TemplateTests(unittest.TestCase):
    def test_profile_renders_one_profile_with_the_ux_rule(self):
        name, text = EXPERIMENT.render_profile(EXPERIMENT.APPARMOR_TEMPLATE.read_text(), TAG, EXPERIMENT.base_for(TAG))
        self.assertEqual(name, "rmzso-owner-" + TAG)
        self.assertTrue(text.startswith("abi <abi/4.0>,\n"))
        base = EXPERIMENT.base_for(TAG)
        lines = text.splitlines()
        # The shim is entered through aa_change_onexec (checked against systemd's label), so it needs
        # mr only; O stays in the profile (ix); the command leaves it (ux), and O's stat of
        # /proc/<K>/exe needs getattr (r) on the command image.
        for rule in (f"  {base}/run/fdshim mr,", f"  {base}/run/owner mrix,", f"  {base}/run/cmd-* ux,",
                     f"  {base}/run/cmd-* r,", f"  {base}/cases/** rw,"):
            self.assertIn(rule, lines)
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
            EXPERIMENT.render_profile(template.replace("cmd-* r,", "cmd-* m,"), TAG, EXPERIMENT.base_for(TAG))
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
                                  "sudo": "not-run", "passwd": "not-run"})

    def test_negative_controls_change_the_values(self):
        self.assertEqual(EXPERIMENT.command_checks(command_report(noNewPrivs="1"), 40, self.MNT, TAG)["noNewPrivs"],
                         "1")
        self.assertEqual(EXPERIMENT.command_checks(command_report(mntNs="mnt:[4026532999]"), 40, self.MNT,
                                                   TAG)["hostMountNamespace"], "no")
        self.assertEqual(EXPERIMENT.command_checks(command_report(capEff="0000000000200000"), 40, self.MNT,
                                                   TAG)["capsEmpty"], "no")
        self.assertEqual(EXPERIMENT.command_checks(command_report(fds="0 1 2 3"), 40, self.MNT, TAG)["commandFds"],
                         "other")
        self.assertEqual(EXPERIMENT.command_checks(command_report(capBnd="000000ffffffffff"), 40, self.MNT,
                                                   TAG)["boundingFull"], "no")

    def test_labels_and_sudo_categories(self):
        label = EXPERIMENT.command_checks(command_report(label=f"rmzso-owner-{TAG} (enforce)"), 40, self.MNT, TAG)
        self.assertEqual(label["commandLabel"], "owner-profile")
        self.assertEqual(EXPERIMENT.command_checks(command_report(label="snap.x (enforce)"), 40, self.MNT,
                                                   TAG)["commandLabel"], "other")
        for category in ("password-required", "allowed", "no-new-privs", "inconclusive"):
            self.assertEqual(EXPERIMENT.command_checks(command_report(sudo=category), 40, self.MNT, TAG)["sudo"],
                             category)
        for category in ("ok", "no-shadow", "failed", "timeout", "no-user"):
            self.assertEqual(EXPERIMENT.command_checks(command_report(passwd=category), 40, self.MNT,
                                                       TAG)["passwd"], category)

    def test_missing_and_invalid_reports(self):
        self.assertEqual(set(EXPERIMENT.command_checks(b"", 40, self.MNT, TAG).values()), {"not-reported"})
        for raw in (command_report(sudo="maybe"), command_report(sudo="timeout"), command_report(passwd="maybe"),
                    command_report(noNewPrivs="2"), command_report() * 2,
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
               b'{"event":"outcome","phase":"succeeded","reason":"none","reported":"dispatched",'
               b'"requesterLost":"no","result":"recorded"}\n{"event":"end"}\n')
        events = EXPERIMENT.authority_events(raw)
        summary, per_dispatch = EXPERIMENT.authority_summary(events, 1)
        self.assertEqual(summary, {"authorityHello": "accepted"})
        self.assertEqual(per_dispatch, [{"authorityPermit": "yes", "authorityPhaseAfterPermit": "executing",
                                         "authorityOutcome": "dispatched", "authorityOutcomeReason": "none",
                                         "authorityPhase": "succeeded"}])
        for bad in (b'{"event":"other"}', b'{"event":"hello","result":"maybe"}',
                    b'{"event":"submit","result":"permit","token":"00"}', b'{"event":"hello","result":1}',
                    b'{"event":"outcome","result":"recorded","reason":"lost"}'):
            with self.assertRaises(ValueError):
                EXPERIMENT.authority_events(bad)

    def test_an_owner_that_died_leaves_the_request_executing(self):
        events = EXPERIMENT.authority_events(b'{"event":"hello","result":"accepted"}\n'
                                             b'{"event":"submit","phase":"executing","result":"permit"}\n')
        _summary, per_dispatch = EXPERIMENT.authority_summary(events, 1)
        self.assertEqual(per_dispatch[0]["authorityOutcome"], "missing")
        self.assertEqual(per_dispatch[0]["authorityPhase"], "executing")
        self.assertEqual(per_dispatch[0]["authorityOutcomeReason"], EXPERIMENT.NA)

    def test_a_dispatch_without_a_command_keeps_its_reason(self):
        # Recorded as failed for the experiment; the report keeps notStarted apart from execFailed.
        events = EXPERIMENT.authority_events(
            b'{"event":"hello","result":"accepted"}\n{"event":"submit","phase":"executing","result":"permit"}\n'
            b'{"event":"outcome","phase":"failed","reason":"notStarted","reported":"notStarted",'
            b'"requesterLost":"no","result":"recorded"}\n')
        _summary, per_dispatch = EXPERIMENT.authority_summary(events, 1)
        self.assertEqual((per_dispatch[0]["authorityPhase"], per_dispatch[0]["authorityOutcomeReason"]),
                         ("failed", "notStarted"))
        self.assertEqual(EXPERIMENT.CONTROL_EXPECT["firstOutcomePhase"], "failed")
        self.assertEqual(EXPERIMENT.CONTROL_EXPECT["firstOutcomeReason"], "notStarted")
        self.assertTrue(any("notStarted" in limit and "distinct outcome" in limit
                            for limit in EXPERIMENT.KNOWN_LIMITS))

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
        self.assertIn('let reason = result == "dispatched" || result == "unknown" ? "none" : result', text)
        self.assertIn('"reason": reason', text)
        self.assertIn("try store.dispatched(token)", text)

    def test_restart_log_per_dispatch(self):
        log = b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 GO\n4 1 DETACH\n5 2 SEIZE\n6 2 INTERRUPT\n7 2 GO\n"
        self.assertEqual(EXPERIMENT.restart_log_clean_all(log, 2), "yes")
        self.assertEqual(EXPERIMENT.restart_log_clean_all(log + b"8 2 DETACH\n9 2 GO\n", 2), "no")
        self.assertEqual(EXPERIMENT.restart_log_clean_all(b"1 3 SEIZE\n", 2), "no")
        # A log that is missing a dispatch is not clean.
        self.assertEqual(EXPERIMENT.restart_log_clean_all(b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 GO\n", 2), "no")
        self.assertEqual(EXPERIMENT.restart_log_clean_all(b"5 2 SEIZE\n6 2 INTERRUPT\n7 2 GO\n", 2), "no")
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
        # 2: passwd -S of the caller with the /etc/shadow fields is the decisive check, with NoNewPrivs 0;
        # sudo -n true is password required, allowed or inconclusive (a FIDO touch through PAM); no
        # sudoers change in the runner.
        for case in ("unit-sudo", "unit-apparmor"):
            expected = cases[case]["expectDispatches"][0]
            self.assertEqual(expected["passwd"], {"ok"})
            self.assertEqual(expected["noNewPrivs"], {"0"})
            self.assertEqual(expected["boundingFull"], {"yes"})
            self.assertEqual(set(expected["sudo"]), {"password-required", "allowed", "inconclusive"})
        # The control asserts on the decisive check and NoNewPrivs, never on sudo's wording.
        control = cases["unit-nnp-control"]["expectDispatches"][0]
        self.assertEqual((control["passwd"], control["noNewPrivs"]), ({"no-shadow", "failed"}, {"1"}))
        self.assertNotIn("sudo", control)
        self.assertNotIn("passwd -S root", COMMAND_SOURCE.replace("passwd -S root is no", ""))
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

    def test_bounding_set_gates_the_command_cases(self):
        for case in ("unit-report", "unit-sudo", "unit-apparmor"):
            observed = observed_for(case)
            self.assertTrue(EXPERIMENT.evaluate(case, observed)["passed"], case)
            observed["dispatches"][0]["boundingFull"] = "no"
            self.assertEqual(EXPERIMENT.evaluate(case, observed)["mismatches"], ["d1.boundingFull"], case)

    def test_nnp_control_ignores_sudo_wording(self):
        for sudo in ("other", "no-new-privs", "password-required", "inconclusive"):
            observed = observed_for("unit-nnp-control")
            observed["dispatches"][0]["sudo"] = sudo
            self.assertTrue(EXPERIMENT.evaluate("unit-nnp-control", observed)["passed"], sudo)
        observed = observed_for("unit-nnp-control")
        observed["dispatches"][0]["passwd"] = "ok"
        self.assertEqual(EXPERIMENT.evaluate("unit-nnp-control", observed)["mismatches"], ["d1.passwd"])
        observed = observed_for("unit-nnp-control")
        observed["dispatches"][0]["noNewPrivs"] = "0"
        self.assertEqual(EXPERIMENT.evaluate("unit-nnp-control", observed)["mismatches"], ["d1.noNewPrivs"])

    def test_a_ledger_error_fails_only_replay_ledger(self):
        events = EXPERIMENT.authority_events(
            b'{"event":"submit","phase":"executing","result":"permit"}\n'
            b'{"event":"submit","ledger":"error","phase":"executing","result":"replay-refused"}\n')
        first = {"firstHello": "OK", "firstPermit": "yes", "replaySubmit": "REFUSED", "firstOutcome": "OK",
                 "replayOutcome": "REFUSED"}
        observed = EXPERIMENT.control_observations(first, {"earlierGenerationHello": "REFUSED",
                                                           "earlierGenerationOutcome": "REFUSED"},
                                                   {"wrongPeer": "REFUSED"}, events)
        self.assertEqual((observed["replayLedger"], observed["replayBinding"]), ("error", EXPERIMENT.NA))
        expect = EXPERIMENT.CONTROL_EXPECT
        observed.update({key: expect[key] for key in expect if key not in ("replayLedger",)})
        result = EXPERIMENT.evaluate("authority-controls", {**observed, "operatorConnect": EXPERIMENT.NA})
        self.assertEqual(result["mismatches"], ["replayLedger"])

    def test_each_refusal_must_carry_the_reason_its_control_tests(self):
        # The refusal alone is no evidence: a stale HELLO refused on the PID, an earlier permit refused as
        # another HELLO of the same process, or a replay that the store accepts fails its control.
        events = EXPERIMENT.authority_events(
            b'{"event":"submit","phase":"executing","result":"permit"}\n'
            b'{"event":"submit","binding":"accepted","ledger":"refused","phase":"executing",'
            b'"result":"replay-refused"}\n'
            b'{"event":"hello","reason":"pid-mismatch","result":"refused"}\n'
            b'{"event":"outcome","reason":"other-hello","result":"generation-refused"}\n'
            b'{"event":"hello","reason":"pid-mismatch","result":"refused"}\n'
            b'{"event":"submit","reason":"no-generation","result":"refused"}\n')
        first = {"firstHello": "OK", "firstPermit": "yes", "replaySubmit": "REFUSED", "firstOutcome": "OK",
                 "replayOutcome": "REFUSED"}
        later = {"earlierGenerationHello": "REFUSED", "earlierGenerationOutcome": "REFUSED",
                 "staleGenerationHello": "REFUSED"}
        zombie = {"zombieHello": "OK", "zombieSubmit": "REFUSED"}
        observed = EXPERIMENT.control_observations(first, later, {"wrongPeer": "REFUSED"}, events, zombie=zombie)
        observed.update(firstOutcomePhase="failed", firstOutcomeReason="notStarted", wrongPeerEvent="wrong-peer")
        result = EXPERIMENT.evaluate("authority-controls", observed)
        self.assertEqual(sorted(result["mismatches"]),
                         ["earlierGenerationEvent", "replayBinding", "staleGenerationReason", "zombieEvent"])

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

    @staticmethod
    def live(pid):
        try:
            text = Path(f"/proc/{pid}/stat").read_text()
        except OSError:
            return False
        return text[text.rindex(")") + 2] not in "ZX"

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
                    if int(words[2]) != pid:
                        self.events.append({"event": "hello", "result": "refused", "reason": "pid-mismatch"})
                    elif int(words[3]) != self.start_time(pid):
                        self.events.append({"event": "hello", "result": "refused", "reason": "stale-generation"})
                    else:
                        generation, reply = tuple(words[1:4]), "OK"
                elif words[0] == "SUBMIT" and generation:
                    if not self.live(pid):
                        self.events.append({"event": "submit", "result": "refused", "reason": "generation-lost"})
                    elif words[1] in self.nonces:
                        self.events.append({"event": "submit", "result": "replay-refused", "ledger": "refused",
                                            "binding": "reserved"})
                    else:
                        self.nonces.add(words[1])
                        token = secrets.token_hex(16)
                        self.permits[token] = [generation, False]
                        reply = f"PERMIT {token} 1 1 normal 0"
                elif words[0] == "OUTCOME" and generation and words[1] in self.permits:
                    permit = self.permits[words[1]]
                    if permit[0] != generation:
                        self.events.append({"event": "outcome", "result": "generation-refused",
                                            "reason": "earlier-generation"})
                    elif not permit[1]:
                        permit[1], reply = True, "OK"
                        reason = "none" if words[2] in ("dispatched", "unknown") else words[2]
                        self.events.append({"event": "outcome", "result": "recorded", "reported": words[2],
                                            "reason": reason, "requesterLost": words[3],
                                            "phase": "failed" if reason != "none" else "succeeded"})
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
                first, later, wrong_reply, zombie, operator = EXPERIMENT.run_controls(
                    Path(directory) / "a.sock", {}, {}, wrong_socket=Path(directory) / "b.sock")
            finally:
                good.close()
                wrong.close()
            observed = EXPERIMENT.control_observations(first, later, wrong_reply, good.events + wrong.events,
                                                       zombie=zombie)
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
            self.assertEqual(checks["passwd"], "not-run")
            self.assertEqual(checks["hostMountNamespace"], "yes")
            # The command's own reserved-free exit codes: never 120-123.
            self.assertIsNone(re.search(r"return 12[0-3]|_exit\(12[0-3]\)", EXPERIMENT.COMMAND.read_text()))

    def test_command_fixture_with_fake_passwd_and_sudo(self):
        # Fakes only: PATH holds just the fake directory, so the real sudo and passwd never run.
        compiler = shutil.which("cc")
        if not LINUX or compiler is None or not Path("/bin/sleep").exists():
            self.skipTest("needs a Linux C compiler")
        with tempfile.TemporaryDirectory() as directory:
            fakes = Path(directory) / "fakes"
            fakes.mkdir()
            (fakes / "passwd").write_text('#!/bin/sh\n[ "$1" = "-S" ] && [ -n "$2" ] && '
                                          'echo "$2 P 2025-01-01 0 99999 7 -1" && exit 0\nexit 3\n')
            # A sudo that waits, as for a FIDO touch through PAM.
            (fakes / "sudo").write_text("#!/bin/sh\nexec /bin/sleep 30\n")
            for fake in fakes.iterdir():
                fake.chmod(0o755)
            binary = Path(directory) / "cmd-sudo"
            subprocess.run([compiler, *EXPERIMENT.SO.CC_FLAGS, "-o", str(binary), str(EXPERIMENT.COMMAND)],
                           check=True, capture_output=True)
            marker = Path(directory) / "marker"
            started = time.monotonic()
            result = subprocess.run([str(binary), "normal", str(marker)], capture_output=True, timeout=20,
                                    stdin=subprocess.DEVNULL, env={"PATH": str(fakes)})
            elapsed = time.monotonic() - started
            self.assertEqual(result.returncode, 0)
            checks = EXPERIMENT.command_checks(result.stdout, int(Path("/proc/sys/kernel/cap_last_cap").read_text()),
                                               os.readlink("/proc/self/ns/mnt"), TAG)
            self.assertEqual((checks["passwd"], checks["sudo"], checks["noNewPrivs"]), ("ok", "inconclusive", "0"))
            self.assertGreaterEqual(elapsed, 5)
            self.assertLess(elapsed, 15)
            (fakes / "passwd").write_text("#!/bin/sh\nexit 1\n")
            (fakes / "sudo").write_text("#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")
            result = subprocess.run([str(binary), "normal", str(marker)], capture_output=True, timeout=20,
                                    stdin=subprocess.DEVNULL, env={"PATH": str(fakes)})
            checks = EXPERIMENT.command_checks(result.stdout, 40, None, TAG)
            self.assertEqual((checks["passwd"], checks["sudo"]), ("failed", "password-required"))


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
        run.ids_picked, run.owner_uid, run.owner_gid, run.authority_uid = True, 0x70000001, 0x70000001, 0x70000002
        calls = []

        def retire(unit):
            calls.append(("retire", unit))
            raise RuntimeError("systemctl failed")

        with tempfile.TemporaryDirectory() as directory:
            records = [Path(directory) / name for name in ("a.user", "1.user")]
            for path in records:
                path.write_text("{}")
            run.userdb_files = list(records)
            with patch.object(run, "retire_unit", side_effect=retire), \
                    patch.object(run, "_remove_profile", side_effect=lambda: calls.append(("profile",)) or True), \
                    patch.object(EXPERIMENT, "kill_id", side_effect=lambda number: calls.append(("kill", number))
                                 or True), \
                    patch.object(EXPERIMENT.PL, "_absent", return_value=True):
                result = run.cleanup()
            self.assertFalse(any(path.exists() for path in records))
        self.assertEqual([call[0] for call in calls[:3]], ["retire", "retire", "profile"])
        self.assertEqual([call for call in calls if call[0] == "kill"], [("kill", 0x70000001), ("kill", 0x70000002)])
        self.assertFalse(result["unitsRemoved"])
        self.assertTrue(result["identityRecordsRemoved"])
        self.assertNotIn("userdel", SCRIPT.read_text())
        self.assertNotIn("useradd", SCRIPT.read_text())

    def test_ids_never_picked_are_never_killed(self):
        run = self.make_run()
        with patch.object(EXPERIMENT, "kill_id") as kill:
            result = run.cleanup()
        kill.assert_not_called()
        self.assertTrue(result["serviceProcessesGone"])

    def test_kill_id_refuses_a_number_outside_the_disposable_range(self):
        for number in (0, 1000, EXPERIMENT.ID_BASE - 1, EXPERIMENT.ID_BASE + EXPERIMENT.ID_SPAN):
            with self.assertRaises(ValueError):
                EXPERIMENT.kill_id(number)

    def test_setup_refuses_an_operator_who_can_read_shadow(self):
        run = self.make_run()
        with patch.object(EXPERIMENT, "cgroup_v2_ready", return_value=True), \
                patch.object(EXPERIMENT, "nss_systemd_enabled", return_value=True), \
                patch.object(EXPERIMENT.NSSWITCH.__class__, "read_text", return_value=""), \
                patch.object(EXPERIMENT.os, "getgrouplist", return_value=[1000]), \
                patch.object(run, "operator_reads_shadow", return_value=True), \
                patch.object(EXPERIMENT.os, "mkdir") as mkdir:
            with self.assertRaises(RuntimeError):
                run.setup()
        mkdir.assert_not_called()

    def test_setup_refuses_a_host_without_nss_systemd(self):
        run = self.make_run()
        with patch.object(EXPERIMENT, "cgroup_v2_ready", return_value=True), \
                patch.object(EXPERIMENT.NSSWITCH.__class__, "read_text", return_value="passwd: files\ngroup: files\n"), \
                patch.object(EXPERIMENT.os, "mkdir") as mkdir:
            with self.assertRaises(RuntimeError):
                run.setup()
        mkdir.assert_not_called()

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


class RetireUnitTests(unittest.TestCase):
    """retire_unit reports a removal only on positive evidence; every failure counts as not removed."""

    def retire(self, procs=None, read_error=None, show=None, stop_code=0):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = EXPERIMENT.Run(operator, 30, "/bin/true", {name: f"/usr/bin/{name}" for name in EXPERIMENT.TOOLS})
        run.RETIRE_SECONDS = 0.1
        unit = f"rmzso-{run.tag}-x.service"
        calls, killed = [], []
        with tempfile.TemporaryDirectory() as directory:
            cgroup = Path(directory)
            if procs is not None:
                (cgroup / unit).mkdir()
                (cgroup / unit / "cgroup.procs").write_text(procs)
                (cgroup / unit / "cgroup.kill").write_text("")
            patches = [patch.object(EXPERIMENT, "CGROUP_SYSTEM", cgroup),
                       patch.object(run, "systemctl", side_effect=lambda *args: calls.append(args) or stop_code),
                       patch.object(run, "show", return_value=dict(show if show is not None
                                                                   else {"LoadState": "not-found"})),
                       patch.object(EXPERIMENT.os, "kill", side_effect=lambda pid, sig: killed.append(pid))]
            if read_error is not None:
                patches.append(patch.object(EXPERIMENT.SO, "read_bounded", side_effect=read_error))
            for item in patches:
                item.start()
            try:
                result = run.retire_unit(unit)
                if procs is not None:
                    killed.extend(["cgroup.kill"] if (cgroup / unit / "cgroup.kill").read_text() == "1" else [])
            finally:
                for item in reversed(patches):
                    item.stop()
        return result, calls, killed, unit

    def test_a_gone_unit_with_no_cgroup_is_removed(self):
        result, calls, killed, unit = self.retire()
        self.assertTrue(result)
        self.assertEqual(calls, [("stop", unit), ("reset-failed", unit)])
        self.assertEqual(killed, [])

    def test_an_unloaded_unit_counts_even_when_stop_fails(self):
        # systemctl stop and reset-failed fail for a unit that systemd already unloaded.
        self.assertTrue(self.retire(stop_code=5)[0])

    def test_a_cgroup_read_error_is_not_removed(self):
        result, _calls, killed, _unit = self.retire(procs="", read_error=PermissionError())
        self.assertFalse(result)
        self.assertEqual(killed, ["cgroup.kill"])  # the kernel kills; no PID is signalled from a read

    def test_a_read_error_stops_the_kill_loop_at_once(self):
        # Unreadable cgroup: the wait reads once and goes straight to systemctl; the readback fails.
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = EXPERIMENT.Run(operator, 30, "/bin/true", {})
        run.RETIRE_SECONDS = 0.05
        events = []
        with patch.object(EXPERIMENT, "kill_cgroup", side_effect=lambda path: events.append("kill") or True), \
                patch.object(run, "cgroup_pids", side_effect=lambda unit: events.append("read")), \
                patch.object(run, "systemctl", side_effect=lambda *args: events.append("systemctl") or 0), \
                patch.object(run, "show", return_value={"LoadState": "not-found"}), \
                patch.object(EXPERIMENT.time, "sleep", side_effect=lambda seconds: events.append("sleep")):
            self.assertFalse(run.retire_unit("u"))
        self.assertEqual(events[:4], ["kill", "read", "systemctl", "systemctl"])

    def test_a_failed_show_is_not_removed(self):
        self.assertFalse(self.retire(show={})[0])

    def test_a_loaded_unit_after_a_failed_stop_is_not_removed(self):
        self.assertFalse(self.retire(stop_code=1, show={"LoadState": "loaded"})[0])

    def test_a_surviving_process_is_not_removed(self):
        result, _calls, killed, _unit = self.retire(procs="4242\n")
        self.assertFalse(result)
        self.assertEqual(killed, ["cgroup.kill"])  # killed through cgroup.kill, never by a PID read from procs

    def test_an_empty_cgroup_is_removed(self):
        self.assertTrue(self.retire(procs="")[0])


class CgroupTests(unittest.TestCase):
    def test_cgroup_v2_needs_the_unified_root_and_system_slice(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(EXPERIMENT.cgroup_v2_ready(root))
            (root / "cgroup.controllers").write_text("cpu memory\n")
            self.assertFalse(EXPERIMENT.cgroup_v2_ready(root))
            (root / "system.slice").mkdir()
            self.assertFalse(EXPERIMENT.cgroup_v2_ready(root))  # no cgroup.kill: before Linux 5.14
            (root / "system.slice/cgroup.kill").write_text("")
            self.assertTrue(EXPERIMENT.cgroup_v2_ready(root))

    def test_kill_cgroup_writes_one_and_treats_a_gone_cgroup_as_killed(self):
        with tempfile.TemporaryDirectory() as directory:
            cgroup = Path(directory) / "u.service"
            self.assertTrue(EXPERIMENT.kill_cgroup(cgroup))
            cgroup.mkdir()
            (cgroup / "cgroup.kill").write_text("")
            self.assertTrue(EXPERIMENT.kill_cgroup(cgroup))
            self.assertEqual((cgroup / "cgroup.kill").read_text(), "1")
            (cgroup / "cgroup.kill").chmod(0o400)
            if os.geteuid() != 0:
                self.assertFalse(EXPERIMENT.kill_cgroup(cgroup))

    def test_the_unit_cgroup_must_be_under_system_slice(self):
        unit = f"rmzso-{TAG}-x.service"
        self.assertTrue(EXPERIMENT.unit_cgroup_ok({"ControlGroup": f"/system.slice/{unit}"}, unit))
        for value in (f"/user.slice/{unit}", f"/system.slice/other.service", "", None):
            self.assertFalse(EXPERIMENT.unit_cgroup_ok({"ControlGroup": value} if value is not None else {}, unit))
        self.assertIn('if not unit_cgroup_ok(self.show(unit, ("ControlGroup",)), unit):', SCRIPT.read_text())

    def test_setup_refuses_a_host_without_cgroup_v2(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = EXPERIMENT.Run(operator, 30, "/bin/true", {})
        with patch.object(EXPERIMENT, "cgroup_v2_ready", return_value=False), \
                patch.object(EXPERIMENT.os, "mkdir") as mkdir:
            with self.assertRaises(RuntimeError):
                run.setup()
        mkdir.assert_not_called()
        self.assertFalse(run.base_created)


class SelftestSocketTests(unittest.TestCase):
    def test_socket_directory_is_short(self):
        directory = EXPERIMENT.selftest_socket_dir()
        try:
            self.assertLess(len(str(directory / "a.sock").encode()), EXPERIMENT.UNIX_PATH_MAX)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        finally:
            shutil.rmtree(directory)

    @unittest.skipUnless(LINUX, "needs Unix sockets")
    def test_a_long_work_dir_still_binds(self):
        # The work directory is far beyond sun_path; the sockets must not live in it.
        bound = []

        class Process:
            def __init__(self, binary, listener, *args, **options):
                bound.append(listener.getsockname())

            def stop(self):
                return b""

            def kill(self):
                return True

        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / ("w" * 150)
            empty = {}
            with patch.object(EXPERIMENT, "AuthorityProcess", Process), \
                    patch.object(EXPERIMENT, "run_controls",
                                 return_value=(empty, empty, empty, empty, EXPERIMENT.NA)), \
                    patch.object(EXPERIMENT, "run_client", return_value={}):
                result = EXPERIMENT.authority_selftest(work, binary="/bin/true")
        self.assertEqual(len(bound), 3)
        self.assertFalse(result["retryNextDirectory"])
        self.assertTrue(result["runtimeSystemOnly"])  # /bin/true loads only system libraries
        self.assertFalse(result["passed"])
        for path in bound:
            self.assertLess(len(path.encode()), EXPERIMENT.UNIX_PATH_MAX)
            self.assertFalse(Path(path).parent.exists())


AUTHORITY_OK = (b'{"event":"start"}\n{"event":"peer","result":"owner"}\n{"event":"hello","result":"accepted"}\n'
                b'{"event":"submit","phase":"executing","result":"permit"}\n'
                b'{"event":"outcome","phase":"succeeded","reason":"none","reported":"dispatched",'
                b'"requesterLost":"no","result":"recorded"}\n{"event":"end"}\n')


class FakeUnitOwner:
    """O as a thread: it sends barriers over the control socket and writes its reports."""

    def __init__(self, pid, unit, thread):
        self.pid, self.unit, self.thread = pid, unit, thread
        self.stdout, self.returncode, self.killed = None, None, False

    def poll(self):
        if self.returncode is None and not self.thread.is_alive():
            self.returncode = 0
        return self.returncode

    def wait(self, timeout):
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise subprocess.TimeoutExpired("owner", timeout)
        return self.poll()

    def kill(self):
        self.killed = True

    def close(self):
        if self.stdout is not None:
            self.stdout.close()


def fake_owner(stdout_fd, control_fd, log_fd, barriers, lines, log):
    control = socket.socket(fileno=control_fd)
    try:
        for name, number, c_pid, k_pid in barriers:
            control.send(f"BARRIER {name} {number} {c_pid} {k_pid}".encode())
            if control.recv(16) != b"C":
                break
        os.write(log_fd, log)
        os.write(stdout_fd, b"\n".join(lines) + b"\n")
    finally:
        control.close()
        os.close(stdout_fd)
        os.close(log_fd)


class FakeAuthorityProcess:
    def __init__(self, output):
        self.output = output

    def read_available(self):
        pass

    def stop(self):
        return self.output

    def kill(self):
        return True


@unittest.skipUnless(LINUX, "needs Linux procfs and Unix sockets")
class DriveCaseTests(unittest.TestCase):
    MNT = "mnt:[4026531832]"

    def drive(self, report=None, case="unit-report"):
        nr_open = int(Path("/proc/sys/fs/nr_open").read_text())
        limits = ",".join(["inf/inf"] * 7 + [f"{nr_open}/{nr_open}"] + ["inf/inf"] * 8)
        report = report if report is not None else command_report()
        barriers = [("start", 1, 0, 0), ("k-ready", 1, 999991, 999992), ("after-s6", 1, 999991, 999992),
                    ("end", 1, 0, 0)]
        lines = [START, dispatch_line(1)]
        log = b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 GO\n4 1 DETACH\n"
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            markers = directory / "markers"
            markers.mkdir()
            (markers / case).write_text("ran\n")
            (directory / "case").mkdir()
            started = []

            def start_owner(case_name, spec, case_directory, fds):
                stdout_write, _listener, control_owner, log_fd = fds
                thread = threading.Thread(target=fake_owner, daemon=True,
                                          args=(os.dup(stdout_write), os.dup(control_owner), os.dup(log_fd),
                                                barriers, lines, log))
                owner = FakeUnitOwner(4242, f"rmzso-{TAG}-{case_name}.service", thread)
                started.append(owner)
                thread.start()
                return owner

            def show(unit, properties):
                if tuple(properties) == ("MainPID",):
                    return {"MainPID": "4242"}
                if tuple(properties) == EXPERIMENT.SHOW_PROPERTIES:
                    return dict(EXPERIMENT.SHOW_EXPECTED)
                return {}

            def start_frontend(_path):
                # C ends with its command; the fake has ended before the runner reads its line.
                frontend = subprocess.Popen([sys.executable, "-I", "-c",
                                             f"import sys; sys.stdout.buffer.write({report!r})"],
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                frontend.wait(timeout=10)
                return frontend

            run = SimpleNamespace(timeout=10, operator=SimpleNamespace(pw_gid=os.getgid(), pw_uid=os.getuid()),
                                  owner_gid=os.getgid(), owner_uid=os.getuid(), markers=markers, tag=TAG,
                                  start_authority=lambda *args: FakeAuthorityProcess(AUTHORITY_OK),
                                  start_owner=start_owner, show=show, start_frontend=start_frontend,
                                  systemctl=lambda *args: 0, retire_unit=lambda unit: True)
            ended = []
            with patch.object(EXPERIMENT.SO, "read_limits", return_value=limits), \
                    patch.object(EXPERIMENT.SO, "_end_session", side_effect=ended.append), \
                    patch.object(EXPERIMENT.SO, "_reap", return_value=True), \
                    patch.object(EXPERIMENT, "_wait_gone"):
                result = EXPERIMENT.drive_case(case, run, directory / "case", 40, self.MNT)
        self.assertTrue(started and started[0].killed)
        self.assertEqual(ended, [999992])
        return result

    def test_happy_path_passes(self):
        result = self.drive()
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["cleanupReapedAllFixtureProcesses"])
        observed = result["observed"]
        self.assertEqual((observed["ownerExit"], observed["unitReadback"], observed["restartLogClean"],
                          observed["markerLines"]), ("ok", "yes", "yes", "1"))
        self.assertEqual(observed["dispatches"][0]["frontendExit"], "closed")
        self.assertEqual(observed["dispatches"][0]["boundingFull"], "yes")

    def test_a_reduced_bounding_set_fails(self):
        result = self.drive(command_report(capBnd="000000ffffffffff"))
        self.assertFalse(result["passed"])
        self.assertEqual(result["mismatches"], ["d1.boundingFull"])


class ActTests(unittest.TestCase):
    def owner(self, returncode):
        owner = SimpleNamespace(unit=f"rmzso-{TAG}-x.service", pid=4242, returncode=None, killed=False)
        owner.kill = lambda: setattr(owner, "killed", True)
        owner.wait = lambda timeout: setattr(owner, "returncode", returncode) or returncode
        owner.poll = lambda: owner.returncode
        return owner

    def run_fake(self, show=None):
        calls = []
        return SimpleNamespace(systemctl=lambda *args: calls.append(args) or 0,
                               show=lambda unit, props: dict(show or {}), calls=calls)

    def test_kill_owner_stops_the_barrier_loop(self):
        owner, observed = self.owner(-9), {}
        self.assertFalse(EXPERIMENT._act("kill-owner", self.run_fake(), owner, {"k": {}}, observed, time.monotonic() + 5))
        self.assertTrue(owner.killed)
        self.assertEqual(observed["ownerExit"], "SIGKILL")

    def test_unit_stop_and_restart(self):
        with patch.object(EXPERIMENT, "_alive", return_value=True):
            observed, run = {}, self.run_fake()
            self.assertFalse(EXPERIMENT._act("unit-stop", run, self.owner(-15), {"k": {1: 77}}, observed,
                                             time.monotonic() + 5))
            self.assertEqual(run.calls, [("stop", f"rmzso-{TAG}-x.service")])
            self.assertEqual((observed["ownerExit"], observed["commandAliveAfterStop"],
                              observed["ownerGoneAfterUnitAction"]), ("SIGTERM", "yes", "yes"))
            observed = {}
            EXPERIMENT._act("unit-restart", self.run_fake({"ExecMainPID": "5000"}), self.owner(-15), {"k": {1: 77}},
                            observed, time.monotonic() + 5)
            self.assertEqual((observed["unitRestarted"], observed["commandAliveAfterRestart"]), ("yes", "yes"))
            observed = {}
            EXPERIMENT._act("unit-restart", self.run_fake({"ExecMainPID": "4242"}), self.owner(-15), {"k": {1: 77}},
                            observed, time.monotonic() + 5)
            self.assertEqual(observed["unitRestarted"], "no")

    def oom(self, events):
        with tempfile.TemporaryDirectory() as directory:
            cgroup = Path(directory)
            unit = f"rmzso-{TAG}-x.service"
            if events is not None:
                (cgroup / unit).mkdir()
                (cgroup / unit / "memory.events").write_text(events)
            observed = {}
            with patch.object(EXPERIMENT, "CGROUP_SYSTEM", cgroup), patch.object(EXPERIMENT, "_wait_gone"), \
                    patch.object(EXPERIMENT, "_alive", return_value=True):
                resume = EXPERIMENT._act("oom-check", self.run_fake({"ActiveState": "active", "Result": "success"}),
                                         self.owner(0), {"k": {1: 77, 2: 78}}, observed, time.monotonic() + 5)
        self.assertTrue(resume)
        return observed

    def test_oom_check_parses_memory_events(self):
        observed = self.oom("low 0\nhigh 0\nmax 12\noom 1\noom_kill 1\noom_group_kill 0\n")
        self.assertEqual((observed["oomKill"], observed["ownerAliveAfterOom"], observed["commandAliveAfterOom"],
                          observed["unitActiveAfterOom"]), ("yes", "yes", "yes", "yes"))
        self.assertEqual(self.oom("oom 1\noom_kill 0\n")["oomKill"], "no")
        self.assertEqual(self.oom("oom_kill x\n")["oomKill"], "no")
        self.assertEqual(self.oom(None)["oomKill"], "no")

    def test_unknown_action(self):
        with self.assertRaises(ValueError):
            EXPERIMENT._act("reboot", None, None, {}, {}, 0)


class UnitOwnerTests(unittest.TestCase):
    def exit_code(self, values):
        owner = EXPERIMENT.UnitOwner(4242, -1, None, f"rmzso-{TAG}-x.service", lambda unit, props: dict(values))
        owner.EXIT_WAIT = 0.1
        return owner._exit_code()

    def test_exec_main_code_mapping(self):
        # CLD_EXITED 1: the status is the exit code; CLD_KILLED 2 and CLD_DUMPED 3: the status is a signal.
        self.assertEqual(self.exit_code({"ExecMainPID": "4242", "ExecMainCode": "1", "ExecMainStatus": "0"}), 0)
        self.assertEqual(self.exit_code({"ExecMainPID": "4242", "ExecMainCode": "1", "ExecMainStatus": "3"}), 3)
        self.assertEqual(self.exit_code({"ExecMainPID": "4242", "ExecMainCode": "2", "ExecMainStatus": "9"}), -9)
        self.assertEqual(self.exit_code({"ExecMainPID": "4242", "ExecMainCode": "3", "ExecMainStatus": "6"}), -6)
        # Another main PID, or no end recorded yet: 255 after the wait.
        self.assertEqual(self.exit_code({"ExecMainPID": "5000", "ExecMainCode": "1", "ExecMainStatus": "0"}), 255)
        self.assertEqual(self.exit_code({"ExecMainPID": "4242", "ExecMainCode": "0"}), 255)
        self.assertEqual(self.exit_code({}), 255)

    def test_exit_categories(self):
        self.assertEqual([EXPERIMENT.exit_category(code) for code in (None, 0, 3, 4, -9, -15, -6, 255)],
                         ["running", "ok", "refused", "usage", "SIGKILL", "SIGTERM", "other", "other"])

    def test_close_without_stdout(self):
        EXPERIMENT.UnitOwner(4242, -1, None, "u", lambda *args: {}).close()


def compile_fixture(source, output, static=False):
    compiler = shutil.which("cc")
    if not LINUX or compiler is None:
        raise unittest.SkipTest("needs a Linux C compiler")
    subprocess.run([compiler, *EXPERIMENT.SO.CC_FLAGS, *(("-static",) if static else ()), "-o", str(output),
                    str(source)], check=True, capture_output=True)


SHIM_TARGET = r"""
import json, os, sys
fds = {}
for name in os.listdir("/proc/self/fd"):
    try:
        fds[name] = os.readlink("/proc/self/fd/" + name)
    except OSError:
        pass
environ = open("/proc/self/environ", "rb").read().decode()
os.write(1, json.dumps({"fds": fds, "environ": environ, "argv": sys.argv[1:]}).encode())
"""


@unittest.skipUnless(LINUX, "needs Linux SEQPACKET sockets and close_range")
class FdshimTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.shim = Path(cls.directory.name) / "fdshim"
        compile_fixture(EXPERIMENT.FDSHIM, cls.shim)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def serve(self, path, message, fds):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(10)
        hello = []

        def accept():
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with connection:
                hello.append(connection.recv(16))
                socket.send_fds(connection, [message], fds)
                connection.recv(1)

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        return listener, thread, hello

    def run_shim(self, arguments, pass_fds=()):
        return subprocess.run([str(self.shim), *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=20, pass_fds=pass_fds)

    def test_descriptors_land_on_1_3_4_5_with_an_empty_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            read_end, write_end = os.pipe()
            stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            control, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            log = open(directory / "restart.log", "wb")
            extra = os.open(directory / "extra", os.O_WRONLY | os.O_CREAT, 0o600)
            high = fcntl.fcntl(extra, fcntl.F_DUPFD, 200)
            sent = [write_end, stream.fileno(), control.fileno(), log.fileno()]
            expected = {str(target): os.readlink(f"/proc/self/fd/{fd}") for target, fd in zip((1, 3, 4, 5), sent)}
            listener, thread, hello = self.serve(directory / "shim.sock", b"FDS\n", sent)
            try:
                result = self.run_shim([str(directory / "shim.sock"), sys.executable, "-I", "-c", SHIM_TARGET,
                                        "argument"], pass_fds=(high,))
                thread.join(10)
                os.close(write_end)
                output = b""
                while chunk := os.read(read_end, 65536):
                    output += chunk
            finally:
                listener.close()
                for item in (stream, control, control_peer, log):
                    item.close()
                for fd in (read_end, extra, high):
                    with contextlib.suppress(OSError):
                        os.close(fd)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(hello, [b"SHIM\n"])
            report = json.loads(output)
            self.assertEqual(report["environ"], "")
            self.assertEqual(report["argv"], ["argument"])
            for target, link in expected.items():
                self.assertEqual(report["fds"][target], link, target)
            self.assertNotIn(str(high), report["fds"])
            # Only 0-5 and the directory that listed them.
            others = {name: link for name, link in report["fds"].items() if int(name) > 5}
            self.assertTrue(all(link.endswith("/fd") for link in others.values()), others)

    def test_failure_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            self.assertEqual(self.run_shim([]).returncode, 4)
            self.assertEqual(self.run_shim(["x" * 200, "/bin/true"]).returncode, 4)
            self.assertEqual(self.run_shim([str(directory / "missing.sock"), "/bin/true"]).returncode, 11)
            fds = [os.open("/dev/null", os.O_RDONLY) for _ in range(4)]
            try:
                for name, message, sent, image, code in (
                        ("wrong.sock", b"NOPE", fds, "/bin/true", 12),
                        ("three.sock", b"FDS\n", fds[:3], "/bin/true", 12),
                        ("exec.sock", b"FDS\n", fds, str(directory / "missing-image"), 14)):
                    listener, thread, _hello = self.serve(directory / name, message, sent)
                    try:
                        self.assertEqual(self.run_shim([str(directory / name), image]).returncode, code, name)
                        thread.join(10)
                    finally:
                        listener.close()
            finally:
                for fd in fds:
                    os.close(fd)


@unittest.skipUnless(LINUX, "needs Linux procfs")
class CommandClassificationTests(unittest.TestCase):
    """command2.c with fake passwd and sudo on PATH; the real sudo and passwd never run."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        compile_fixture(EXPERIMENT.COMMAND, root / "cmd-sudo")
        for name in ("cmd-prompt", "cmd-report"):
            shutil.copy(root / "cmd-sudo", root / name)
        cls.root = root
        cls.fakes = root / "fakes"
        cls.fakes.mkdir()

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_command(self, name, passwd="#!/bin/sh\nexit 1\n", sudo="#!/bin/sh\nexit 1\n", mode="normal",
                    pass_fds=()):
        (self.fakes / "passwd").write_text(passwd)
        (self.fakes / "sudo").write_text(sudo)
        for fake in self.fakes.iterdir():
            fake.chmod(0o755)
        marker = self.root / f"marker-{secrets.token_hex(4)}"
        result = subprocess.run([str(self.root / name), mode, str(marker)], capture_output=True, timeout=20,
                                stdin=subprocess.DEVNULL, env={"PATH": str(self.fakes)}, pass_fds=pass_fds)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text(), "ran\n")
        return result.stdout

    def report(self, name, **options):
        return json.loads(self.run_command(name, **options))

    def test_sudo_categories(self):
        def says(text, code=1):
            return f"#!/bin/sh\necho '{text}' >&2\nexit {code}\n"
        cases = {
            "sudo: a password is required": "password-required",
            "sudo: The no new privileges flag is set, which prevents sudo from running as root.": "no-new-privs",
            "sudo: effective uid is not 0, is /usr/bin/sudo on a file system with nosuid?": "not-setuid",
            "sudo: a terminal is required to read the password": "terminal-required",
            "sudo: no tty present and no askpass program specified": "terminal-required",
            "operator is not in the sudoers file.": "not-permitted",
            "sudo: an unexpected message about a tty-like terminal": "other",
        }
        for text, category in cases.items():
            self.assertEqual(self.report("cmd-sudo", sudo=says(text))["sudo"], category, text)
        self.assertEqual(self.report("cmd-sudo", sudo="#!/bin/sh\nexit 0\n")["sudo"], "allowed")

    def test_stderr_after_the_helper_is_reaped_is_kept(self):
        # The helper exits at once; a descendant writes the message later. The pipe is drained to end
        # of file after the reap, so the message is not lost.
        if not Path("/bin/sleep").exists():
            self.skipTest("needs /bin/sleep")
        sudo = "#!/bin/sh\n( /bin/sleep 0.3; echo 'sudo: a password is required' >&2 ) &\nexit 1\n"
        self.assertEqual(self.report("cmd-sudo", sudo=sudo)["sudo"], "password-required")

    def test_passwd_needs_the_shadow_fields(self):
        def prints(line):
            return f'#!/bin/sh\necho "$2 {line}"\nexit 0\n'
        self.assertEqual(self.report("cmd-sudo", passwd=prints("P 2025-01-01 0 99999 7 -1"))["passwd"], "ok")
        self.assertEqual(self.report("cmd-sudo", passwd=prints("P"))["passwd"], "no-shadow")
        self.assertEqual(self.report("cmd-sudo", passwd=prints("P 2025-01-01"))["passwd"], "other")
        self.assertEqual(self.report("cmd-sudo", passwd="#!/bin/sh\necho other 1 2 3 4 5 6\nexit 0\n")["passwd"],
                         "other")
        self.assertEqual(self.report("cmd-sudo", passwd="#!/bin/sh\nexit 1\n")["passwd"], "failed")

    def test_prompt_and_report_names(self):
        prompt = self.report("cmd-prompt", sudo="#!/bin/sh\n[ \"$1\" = -n ] && exit 9\n"
                                                "echo 'sudo: a terminal is required to read the password' >&2\nexit 1\n")
        self.assertEqual((prompt["sudo"], prompt["passwd"]), ("terminal-required", "not-run"))
        report = self.report("cmd-report")
        self.assertEqual((report["sudo"], report["passwd"]), ("not-run", "not-run"))

    def test_short_mode_reports_nothing(self):
        self.assertEqual(self.run_command("cmd-report", mode="short"), b"")

    def test_descriptors_are_listed_in_order(self):
        low = os.open("/dev/null", os.O_RDONLY)
        high = fcntl.fcntl(low, fcntl.F_DUPFD, 300)
        middle = fcntl.fcntl(low, fcntl.F_DUPFD, 200)
        try:
            report = self.report("cmd-report", pass_fds=(high, middle))
        finally:
            for fd in (low, high, middle):
                os.close(fd)
        self.assertEqual(report["fds"], f"0 1 2 {middle} {high}")


class IdentityTests(unittest.TestCase):
    """Numeric disposable identities with no /etc entry (Toni's item 2)."""

    def test_subordinate_ranges(self):
        self.assertEqual(EXPERIMENT.parse_subids(["a:100000:65536\n# x\nbad\n", "b:200000:10\n"]),
                         [(100000, 65536), (200000, 10)])

    def test_an_id_is_unused_only_without_entry_range_or_process(self):
        number = EXPERIMENT.ID_BASE + 5
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            missing = patch.object(EXPERIMENT.pwd, "getpwuid", side_effect=KeyError(number))
            missing_group = patch.object(EXPERIMENT.grp, "getgrgid", side_effect=KeyError(number))
            with missing, missing_group:
                self.assertTrue(EXPERIMENT.id_unused(number, proc))
                self.assertFalse(EXPERIMENT.id_unused(1000, proc))  # outside the range
                self.assertFalse(EXPERIMENT.id_unused(number, proc, [(EXPERIMENT.ID_BASE, 10)]))
                (proc / "77").mkdir()
                (proc / "77/status").write_text(f"Name:\tx\nUid:\t1\t1\t1\t1\nGid:\t2\t2\t{number}\t2\n")
                self.assertFalse(EXPERIMENT.id_unused(number, proc))  # a saved GID counts
            with patch.object(EXPERIMENT.pwd, "getpwuid", return_value=object()), missing_group:
                self.assertFalse(EXPERIMENT.id_unused(number, Path(directory) / "none"))

    def test_pick_ids_gives_two_distinct_unused_numbers(self):
        values = iter([3, 3, 4, 9])
        picked = EXPERIMENT.pick_ids(lambda number: number != EXPERIMENT.ID_BASE + 4, randbelow=lambda span: next(values))
        self.assertEqual(picked, (EXPERIMENT.ID_BASE + 3, EXPERIMENT.ID_BASE + 9))
        with self.assertRaises(RuntimeError):
            EXPERIMENT.pick_ids(lambda number: False, attempts=3)

    def test_nss_systemd_must_serve_passwd_and_group(self):
        self.assertTrue(EXPERIMENT.nss_systemd_enabled("passwd: files systemd sss\ngroup: files systemd\n"))
        self.assertFalse(EXPERIMENT.nss_systemd_enabled("passwd: files systemd\ngroup: files\n"))
        self.assertFalse(EXPERIMENT.nss_systemd_enabled("passwd: files # systemd\ngroup: files systemd\n"))

    def test_drop_in_records(self):
        user, group = EXPERIMENT.userdb_records(f"rmzso{TAG}", EXPERIMENT.ID_BASE + 1)
        self.assertEqual(json.loads(user), {"userName": f"rmzso{TAG}", "uid": EXPERIMENT.ID_BASE + 1,
                                            "gid": EXPERIMENT.ID_BASE + 1, "homeDirectory": "/",
                                            "shell": "/usr/sbin/nologin", "locked": True})
        self.assertEqual(json.loads(group), {"groupName": f"rmzso{TAG}", "gid": EXPERIMENT.ID_BASE + 1})

    def test_the_unit_runs_as_the_number(self):
        properties = EXPERIMENT.unit_properties(EXPERIMENT.ID_BASE + 1, EXPERIMENT.ID_BASE + 1)
        self.assertEqual(properties[:2], [f"User={EXPERIMENT.ID_BASE + 1}", f"Group={EXPERIMENT.ID_BASE + 1}"])
        self.assertIn("unit_properties(self.owner_uid, self.owner_gid,", SCRIPT.read_text())


class LoaderTests(unittest.TestCase):
    """The authority must start as its own identity (Toni's item 3)."""

    TRACE = ("\tlinux-vdso.so.1 (0x00007ffd00000000)\n"
             "\tlibsqlite3.so.0 => /lib/x86_64-linux-gnu/libsqlite3.so.0 (0x00007f0000000000)\n"
             "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000100000)\n"
             "\t/lib64/ld-linux-x86-64.so.2 (0x00007f0000200000)\n")

    def test_the_trace_names_every_library(self):
        self.assertEqual(EXPERIMENT.loader_libraries(self.TRACE),
                         ["/lib/x86_64-linux-gnu/libsqlite3.so.0", "/lib/x86_64-linux-gnu/libc.so.6",
                          "/lib64/ld-linux-x86-64.so.2"])
        for bad in ("\tlibswiftCore.so => not found\n", "statically linked\n", ""):
            with self.assertRaises(ValueError):
                EXPERIMENT.loader_libraries(bad)

    def test_only_system_libraries_and_no_swift_runtime(self):
        self.assertTrue(EXPERIMENT.runtime_system_only(EXPERIMENT.loader_libraries(self.TRACE)))
        self.assertFalse(EXPERIMENT.runtime_system_only(["/home/u/toolchain/usr/lib/swift/linux/libswiftCore.so"]))
        self.assertFalse(EXPERIMENT.runtime_system_only(["/usr/lib/swift/linux/libswiftCore.so"]))
        self.assertFalse(EXPERIMENT.runtime_system_only(["/opt/lib/libsqlite3.so.0"]))
        self.assertFalse(EXPERIMENT.runtime_system_only([]))

    def test_a_soname_symlink_is_hashed_through_its_resolved_system_file(self):
        resolved = {"/lib/x86_64-linux-gnu/libsqlite3.so.0": "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6",
                    "/lib/x86_64-linux-gnu/libbad.so.1": "/opt/lib/libbad.so.1"}
        with patch.object(EXPERIMENT.os.path, "realpath", side_effect=lambda path: resolved.get(path, path)):
            self.assertEqual(EXPERIMENT.resolved_system_library("/lib/x86_64-linux-gnu/libsqlite3.so.0"),
                             Path("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6"))
            with self.assertRaises(RuntimeError):
                EXPERIMENT.resolved_system_library("/lib/x86_64-linux-gnu/libbad.so.1")

    def test_the_build_links_the_swift_runtime_statically(self):
        self.assertIn('"--static-swift-stdlib"', SCRIPT.read_text())

    def test_the_start_check_runs_as_the_authority_identity(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = EXPERIMENT.Run(operator, 30, "/bin/true", {})
        run.authority_uid = run.authority_gid = EXPERIMENT.ID_BASE + 2
        calls = []

        def fake_run(arguments, **options):
            calls.append(options)
            if options["env"]:
                return SimpleNamespace(returncode=0, stdout=self.TRACE.encode())
            return SimpleNamespace(returncode=2, stdout=b'{"event":"error"}\n')

        with patch.object(EXPERIMENT.subprocess, "run", side_effect=fake_run), \
                patch.object(EXPERIMENT.SO, "read_bounded", return_value=b"library"):
            run._check_authority_start()
        self.assertEqual(len(run.build_hashes["authorityLibraries"]), 3)
        self.assertTrue(all(call["user"] == EXPERIMENT.ID_BASE + 2 and call["extra_groups"] == [] for call in calls))
        with patch.object(EXPERIMENT.subprocess, "run",
                          return_value=SimpleNamespace(returncode=127, stdout=b"")), self.assertRaises(RuntimeError):
            run._check_authority_start()


APPARMOR_DIR = Path(tempfile.mkdtemp(prefix="rmzso-aa-test-"))
(APPARMOR_DIR / "profiles").write_text("")


class OwnershipTests(unittest.TestCase):
    """Only what this run created is cleaned up (Toni's items 5 and 6)."""

    def make_run(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = EXPERIMENT.Run(operator, 30, "/bin/true", {name: f"/usr/bin/{name}" for name in EXPERIMENT.TOOLS})
        run.owner_uid = run.owner_gid = EXPERIMENT.ID_BASE + 1
        run.markers = run.base / "markers"
        return run

    def start(self, run, states, code):
        spec = EXPERIMENT.CASES["unit-report"]
        with tempfile.TemporaryDirectory() as directory:
            states = iter(states)
            with patch.object(run, "show", side_effect=lambda unit, properties: {"LoadState": next(states)}), \
                    patch.object(EXPERIMENT, "bind_listener", return_value=unittest.mock.MagicMock()), \
                    patch.object(EXPERIMENT.PL, "run_owned", return_value=(code, b"")):
                try:
                    run.start_owner("unit-report", spec, Path(directory), (0, 0, 0, 0))
                except RuntimeError as error:
                    return str(error)
        return "started"

    def test_a_unit_name_in_use_is_never_started_or_recorded(self):
        run = self.make_run()
        with patch.object(EXPERIMENT.PL, "run_owned") as tool, \
                patch.object(EXPERIMENT, "bind_listener", return_value=unittest.mock.MagicMock()):
            self.assertEqual(self.start(run, ["loaded"], 0), "unit name already in use")
        tool.assert_not_called()
        self.assertEqual(run.units, [])

    def test_a_failed_start_is_recorded_only_when_a_unit_exists(self):
        run = self.make_run()
        self.assertEqual(self.start(run, ["not-found", "not-found"], 1), "unit start failed")
        self.assertEqual(run.units, [])
        self.assertEqual(self.start(run, ["not-found", "failed"], 1), "unit start failed")
        self.assertEqual(run.units, [run.unit_name("unit-report")])

    def test_a_profile_name_already_loaded_is_refused(self):
        run = self.make_run()
        run.tools["apparmor_parser"] = "/usr/sbin/apparmor_parser"
        name = EXPERIMENT.PROFILE_PREFIX + run.tag
        with patch.object(EXPERIMENT, "APPARMOR", APPARMOR_DIR), \
                patch.object(EXPERIMENT, "render_profile", return_value=(name, "text")), \
                patch.object(EXPERIMENT.Run, "_loaded_profiles", return_value={name}), \
                patch.object(EXPERIMENT.PL, "run_owned") as tool, self.assertRaises(RuntimeError):
            run._load_profile()
        tool.assert_not_called()
        self.assertFalse(run.profile_loaded)

    def test_a_failed_profile_load_leaves_the_apparmor_case_not_run(self):
        # AppArmor 3.x cannot read abi 4.0: the load fails, the run goes on, unit-apparmor is not run.
        run = self.make_run()
        run.tools["apparmor_parser"] = "/usr/sbin/apparmor_parser"
        name = EXPERIMENT.PROFILE_PREFIX + run.tag
        with patch.object(EXPERIMENT, "APPARMOR", APPARMOR_DIR), \
                patch.object(EXPERIMENT, "render_profile", return_value=(name, "text")), \
                patch.object(EXPERIMENT.Run, "_loaded_profiles", return_value=set()), \
                patch.object(EXPERIMENT.PL, "write_root_file"), \
                patch.object(EXPERIMENT.PL, "run_owned", return_value=(1, b"")):
            self.assertFalse(run._load_profile())
        self.assertFalse(run.profile_loaded or run.apparmor_ready)
        with tempfile.TemporaryDirectory() as directory:
            run.base = Path(directory)
            (run.base / "cases").mkdir()
            self.assertEqual(run.run_case("unit-apparmor", 40, "mnt"),
                             {"passed": False, "status": "not-run", "reason": "apparmor-unavailable"})


class SweepTests(unittest.TestCase):
    """--sweep and the sweep at the start of a run (Toni's item 4)."""

    def test_the_sweep_removes_every_prefixed_item_and_nothing_else(self):
        tag, other = "0123abcd", "feedbeef"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroups, apparmor, base_parent, userdb = (root / name for name in ("cg", "aa", "lib", "userdb"))
            for path in (cgroups, apparmor, base_parent, userdb):
                path.mkdir()
            unit = f"rmzso-{tag}-unit-report.service"
            (cgroups / unit).mkdir()
            (cgroups / unit / "cgroup.kill").write_text("")
            (cgroups / "ssh.service").mkdir()
            (apparmor / "profiles").write_text(f"{EXPERIMENT.PROFILE_PREFIX}{tag} (enforce)\nother (enforce)\n")
            removed = []

            class Remove:
                def __init__(self, *args, **kwargs):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def write(self, name):
                    removed.append(name)
                    (apparmor / "profiles").write_text("other (enforce)\n")

            run_dir = base_parent / (EXPERIMENT.BASE_PREFIX + tag)
            run_dir.mkdir()
            (run_dir / "ids").write_text(f"owner {EXPERIMENT.ID_BASE + 7}\nauthority {EXPERIMENT.ID_BASE + 8}\n")
            (base_parent / "unrelated").mkdir()
            (userdb / f"rmzso{tag}.user").write_text(json.dumps({"uid": EXPERIMENT.ID_BASE + 7,
                                                                  "gid": EXPERIMENT.ID_BASE + 7}))
            (userdb / f"{EXPERIMENT.ID_BASE + 7}.user").symlink_to(f"rmzso{tag}.user")
            (userdb / "alice.user").write_text("{}")
            (userdb / "4711.user").symlink_to("alice.user")
            calls, killed = [], []

            def systemctl(*arguments):
                calls.append(arguments)
                if arguments[0] == "list-units":
                    listed = f"{unit} loaded failed failed x\nrmzso-{other}-x.service loaded active running x\n" \
                        if not any(call[0] == "stop" for call in calls) else ""
                    return 0, listed.encode()
                if arguments[0] == "stop":
                    shutil.rmtree(cgroups / arguments[1], ignore_errors=True)
                if arguments[0] == "show":
                    return 0, b"LoadState=not-found\n"
                return 0, b""

            real_open = open
            with patch.object(EXPERIMENT, "root_owned_file", side_effect=lambda path: path.is_file()), \
                    patch("builtins.open", side_effect=lambda path, *a, **k: Remove() if str(path).endswith(".remove")
                          else real_open(path, *a, **k)):
                result = EXPERIMENT.sweep(systemctl, cgroups, apparmor, base_parent, userdb,
                                          kill=lambda number: killed.append(number) or True,
                                          claimable=lambda number, proc, subids: True)
            self.assertTrue(result["clean"], result)
            self.assertEqual(result["units"], 2)
            self.assertIn(("stop", unit), calls)
            self.assertIn(("stop", f"rmzso-{other}-x.service"), calls)
            self.assertEqual((cgroups / "ssh.service").is_dir(), True)
            self.assertEqual(sorted(killed), [EXPERIMENT.ID_BASE + 7, EXPERIMENT.ID_BASE + 8])
            self.assertEqual(removed, [f"{EXPERIMENT.PROFILE_PREFIX}{tag}"])
            self.assertFalse(run_dir.exists())
            self.assertTrue((base_parent / "unrelated").is_dir())
            self.assertEqual(sorted(path.name for path in userdb.iterdir()), ["4711.user", "alice.user"])

    def test_an_id_outside_the_range_is_never_swept(self):
        with tempfile.TemporaryDirectory() as directory:
            base_parent = Path(directory)
            run_dir = base_parent / (EXPERIMENT.BASE_PREFIX + TAG)
            run_dir.mkdir()
            (run_dir / "ids").write_text("owner 1000\nauthority 0\n")
            with patch.object(EXPERIMENT, "root_owned_file", side_effect=lambda path: path.is_file()):
                self.assertEqual(EXPERIMENT.sweep_ids(base_parent, Path(directory) / "none"), set())

    def test_a_run_stops_when_the_sweep_leaves_state(self):
        if os.geteuid() == 0:
            self.skipTest("runs as Root")
        with patch.object(EXPERIMENT.os, "geteuid", return_value=0), \
                patch.object(EXPERIMENT.os, "getuid", return_value=0), \
                patch.object(EXPERIMENT.shutil, "which", return_value="/usr/bin/tool"), \
                patch.object(EXPERIMENT.PL, "operator_account", return_value=SimpleNamespace()), \
                patch.object(EXPERIMENT.PL, "root_owned_ancestry", return_value=True), \
                patch.object(EXPERIMENT.PL, "host_metadata", return_value={}), \
                patch.object(EXPERIMENT.SO, "last_capability", return_value=40), \
                patch.object(EXPERIMENT.os, "readlink", return_value="mnt:[1]"), \
                patch.object(EXPERIMENT, "RUN_LOCK", LOCK_DIR / "measure.lock"), \
                patch.object(EXPERIMENT.PL, "subreaper", contextlib.nullcontext):
            factory = unittest.mock.Mock()
            with self.assertRaises(RuntimeError):
                EXPERIMENT.measure(30, "/bin/true", run_factory=factory,
                                   sweep_factory=lambda systemctl: {"clean": False})
            factory.return_value.setup.assert_not_called()
            factory.return_value.cleanup.assert_not_called()


LOCK_DIR = Path(tempfile.mkdtemp(prefix="rmzso-lock-test-"))


class HostSafetyTests(unittest.TestCase):
    """Toni's second review, item 1."""

    def test_one_run_or_sweep_at_a_time(self):
        path = LOCK_DIR / "one.lock"
        with EXPERIMENT.run_lock(path):
            with self.assertRaises(RuntimeError):
                with EXPERIMENT.run_lock(path):
                    pass
        with EXPERIMENT.run_lock(path):  # released at the end of the block
            pass
        self.assertIn("with run_lock(), PL.subreaper():", SCRIPT.read_text())
        self.assertEqual(SCRIPT.read_text().count("run_lock()"), 2)  # the run and --sweep

    def test_a_user_namespace_mapping_claims_an_id(self):
        number = EXPERIMENT.ID_BASE + 100
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "5").mkdir()
            (proc / "5/uid_map").write_text("         0          0 4294967295\n")  # identity: ignored
            with patch.object(EXPERIMENT.pwd, "getpwuid", side_effect=KeyError(number)), \
                    patch.object(EXPERIMENT.grp, "getgrgid", side_effect=KeyError(number)):
                self.assertTrue(EXPERIMENT.id_unclaimed(number, proc))
                (proc / "6").mkdir()
                (proc / "6/gid_map").write_text(f"0 {EXPERIMENT.ID_BASE} 65536\n")
                self.assertFalse(EXPERIMENT.id_unclaimed(number, proc))
                self.assertFalse(EXPERIMENT.id_unused(number, proc))

    def test_the_sweep_kills_a_recorded_id_only_while_it_is_unclaimed(self):
        number = EXPERIMENT.ID_BASE + 7
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            own = SimpleNamespace(pw_name=f"rmzso{TAG}", gr_name=f"rmzso{TAG}")
            with patch.object(EXPERIMENT.pwd, "getpwuid", return_value=own), \
                    patch.object(EXPERIMENT.grp, "getgrgid", return_value=own):
                self.assertTrue(EXPERIMENT.sweep_claimable(number, proc, []))  # its own drop-in record
                self.assertFalse(EXPERIMENT.sweep_claimable(number, proc, [(number, 1)]))
            other = SimpleNamespace(pw_name="alice", gr_name="alice")
            with patch.object(EXPERIMENT.pwd, "getpwuid", return_value=other), \
                    patch.object(EXPERIMENT.grp, "getgrgid", return_value=other):
                self.assertFalse(EXPERIMENT.sweep_claimable(number, proc, []))
            base_parent = proc / "lib"
            run_dir = base_parent / (EXPERIMENT.BASE_PREFIX + TAG)
            run_dir.mkdir(parents=True)
            (run_dir / "ids").write_text(f"owner {number}\nauthority {number + 1}\n")
            killed = []
            with patch.object(EXPERIMENT, "root_owned_file", side_effect=lambda path: path.is_file()):
                EXPERIMENT.sweep(lambda *arguments: (0, b""), proc / "cg", proc / "aa", base_parent, proc / "udb",
                                 kill=lambda n: killed.append(n) or True,
                                 claimable=lambda n, _proc, _subids: n == number + 1)
            self.assertEqual(killed, [number + 1])

    def test_the_sweep_removes_a_cgroup_only_after_its_unit_is_not_found(self):
        unit = f"rmzso-{TAG}-x.service"
        with tempfile.TemporaryDirectory() as directory:
            cgroups = Path(directory) / "cg"
            (cgroups / unit).mkdir(parents=True)
            calls, loaded = [], {"value": 2}

            def systemctl(*arguments):
                calls.append(arguments[0])
                if arguments[0] == "show":
                    loaded["value"] -= 1
                    state = "loaded" if loaded["value"] > 0 else "not-found"
                    return 0, f"LoadState={state}\n".encode()
                return 0, b""

            removed = []
            real_rmdir = os.rmdir
            with patch.object(EXPERIMENT, "kill_cgroup", return_value=True), \
                    patch.object(EXPERIMENT.os, "rmdir",
                                 side_effect=lambda path: removed.append(len(calls)) or real_rmdir(path)):
                result = EXPERIMENT.sweep(systemctl, cgroups, Path(directory) / "aa", Path(directory) / "lib",
                                          Path(directory) / "udb", claimable=lambda *args: True)
            self.assertTrue(result["clean"], result)
            first_show = calls.index("show")
            self.assertEqual(calls[first_show + 1:first_show + 3], ["stop", "reset-failed"])  # still loaded
            self.assertEqual(calls[removed[0] - 1], "show")  # rmdir right after a not-found show

    def test_userdb_paths_are_recorded_before_creation_and_never_taken_over(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = EXPERIMENT.Run(operator, 30, "/bin/true", {})
        run.owner_uid = run.owner_gid = EXPERIMENT.ID_BASE + 1
        with tempfile.TemporaryDirectory() as directory:
            userdb = Path(directory) / "userdb"
            seen = []

            def write(path, data, mode):
                seen.append(path in run.userdb_files)
                path.write_bytes(data)

            with patch.object(EXPERIMENT, "USERDB", userdb), \
                    patch.object(EXPERIMENT, "stat_is_root_directory", return_value=True), \
                    patch.object(EXPERIMENT.PL, "write_root_file", side_effect=write):
                run._write_userdb()
            self.assertEqual(seen, [True, True])
            self.assertTrue(run.userdb_created)
            self.assertEqual(len(run.userdb_files), 4)
            self.assertIn("with PL.deferred_cancel():\n            if not os.path.lexists(USERDB):",
                          SCRIPT.read_text())
            other = EXPERIMENT.Run(operator, 30, "/bin/true", {})
            other.owner_name, other.owner_uid = run.owner_name, run.owner_uid
            with patch.object(EXPERIMENT, "USERDB", userdb), \
                    patch.object(EXPERIMENT, "stat_is_root_directory", return_value=True), \
                    self.assertRaises(RuntimeError):
                other._write_userdb()
            self.assertEqual(other.userdb_files, [])  # an existing record is never recorded as its own
            self.assertFalse(other.userdb_created)
            for path in reversed(run.userdb_files):
                os.unlink(path)
            run.ids_picked = False
            with patch.object(EXPERIMENT, "USERDB", userdb):
                run.cleanup()
            self.assertFalse(userdb.exists())  # the empty directory that the run created


class SelftestGateTests(unittest.TestCase):
    def test_the_self_test_is_not_run_before_linux_6_5(self):
        if os.geteuid() == 0:
            self.skipTest("runs as Root")
        with patch.object(EXPERIMENT, "peer_pidfd_supported", return_value=False), \
                patch.object(EXPERIMENT, "build_authority") as build:
            result = EXPERIMENT.authority_selftest("/nonexistent")
        build.assert_not_called()
        self.assertEqual((result["status"], result["passed"]), ("not-run", None))  # never a pass

    def test_the_host_check_no_longer_builds_the_authority(self):
        self.assertNotIn("single-owner", (ROOT / "scripts/check-linux-host.sh").read_text())


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
