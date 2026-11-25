#!/usr/bin/env python3
"""Supervised single-owner measurement, PR2 (issue #988): Swift authority, systemd unit, AppArmor, sudo.

PR1 (run-linux-single-owner-experiment.py) measured the owner O with a stub authority and setpriv.
This runner composes the unchanged owner.c with the Swift authority of the composed fixture
(experiments/linux-single-owner/authority) and starts O in a transient systemd unit, with the unit
options of docs/linux-single-owner-design.md. It adds no production executor, no installer and no
file under /etc.

Three modes:

  --build-authority --work-dir DIR   builds the Swift authority as the current user (no root)
  --authority-selftest --work-dir DIR
                                     builds it, then runs the authority control cases (replay,
                                     earlier generation, wrong peer) as the current user (no root)
  --authority PATH                   the supervised Root run, through sudo, from the operator's
                                     session: PATH is the authority that the operator built with
                                     --build-authority; the runner copies it and records its hash

The Root run creates two disposable system accounts (O's service user and the authority's user),
a directory under /var/lib, transient units named rmzso-<tag>-<case>.service and one AppArmor
profile rmzso-owner-<tag> in the kernel only (apparmor_parser -a -K). It changes no sysctl, no
sudoers file and nothing under /etc except the two accounts. Cleanup removes all of it in a finally
block and reports each step.

If a run is interrupted before cleanup, as Root: kill the processes in each
/sys/fs/cgroup/system.slice/rmzso-*.service/cgroup.procs, run "systemctl stop" and
"systemctl reset-failed" for each rmzso-*.service, write each rmzso-owner- name in
/sys/kernel/security/apparmor/profiles to /sys/kernel/security/apparmor/.remove, remove
/var/lib/remozio-single-owner-pr2-*, and delete the rmzso* and rmzsa* system accounts.

The report holds booleans, closed categories, errno names, settings and hashes only.
strictAdmission is true only when every gating case passes; the sudo password prompt is a known
limit and does not gate it. Inside the command, passwd -S of the operator's own account is the
decisive set-user-ID check; "sudo -n true" gets 5 s and is "inconclusive" when it does not end (sudo
can wait for a FIDO touch through PAM), which never fails a case. The authority records a dispatch
without a command as failed with the reason notStarted. productionAdmission is always false.
"""
import argparse
import contextlib
import datetime
import grp
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import select
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "experiments/linux-single-owner"
PR1_RUNNER = ROOT / "scripts/run-linux-single-owner-experiment.py"
# The PR1 runner stays byte-identical (its evidence records its hash): this runner loads it as a
# module and uses its parsers, its O_NOFOLLOW reads, its process helpers and, through it, the #728
# helpers. Nothing here calls its measure().
_spec = importlib.util.spec_from_file_location("remozio_single_owner_pr1_runner", PR1_RUNNER)
SO = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SO)
PL = SO.PL

AUTHORITY_PACKAGE = FIXTURES / "authority"
AUTHORITY_PRODUCT = "LinuxSingleOwnerAuthority"
APPARMOR_TEMPLATE = FIXTURES / "apparmor.in"
FDSHIM, COMMAND = FIXTURES / "fdshim.c", FIXTURES / "command2.c"
BASE_PARENT = SO.BASE_PARENT
BASE_PREFIX = "remozio-single-owner-pr2-"
PROFILE_PREFIX = "rmzso-owner-"
TAG_PATTERN = re.compile(r"[0-9a-f]{8}")
ABI_LINE = "abi <abi/4.0>,"
CGROUP_SYSTEM = Path("/sys/fs/cgroup/system.slice")
APPARMOR = Path("/sys/kernel/security/apparmor")
TOOLS = ("systemd-run", "systemctl", "apparmor_parser", "useradd", "userdel", "groupdel", "cc")
DEADLINE_MS = SO.DEADLINE_MS
MAX_OUTPUT_BYTES = SO.MAX_OUTPUT_BYTES
NA, YES_NO = SO.NA, SO.YES_NO
# Every image is static, so the AppArmor profile needs no loader rule.
BUILDS = {"owner": (SO.OWNER, ("-static",)), "frontend": (SO.FRONTEND, ("-static",)),
          "fdshim": (FDSHIM, ("-static",)), "command": (COMMAND, ("-static",))}
COMMANDS = ("cmd-report", "cmd-sudo", "cmd-prompt", "cmd-hog")

# The unit options of the design ("Unit options"), as systemd-run properties. RemainAfterExit= is
# an experiment addition: it keeps ExecMainCode and ExecMainStatus readable after O ends. It sets
# no no_new_privs and no mount namespace.
LIMITS = ("CPU", "FSIZE", "DATA", "STACK", "CORE", "RSS", "NOFILE", "AS", "NPROC", "MEMLOCK", "LOCKS",
          "SIGPENDING", "MSGQUEUE", "NICE", "RTPRIO", "RTTIME")
UNIT_OPTIONS = ("AmbientCapabilities=CAP_SYS_PTRACE CAP_SETUID CAP_SETGID", "KillMode=process",
                "OOMPolicy=continue", "TasksMax=infinity", *(f"Limit{name}=infinity" for name in LIMITS),
                "RemainAfterExit=yes")
# Case-only additions: the two negative controls, the AppArmor profile, and the memory bound that
# causes a real out-of-memory kill in the unit's cgroup. None of them is a production option.
EXTRA_OPTIONS = {"nnp": ("NoNewPrivileges=yes",), "privatetmp": ("PrivateTmp=yes",),
                 "oom": ("MemoryMax=64M", "MemorySwapMax=0"), "apparmor": ("AppArmorProfile=@@PROFILE@@",)}
SHOW_PROPERTIES = ("KillMode", "OOMPolicy", "TasksMax", "NoNewPrivileges", "PrivateTmp", "AmbientCapabilities",
                   *(f"Limit{name}" for name in LIMITS))
SHOW_EXPECTED = {"KillMode": "process", "OOMPolicy": "continue", "TasksMax": "infinity", "NoNewPrivileges": "no",
                 "PrivateTmp": "no", "AmbientCapabilities": "cap_setgid cap_setuid cap_sys_ptrace",
                 **{f"Limit{name}": "infinity" for name in LIMITS}}

SUDO = frozenset({"password-required", "allowed", "terminal-required", "no-new-privs", "not-setuid",
                  "not-permitted", "not-found", "inconclusive", "other", "not-run", "not-reported"})
# sudo started set-user-ID and reached its policy, without no_new_privs: the plan review expects for the
# sudo child is "a password is required"; "allowed" (an operator rule without a password) proves the
# same start. sudo can wait for a FIDO touch through PAM even with -n, so a sudo that does not end in
# 5 s is "inconclusive": recorded, never a failure. passwd -S is the decisive check.
SUDO_REACHED_POLICY = ("password-required", "allowed", "inconclusive")
# passwd -S <caller> inside the command: "ok" only when the set-user-ID image started with euid 0 (no
# no_new_privs) and needed no interaction.
PASSWD = frozenset({"ok", "failed", "not-found", "timeout", "no-user", "other", "not-run", "not-reported"})
# The authority records a dispatch without a command as failed; the reason keeps the difference.
OUTCOME_REASONS = frozenset({"none", "notStarted", "execFailed", "refused"})
PHASES = frozenset({"queued", "presented", "authorized", "executing", "succeeded", "failed", "unknown", "declined",
                    "cancelled", "expired", "unreadable", "other"})
OUTCOME_PHASE = {"dispatched": "succeeded", "unknown": "unknown", "execFailed": "failed", "notStarted": "failed",
                 "refused": "failed"}


KNOWN_LIMITS = ("sudo password prompt: no controlling terminal for the command (unit-sudo-prompt, "
                "recorded, not gating)",
                "sudo -n true may wait for a FIDO touch through PAM: after 5 s it is recorded as "
                "inconclusive and does not gate; passwd -S is the decisive check",
                "a dispatch without a command (notStarted) is recorded as failed with the reason "
                "notStarted; production needs a distinct outcome (design S4)")


# --- Vocabulary ---------------------------------------------------------------------------------

DISPATCH_KEYS = {
    **{key: values | {NA} for key, values in SO.OWNER_DISPATCH_KEYS.items() if key != "dispatch"},
    "authorityPermit": YES_NO, "authorityPhaseAfterPermit": PHASES | {NA},
    "authorityOutcome": SO.RESULTS | {"missing"}, "authorityOutcomeReason": OUTCOME_REASONS | {NA},
    "authorityPhase": PHASES | {NA},
    "frontendExit": frozenset({"closed", "SIGKILL", "other", "not-started", "running"}),
    "capsEmpty": YES_NO | {"not-reported"}, "boundingFull": YES_NO | {"not-reported"},
    "noNewPrivs": frozenset({"0", "1", "not-reported"}), "hostMountNamespace": YES_NO | {"not-reported"},
    "commandLabel": frozenset({"unconfined", "owner-profile", "other", "not-reported"}),
    "commandFds": frozenset({"exact", "other", "not-reported"}), "sudo": SUDO, "passwd": PASSWD,
}
CASE_KEYS = {
    **{key: values | {NA} for key, values in SO.OWNER_START_KEYS.items()},
    "ownerExit": frozenset({"ok", "refused", "usage", "SIGKILL", "SIGTERM", "other", "running"}),
    "ownerIsMainPID": YES_NO, "ownerLabel": frozenset({"profile", "unconfined", "other", NA}),
    "unitReadback": YES_NO | {NA}, "ownerLimitsMax": YES_NO | {NA},
    "markerLines": frozenset({"0", "1", "2", "more"}), "restartLogClean": YES_NO | {NA},
    "authorityHello": frozenset({"accepted", "refused", "missing"}),
    # A stopped transient unit can be unloaded at once, and its exit status with it: the pidfd shows
    # that O ended, whatever systemd still reports.
    "ownerGoneAfterUnitAction": YES_NO | {NA},
    "commandAliveAfterStop": YES_NO | {NA}, "commandAliveAfterRestart": YES_NO | {NA}, "unitRestarted": YES_NO | {NA},
    "oomKill": YES_NO | {NA}, "ownerAliveAfterOom": YES_NO | {NA}, "commandAliveAfterOom": YES_NO | {NA},
    "unitActiveAfterOom": YES_NO | {NA},
    "k2FdsExact": YES_NO | {NA}, "k2StreamsAreC2": YES_NO | {NA}, "k2PipesHeldByOwner": YES_NO | {NA},
    "ownerHoldsNothingOfDispatch1": YES_NO | {NA}, "ownerFdCountStable": YES_NO | {NA},
    "command1HoldsOnlyItsStreams": YES_NO | {NA},
}
CONTROL_KEYS = {
    "firstHello": frozenset({"OK", "REFUSED", "error"}), "firstPermit": YES_NO,
    "replaySubmit": frozenset({"REFUSED", "PERMIT", "error"}), "replayLedger": frozenset({"refused", "accepted", NA}),
    "firstOutcome": frozenset({"OK", "REFUSED", "error"}),
    "firstOutcomePhase": PHASES | {"missing"}, "firstOutcomeReason": OUTCOME_REASONS | {"missing"},
    "replayOutcome": frozenset({"OK", "REFUSED", "error"}),
    "earlierGenerationHello": frozenset({"OK", "REFUSED", "error"}),
    "earlierGenerationOutcome": frozenset({"OK", "REFUSED", "error"}),
    "earlierGenerationEvent": frozenset({"generation-refused", "other", "missing"}),
    "wrongPeer": frozenset({"OK", "REFUSED", "error"}), "wrongPeerEvent": frozenset({"wrong-peer", "other", "missing"}),
    "operatorConnect": frozenset({"EACCES", "connected", "other", NA}),
}
CONTROL_EXPECT = {"firstHello": "OK", "firstPermit": "yes", "replaySubmit": "REFUSED", "replayLedger": "refused",
                  "firstOutcome": "OK", "firstOutcomePhase": "failed", "firstOutcomeReason": "notStarted",
                  "replayOutcome": "REFUSED", "earlierGenerationHello": "REFUSED",
                  "earlierGenerationOutcome": "REFUSED", "earlierGenerationEvent": "generation-refused",
                  "wrongPeer": "REFUSED", "wrongPeerEvent": "wrong-peer"}


def _expect(**values):
    return {key: frozenset(value if isinstance(value, tuple) else (value,)) for key, value in values.items()}


STARTED = {"ownerCapabilitiesExact": "yes", "generation": "yes", "authorityAccepted": "yes",
           "authorityHello": "accepted", "ownerIsMainPID": "yes"}
DISPATCHED = {"admitted": "yes", "permit": "yes", "finalCheck": "yes", "kSetup": "ok", "result": "dispatched",
              "goWritten": "yes", "requesterLostBeforeCheck": "no", "requesterLostAfterCheck": "no",
              "killedAtDeadline": "no", "reported": "yes", "restartLogComplete": "yes", "authorityPermit": "yes",
              "authorityPhaseAfterPermit": "executing", "authorityOutcome": "dispatched",
              "authorityOutcomeReason": "none", "authorityPhase": "succeeded", "frontendExit": "closed"}
COMMAND_OK = {"capsEmpty": "yes", "noNewPrivs": "0", "hostMountNamespace": "yes", "commandFds": "exact"}
# O dies before it prints its dispatch line: the permit is seen at the authority only.
KILLED_BEFORE_GO = {"authorityPermit": "yes",
                    "authorityPhaseAfterPermit": "executing", "authorityOutcome": "missing",
                    "authorityOutcomeReason": NA, "authorityPhase": "executing", "frontendExit": "SIGKILL"}


def _case(command="cmd-report", modes=("normal",), extra=(), actions=(), case=None, dispatches=None,
          gating=True, kind="owner"):
    """case: expected case-level values; dispatches: expected values per dispatch (list of dicts)."""
    return {"command": command, "modes": tuple(modes), "extra": tuple(extra), "actions": tuple(actions),
            "expectCase": _expect(**(case or {})),
            "expectDispatches": [_expect(**item) for item in (dispatches or [])],
            "gating": gating, "kind": kind}


CASES = {
    # The unit options, read from inside a command, and the unit's own readback.
    "unit-report": _case(case={**STARTED, "ownerExit": "ok", "unitReadback": "yes", "ownerLimitsMax": "yes",
                               "markerLines": "1", "restartLogClean": "yes"},
                         dispatches=[{**DISPATCHED, **COMMAND_OK, "commandLabel": "unconfined"}]),
    # The two negative controls: each proves that the check above can fail.
    "unit-nnp-control": _case("cmd-sudo", extra=("nnp",),
                              case={**STARTED, "ownerExit": "ok", "markerLines": "1"},
                              dispatches=[{**DISPATCHED, "noNewPrivs": "1", "passwd": "failed",
                                           "sudo": ("no-new-privs", "not-setuid", "inconclusive")}]),
    "unit-privatetmp-control": _case(extra=("privatetmp",), case={**STARTED, "ownerExit": "ok", "markerLines": "1"},
                                     dispatches=[{**DISPATCHED, "hostMountNamespace": "no"}]),
    # passwd -S <caller> inside the command succeeds (set-user-ID start with euid 0, NoNewPrivs 0);
    # sudo -n true is recorded, and an inconclusive sudo does not fail the case.
    "unit-sudo": _case("cmd-sudo", case={**STARTED, "ownerExit": "ok", "markerLines": "1"},
                       dispatches=[{**DISPATCHED, **COMMAND_OK, "passwd": "ok", "sudo": SUDO_REACHED_POLICY}]),
    # Known limit: no controlling terminal for the password prompt. Recorded, not gating.
    "unit-sudo-prompt": _case("cmd-prompt", case={**STARTED, "ownerExit": "ok", "markerLines": "1"},
                              dispatches=[{**DISPATCHED, "sudo": ("terminal-required", "inconclusive", "other",
                                                                  "password-required")}], gating=False),
    # O under its AppArmor profile; the command leaves it through the ux rule, and passwd -S works inside.
    "unit-apparmor": _case("cmd-sudo", extra=("apparmor",),
                           case={**STARTED, "ownerExit": "ok", "ownerLabel": "profile", "markerLines": "1"},
                           dispatches=[{**DISPATCHED, **COMMAND_OK, "commandLabel": "unconfined",
                                        "passwd": "ok", "sudo": SUDO_REACHED_POLICY}]),
    # A second dispatch while the first command still runs after S6 (plan review, answer 1).
    "second-dispatch-fds": _case(modes=("sleep", "normal"),
                                 case={**STARTED, "ownerExit": "ok", "markerLines": "2", "restartLogClean": "yes",
                                       "k2FdsExact": "yes", "k2StreamsAreC2": "yes", "k2PipesHeldByOwner": "yes",
                                       "ownerHoldsNothingOfDispatch1": "yes", "ownerFdCountStable": "yes",
                                       "command1HoldsOnlyItsStreams": "yes"},
                                 dispatches=[DISPATCHED, DISPATCHED]),
    # KillMode=process: a unit stop and a unit restart end only O.
    "unit-stop": _case(modes=("sleep",), actions=(("end", "unit-stop"),),
                       case={**STARTED, "ownerGoneAfterUnitAction": "yes", "markerLines": "1",
                             "commandAliveAfterStop": "yes"},
                       dispatches=[DISPATCHED]),
    "unit-restart": _case(modes=("sleep",), actions=(("end", "unit-restart"),),
                          case={**STARTED, "ownerGoneAfterUnitAction": "yes", "markerLines": "1",
                                "commandAliveAfterRestart": "yes", "unitRestarted": "yes"},
                          dispatches=[DISPATCHED]),
    # OOMPolicy=continue: a real out-of-memory kill of the second command (MemoryMax=).
    "unit-oom": _case("cmd-hog", modes=("sleep", "normal"), extra=("oom",), actions=(("end", "oom-check"),),
                      case={**STARTED, "ownerExit": "ok", "oomKill": "yes", "ownerAliveAfterOom": "yes",
                            "commandAliveAfterOom": "yes", "unitActiveAfterOom": "yes"},
                      dispatches=[DISPATCHED, {**{k: v for k, v in DISPATCHED.items()
                                                  if k not in ("frontendExit",)}}]),
    # The dispatch-race-limitation rows with the Swift authority: O dies before the go byte.
    "kill-owner-at-s1": _case(actions=(("s1", "kill-owner"),),
                              case={**STARTED, "ownerExit": "SIGKILL", "markerLines": "0"},
                              dispatches=[KILLED_BEFORE_GO]),
    "kill-owner-after-fork": _case(actions=(("after-fork", "kill-owner"),),
                                   case={**STARTED, "ownerExit": "SIGKILL", "markerLines": "0"},
                                   dispatches=[KILLED_BEFORE_GO]),
    "kill-owner-before-go": _case(actions=(("before-go", "kill-owner"),),
                                  case={**STARTED, "ownerExit": "SIGKILL", "markerLines": "0"},
                                  dispatches=[KILLED_BEFORE_GO]),
    # The authority alone: a replayed permit, a permit of an earlier generation, a wrong peer.
    "authority-controls": _case(kind="controls"),
}
ACTIONS = frozenset({"kill-owner", "unit-stop", "unit-restart", "oom-check"})


# --- Pure parts (tested without Root) ----------------------------------------------------------

def base_for(tag):
    return BASE_PARENT / (BASE_PREFIX + tag)


def render_profile(template, tag, base):
    """Exact substitution; one profile named rmzso-owner-<tag>, with the ux rule for the commands."""
    if not TAG_PATTERN.fullmatch(tag) or Path(base) != base_for(tag):
        raise ValueError("unexpected tag or run directory")
    text = template.replace("@@TAG@@", tag).replace("@@BASE@@", str(base))
    if "@@" in text:
        raise ValueError("unrendered placeholder")
    abi, blocks = profile_blocks(text)
    name = PROFILE_PREFIX + tag
    if abi != ABI_LINE or set(blocks) != {name}:
        raise ValueError("unexpected profile")
    if f"  {base}/run/cmd-* ux," not in blocks[name].splitlines():
        raise ValueError("missing ux rule")
    return name, f"{abi}\n\n{blocks[name]}\n"


def profile_blocks(text):
    abi, blocks, current = None, {}, None
    for line in text.splitlines():
        if current is not None:
            current.append(line)
            if line == "}":
                name = current[0].split()[1]
                if name in blocks:
                    raise ValueError("duplicate profile")
                blocks[name] = "\n".join(current)
                current = None
        elif line.startswith("profile "):
            current = [line]
        elif line.startswith("abi "):
            abi = line
        elif line.strip() and not line.startswith("#"):
            raise ValueError("rule outside a profile")
    if current is not None:
        raise ValueError("unterminated profile")
    return abi, blocks


def unit_properties(user, group, extra=(), profile=None):
    """The design's options, the case's additions, then the identity."""
    properties = [*UNIT_OPTIONS]
    for name in extra:
        for item in EXTRA_OPTIONS[name]:
            if "@@PROFILE@@" in item:
                if not profile:
                    raise ValueError("profile not loaded")
                item = item.replace("@@PROFILE@@", profile)
            properties.append(item)
    return [f"User={user}", f"Group={group}", *properties]


def unit_command(systemd_run, unit, properties, arguments):
    """No --collect: a failed unit stays loaded, so its exit status can be read, and cleanup stops it."""
    if not re.fullmatch(r"rmzso-[0-9a-f]{8}-[a-z0-9-]{1,40}\.service", unit):
        raise ValueError("unexpected unit name")
    return [systemd_run, f"--unit={unit}", "--quiet", "--service-type=exec",
            *(f"--property={item}" for item in properties), "--", *arguments]


def parse_show(text):
    """systemctl show output: one Key=value per line; a repeated key is invalid."""
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z]{1,40}", key) or key in values:
            raise ValueError("unexpected show output")
        values[key] = value
    return values


def readback_matches(values):
    """The unit's settings as systemd reports them. AmbientCapabilities is compared as a set."""
    for key, expected in SHOW_EXPECTED.items():
        value = values.get(key)
        if value is None:
            return False
        if key == "AmbientCapabilities":
            if set(value.split()) != set(expected.split()):
                return False
        elif value != expected:
            return False
    return True


def limits_at_max(limits, nr_open):
    """O's /proc limits in the PR1 "soft/hard" form: every limit unlimited, RLIMIT_NOFILE at nr_open."""
    pairs = limits.split(",")
    if len(pairs) != 16:
        return False
    for index, pair in enumerate(pairs):
        wanted = f"{nr_open}/{nr_open}" if index == 7 else "inf/inf"
        if pair != wanted and not (index == 7 and pair == "inf/inf"):
            return False
    return True


COMMAND_REPORT_KEYS = ("capPrm", "capEff", "capInh", "capAmb", "capBnd", "noNewPrivs", "mntNs", "label", "fds",
                       "sudo", "passwd")


def command_checks(raw, last_cap, host_mnt, tag):
    """The command's report, reduced to closed values. raw is b"" when no report came."""
    keys = ("capsEmpty", "boundingFull", "noNewPrivs", "hostMountNamespace", "commandLabel", "commandFds", "sudo",
            "passwd")
    if not raw:
        return {key: "not-reported" for key in keys}
    lines = [line for line in raw.split(b"\n") if line]
    if len(lines) != 1:
        raise ValueError("unexpected command line count")
    report = SO.parse_report(lines[0])
    if set(report) != set(COMMAND_REPORT_KEYS):
        raise ValueError("invalid command report")
    caps = {key: SO._hex_mask(report[key]) for key in ("capPrm", "capEff", "capInh", "capAmb", "capBnd")}
    if report["noNewPrivs"] not in ("0", "1") or report["sudo"] not in SUDO or report["passwd"] not in PASSWD:
        raise ValueError("invalid command report")
    label = report["label"]
    owner_profile = PROFILE_PREFIX + tag if tag else None
    yes = lambda condition: "yes" if condition else "no"
    return {"capsEmpty": yes(not (caps["capPrm"] or caps["capEff"] or caps["capInh"] or caps["capAmb"])),
            "boundingFull": yes(caps["capBnd"] == (1 << (last_cap + 1)) - 1),
            "noNewPrivs": report["noNewPrivs"],
            "hostMountNamespace": yes(host_mnt is not None and report["mntNs"] == host_mnt),
            "commandLabel": ("unconfined" if label == "unconfined"
                             else "owner-profile" if owner_profile and label.split(" ")[0] == owner_profile
                             else "other"),
            "commandFds": "exact" if report["fds"] == "0 1 2" else "other",
            "sudo": report["sudo"], "passwd": report["passwd"]}


def owner_reports(raw, dispatches):
    """O's stdout: a start line, then at most one line per dispatch, numbered from 1."""
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("owner output exceeds bound")
    lines = [line for line in raw.split(b"\n") if line]
    if not 1 <= len(lines) <= 1 + dispatches:
        raise ValueError("unexpected owner line count")
    start = SO.parse_report(lines[0])
    if set(start) != set(SO.OWNER_START_KEYS) or any(v not in SO.OWNER_START_KEYS[k] for k, v in start.items()):
        raise ValueError("invalid owner start report")
    keys = {**SO.OWNER_DISPATCH_KEYS, "dispatch": frozenset(str(n) for n in range(1, dispatches + 1))}
    reports = []
    for number, line in enumerate(lines[1:], start=1):
        report = SO.parse_report(line)
        if set(report) != set(keys) or any(v not in keys[k] for k, v in report.items()) or \
                report["dispatch"] != str(number):
            raise ValueError("invalid owner dispatch report")
        del report["dispatch"]
        reports.append(report)
    return start, reports


AUTHORITY_EVENTS = {
    "start": {}, "end": {}, "error": {},
    "peer": {"result": frozenset({"owner", "wrong-uid", "refused"})},
    "hello": {"result": frozenset({"accepted", "refused"})},
    "message": {"result": frozenset({"refused", "wrong-peer"})},
    "submit": {"result": frozenset({"permit", "refused", "replay-refused"}),
               "reason": frozenset({"no-generation", "malformed", "generation-lost", "no-more-requests", "declined",
                                    "store"}),
               "ledger": frozenset({"refused", "accepted"}), "phase": PHASES},
    "outcome": {"result": frozenset({"recorded", "refused", "generation-refused", "replay-refused",
                                     "store-refused"}),
                "reported": SO.RESULTS, "reason": OUTCOME_REASONS, "requesterLost": YES_NO, "phase": PHASES},
}


def authority_events(raw):
    """The authority's stdout: JSON lines whose event and fields are all in the closed vocabulary."""
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("authority output exceeds bound")
    events = []
    for line in raw.split(b"\n"):
        if not line:
            continue
        event = SO.parse_report(line)
        kind = event.get("event")
        allowed = AUTHORITY_EVENTS.get(kind)
        if allowed is None or any(key != "event" and (key not in allowed or value not in allowed[key])
                                  for key, value in event.items()):
            raise ValueError("invalid authority event")
        events.append(event)
    return events


def authority_summary(events, dispatches):
    """Case-level and per-dispatch values from the authority's events, in order."""
    hellos = [event["result"] for event in events if event["event"] == "hello"]
    permits = [event for event in events if event["event"] == "submit" and event["result"] == "permit"]
    outcomes = [event for event in events if event["event"] == "outcome" and event["result"] == "recorded"]
    summary = {"authorityHello": "accepted" if hellos == ["accepted"] else "refused" if hellos else "missing"}
    per_dispatch = []
    for index in range(dispatches):
        permit = permits[index] if index < len(permits) else None
        outcome = outcomes[index] if index < len(outcomes) else None
        per_dispatch.append({
            "authorityPermit": "yes" if permit else "no",
            "authorityPhaseAfterPermit": permit.get("phase", NA) if permit else NA,
            "authorityOutcome": outcome["reported"] if outcome else "missing",
            "authorityOutcomeReason": outcome.get("reason", NA) if outcome else NA,
            "authorityPhase": outcome.get("phase", NA) if outcome else (permit.get("phase", NA) if permit else NA)})
    return summary, per_dispatch


def restart_log_clean_all(raw, dispatches):
    """PR1's check for each dispatch's lines of the shared log."""
    if not raw:
        return NA
    by_dispatch = {}
    for line in raw.decode("ascii", "replace").splitlines():
        match = re.fullmatch(r"([0-9]{1,20}) ([0-9]) ([A-Z]{1,16})", line)
        if not match or not 1 <= int(match[2]) <= dispatches:
            return "no"
        by_dispatch.setdefault(int(match[2]), []).append(f"{match[1]} 1 {match[3]}")
    return "yes" if all(SO.restart_log_clean(("\n".join(lines) + "\n").encode()) == "yes"
                        for lines in by_dispatch.values()) else "no"


def fd_checks(first, second):
    """first: the snapshot at dispatch 1's k-ready; second: at dispatch 2's k-ready.

    Each snapshot maps "owner", "k", "c" (and "command1" in the second) to {fd number: link}. Pipe
    links name the pipe's inode, so both ends of one pipe have the same link."""
    if not first or not second:
        return {key: NA for key in ("k2FdsExact", "k2StreamsAreC2", "k2PipesHeldByOwner",
                                    "ownerHoldsNothingOfDispatch1", "ownerFdCountStable",
                                    "command1HoldsOnlyItsStreams")}
    yes = lambda condition: "yes" if condition else "no"
    k1, c1, owner1 = first["k"], first["c"], first["owner"]
    k2, c2, owner2, command1 = second["k"], second["c"], second["owner"], second["command1"]
    streams1 = {c1.get(n) for n in (0, 1, 2)} - {None}
    dispatch1 = streams1 | {k1.get(3), k1.get(4)} - {None}
    pipes2 = [k2.get(3), k2.get(4)]
    return {
        "k2FdsExact": yes(set(k2) == {0, 1, 2, 3, 4}),
        "k2StreamsAreC2": yes(all(k2.get(n) is not None and k2.get(n) == c2.get(n) for n in (0, 1, 2))),
        "k2PipesHeldByOwner": yes(all(p is not None and p.startswith("pipe:") and p in owner2.values()
                                      and p not in dispatch1 for p in pipes2)),
        "ownerHoldsNothingOfDispatch1": yes(len(dispatch1) == 5 and not dispatch1 & set(owner2.values())),
        "ownerFdCountStable": yes(len(owner1) == len(owner2)),
        "command1HoldsOnlyItsStreams": yes(set(command1) == {0, 1, 2}
                                           and {command1[n] for n in (0, 1, 2)} == streams1
                                           and not set(command1.values()) & set(pipes2)),
    }


def evaluate(case, observed):
    """observed: the case's keys; every value must be in the vocabulary, then the expectation."""
    spec = CASES[case]
    vocabulary = CONTROL_KEYS if spec["kind"] == "controls" else None
    if vocabulary is not None:
        if set(observed) != set(vocabulary) or any(observed[k] not in vocabulary[k] for k in observed):
            return {"passed": False, "error_type": "InvalidObservation"}
        mismatches = sorted(k for k, v in CONTROL_EXPECT.items() if observed[k] != v)
        return {"passed": not mismatches, "observed": dict(sorted(observed.items())), "mismatches": mismatches}
    dispatches = observed.get("dispatches")
    if type(dispatches) is not list or len(dispatches) != len(spec["modes"]):
        return {"passed": False, "error_type": "InvalidObservation"}
    case_values = {k: v for k, v in observed.items() if k != "dispatches"}
    if set(case_values) != set(CASE_KEYS) or any(case_values[k] not in CASE_KEYS[k] for k in case_values) or \
            any(set(item) != set(DISPATCH_KEYS) or any(item[k] not in DISPATCH_KEYS[k] for k in item)
                for item in dispatches):
        return {"passed": False, "error_type": "InvalidObservation"}
    mismatches = sorted(k for k, allowed in spec["expectCase"].items() if case_values[k] not in allowed)
    for number, expected in enumerate(spec["expectDispatches"], start=1):
        mismatches += sorted(f"d{number}.{k}" for k, allowed in expected.items()
                             if dispatches[number - 1][k] not in allowed)
    return {"passed": not mismatches, "observed": {**dict(sorted(case_values.items())), "dispatches": dispatches},
            "mismatches": mismatches}


def admission(cases, setup, cleanup):
    """passed: every case passed. strictAdmission: every gating case passed, with setup and cleanup."""
    complete = set(cases) == set(CASES)
    ok = bool(setup) and all(setup.values()) and all(cleanup.values()) and complete
    passed = ok and all(item.get("passed") is True for item in cases.values())
    strict = ok and all(item.get("passed") is True for name, item in cases.items() if CASES[name]["gating"])
    return passed, strict


# --- Authority control client ------------------------------------------------------------------

# Runs as the owner's service user (Root run) or as the current user (self-test). It prints one
# JSON object of reply categories; the tokens it needs travel between its runs through the runner,
# never into the report.
CLIENT = r"""
import json, os, secrets, socket, sys
path, step = sys.argv[1], sys.argv[2]
def generation():
    boot = open("/proc/sys/kernel/random/boot_id").read().strip()
    text = open("/proc/self/stat").read()
    return boot, os.getpid(), int(text[text.rindex(")") + 2:].split()[19])
def ask(s, text):
    s.send(text.encode())
    reply = s.recv(1024).decode("ascii", "replace")
    return reply
def category(reply):
    word = reply.split(" ")[0]
    return word if word in ("OK", "REFUSED", "PERMIT") else "error"
def connect():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.settimeout(10)
    s.connect(path)
    return s
out = {}
if step == "first":
    s = connect()
    boot, pid, start = generation()
    out["firstHello"] = category(ask(s, f"HELLO {boot} {pid} {start} {secrets.token_hex(16)}"))
    nonce = secrets.token_hex(16)
    first = ask(s, f"SUBMIT {nonce} {os.getppid()}")
    out["firstPermit"] = "yes" if category(first) == "PERMIT" else "no"
    out["replaySubmit"] = category(ask(s, f"SUBMIT {nonce} {os.getppid()}"))
    token = first.split(" ")[1] if out["firstPermit"] == "yes" else "0" * 32
    out["firstOutcome"] = category(ask(s, f"OUTCOME {token} notStarted no"))
    out["replayOutcome"] = category(ask(s, f"OUTCOME {token} notStarted no"))
    kept = ask(s, f"SUBMIT {secrets.token_hex(16)} {os.getppid()}")
    out["kept"] = kept.split(" ")[1] if category(kept) == "PERMIT" else "0" * 32
    out["generation"] = f"{boot} {pid} {start}"
elif step == "later":
    token, boot, pid, start = sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
    s = connect()
    out["earlierGenerationHello"] = category(ask(s, f"HELLO {boot} {pid} {start} {secrets.token_hex(16)}"))
    s = connect()
    b, p, t = generation()
    ask(s, f"HELLO {b} {p} {t} {secrets.token_hex(16)}")
    out["earlierGenerationOutcome"] = category(ask(s, f"OUTCOME {token} notStarted no"))
elif step == "wrong":
    s = connect()
    b, p, t = generation()
    out["wrongPeer"] = category(ask(s, f"HELLO {b} {p} {t} {secrets.token_hex(16)}"))
elif step == "connect":
    try:
        connect()
        out["operatorConnect"] = "connected"
    except PermissionError:
        out["operatorConnect"] = "EACCES"
    except OSError:
        out["operatorConnect"] = "other"
sys.stdout.write(json.dumps(out))
"""


def run_client(step, socket_path, extra=(), timeout=20, **options):
    result = subprocess.run([sys.executable, "-I", "-c", CLIENT, str(socket_path), step, *extra],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, **options)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("client failed")
    value = json.loads(result.stdout)
    if type(value) is not dict or any(type(k) is not str or type(v) is not str for k, v in value.items()):
        raise ValueError("client output")
    return value


def control_observations(first, later, wrong, events, operator_connect=NA):
    """The authority-controls case from the three client runs and the authority's events."""
    ledger = next((e.get("ledger", NA) for e in events if e["event"] == "submit"
                   and e["result"] == "replay-refused"), NA)
    generation_event = ("generation-refused" if any(e["event"] == "outcome" and e["result"] == "generation-refused"
                                                    for e in events) else "missing")
    wrong_event = "wrong-peer" if any(e["event"] == "message" and e["result"] == "wrong-peer"
                                      for e in events) else "missing"
    observed = {key: first.get(key, "error") for key in ("firstHello", "replaySubmit", "firstOutcome",
                                                         "replayOutcome")}
    observed["firstPermit"] = first.get("firstPermit", "no")
    # The client reports notStarted for the first permit: the record is failed, with the reason kept.
    recorded = next((e for e in events if e["event"] == "outcome" and e["result"] == "recorded"), None)
    observed["firstOutcomePhase"] = recorded.get("phase", "missing") if recorded else "missing"
    observed["firstOutcomeReason"] = recorded.get("reason", "missing") if recorded else "missing"
    observed.update(replayLedger=ledger, earlierGenerationHello=later.get("earlierGenerationHello", "error"),
                    earlierGenerationOutcome=later.get("earlierGenerationOutcome", "error"),
                    earlierGenerationEvent=generation_event, wrongPeer=wrong.get("wrongPeer", "error"),
                    wrongPeerEvent=wrong_event, operatorConnect=operator_connect)
    return observed


def _hex_ok(value):
    return bool(re.fullmatch(r"[0-9a-f]{32}", value or ""))


def run_controls(socket_path, client_options, wrong_options, wrong_socket=None, operator_options=None, timeout=20):
    """Drives the client steps against a running authority: first, later (after the first client has
    exited), the wrong peer and, in the Root run, the operator's connect."""
    first = run_client("first", socket_path, timeout=timeout, **client_options)
    kept, generation = first.pop("kept", ""), first.pop("generation", "").split(" ")
    if not _hex_ok(kept) or len(generation) != 3:
        raise ValueError("client state")
    # The first client has exited: its generation is now an earlier one.
    later = run_client("later", socket_path, (kept, *generation), timeout=timeout, **client_options)
    wrong = run_client("wrong", wrong_socket or socket_path, timeout=timeout, **wrong_options)
    operator = (run_client("connect", socket_path, timeout=timeout, **operator_options)["operatorConnect"]
                if operator_options is not None else NA)
    return first, later, wrong, operator


# --- Non-root modes: build and self-test --------------------------------------------------------

def build_authority(work_dir, timeout=900):
    swift = shutil.which("swift")
    if swift is None:
        raise RuntimeError("swift unavailable")
    work_dir = Path(work_dir).resolve()
    for name in ("cache", "config", "security", "build", "module-cache"):
        (work_dir / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    arguments = [swift, "build", "--package-path", str(AUTHORITY_PACKAGE), "--product", AUTHORITY_PRODUCT,
                 "--cache-path", str(work_dir / "cache"), "--config-path", str(work_dir / "config"),
                 "--security-path", str(work_dir / "security"), "--scratch-path", str(work_dir / "build"),
                 "--disable-keychain", "--disable-netrc", "--force-resolved-versions", "--jobs", "4"]
    environment = {**os.environ, "CLANG_MODULE_CACHE_PATH": str(work_dir / "module-cache"),
                   "SWIFTPM_MODULECACHE_OVERRIDE": str(work_dir / "module-cache")}
    subprocess.run(arguments, stdin=subprocess.DEVNULL, check=True, timeout=timeout, env=environment)
    binary = work_dir / "build/debug" / AUTHORITY_PRODUCT
    if not os.access(binary, os.X_OK):
        raise RuntimeError("authority build produced no executable")
    return binary


class AuthorityProcess:
    """One authority on an inherited listener. stop() ends it (end of file on stdin) and returns stdout."""

    def __init__(self, binary, listener, store, owner_uid, command, frontend, marker, target, modes, **options):
        uid, gid, groups = target
        group_text = ",".join(str(g) for g in sorted(set(groups))) or "-"
        self.process = subprocess.Popen(
            [str(binary), str(listener.fileno()), str(store), str(owner_uid), str(command), str(frontend),
             str(marker), str(uid), str(gid), group_text, ",".join(modes)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            pass_fds=(listener.fileno(),), env={}, cwd="/", start_new_session=True, **options)
        self.output = bytearray()

    def read_available(self):
        """Reads whatever stdout holds now, without blocking."""
        while select.select([self.process.stdout], [], [], 0)[0]:
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                break
            self.output.extend(chunk)
            if len(self.output) > MAX_OUTPUT_BYTES:
                raise ValueError("authority output bound")

    def stop(self, timeout=10):
        with contextlib.suppress(OSError):
            self.process.stdin.close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready = select.select([self.process.stdout], [], [], max(0.0, deadline - time.monotonic()))[0]
            if not ready:
                break
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                break
            self.output.extend(chunk)
            if len(self.output) > MAX_OUTPUT_BYTES:
                raise ValueError("authority output bound")
        self.kill()
        return bytes(self.output)

    def kill(self):
        if self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self.process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.process.wait(timeout=3)
        for stream in (self.process.stdin, self.process.stdout):
            with contextlib.suppress(OSError):
                stream.close()
        return self.process.returncode is not None


def bind_listener(path, gid=None):
    """PR1's bind: 0600 first, the group, and only then 0660."""
    return SO.Host._bind(socket.SOCK_SEQPACKET, path, gid)


def authority_selftest(work_dir, binary=None, timeout=20):
    """The authority control cases as the current user, without Root. Returns the case result."""
    if os.geteuid() == 0:
        raise RuntimeError("the self-test runs without Root")
    work_dir = Path(work_dir).resolve()
    binary = Path(binary) if binary else build_authority(work_dir)
    root = work_dir / f"selftest-{secrets.token_hex(4)}"
    root.mkdir(mode=0o700, parents=True)
    uid, gid = os.getuid(), os.getgid()
    groups = sorted(set(os.getgroups()) | {gid})[:64]
    processes, listeners = [], []
    try:
        for name, owner_uid in (("a", uid), ("b", uid + 1 if uid + 1 < 2**32 - 1 else uid - 1)):
            (root / f"store-{name}").mkdir(mode=0o700)
            listener = bind_listener(root / f"{name}.sock")
            listeners.append(listener)
            processes.append(AuthorityProcess(binary, listener, root / f"store-{name}", owner_uid, binary, binary,
                                              root / "marker", (uid, gid, groups), ("normal", "normal")))
        first, later, wrong, _operator = run_controls(root / "a.sock", {}, {}, wrong_socket=root / "b.sock",
                                                      timeout=timeout)
        events = authority_events(processes[0].stop()) + authority_events(processes[1].stop())
        observed = control_observations(first, later, wrong, events)
        result = evaluate("authority-controls", observed)
        result["storeWritten"] = (root / "store-a/request-1/fixture.sqlite").is_file()
        result["passed"] = result["passed"] and result["storeWritten"]
        return result
    finally:
        for process in processes:
            process.kill()
        for listener in listeners:
            listener.close()
        shutil.rmtree(root, ignore_errors=True)


# --- Root run -----------------------------------------------------------------------------------

def _links(pid):
    """{fd number: link} of a process, read as Root; links name files, pipes and sockets by inode."""
    links = {}
    directory = f"/proc/{pid}/fd"
    for name in os.listdir(directory):
        if name.isdigit():
            with contextlib.suppress(FileNotFoundError):
                links[int(name)] = os.readlink(f"{directory}/{name}")
    return links


def _alive(pid):
    return bool(pid) and SO._alive(pid)


def _label(pid, tag):
    try:
        raw = SO.read_bounded(f"/proc/{pid}/attr/current", 4096).decode("ascii", "replace").strip("\0\n ")
    except (OSError, ValueError):
        return "other"
    if raw == "unconfined":
        return "unconfined"
    return "profile" if raw.split(" ")[0] == PROFILE_PREFIX + tag else "other"


class UnitOwner:
    """O as the main process of a transient unit; a pidfd stands in for Popen."""

    def __init__(self, pid, pidfd, stdout, unit, show):
        self.pid, self.pidfd, self.stdout, self.unit = pid, pidfd, stdout, unit
        self._show = show
        self.returncode = None

    def poll(self):
        if self.returncode is None and select.select([self.pidfd], [], [], 0)[0]:
            self.returncode = self._exit_code()
        return self.returncode

    def wait(self, timeout):
        deadline = time.monotonic() + timeout
        while self.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("owner", timeout)
            select.select([self.pidfd], [], [], min(0.2, max(0.0, deadline - time.monotonic())))
        return self.returncode

    def kill(self):
        with contextlib.suppress(ProcessLookupError, OSError):
            signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)

    def _exit_code(self):
        # systemd records the main process's end a moment after the pidfd turns readable.
        deadline = time.monotonic() + 2
        while True:
            values = self._show(self.unit, ("ExecMainCode", "ExecMainStatus", "ExecMainPID"))
            if values.get("ExecMainPID") == str(self.pid) and values.get("ExecMainCode") in ("1", "2", "3"):
                status = int(values.get("ExecMainStatus", "255") or 255)
                return status if values["ExecMainCode"] == "1" else -status
            if time.monotonic() >= deadline:
                return 255
            time.sleep(0.05)

    def close(self):
        with contextlib.suppress(OSError):
            os.close(self.pidfd)
        with contextlib.suppress(OSError):
            self.stdout.close()


def exit_category(returncode):
    if returncode is None:
        return "running"
    return {0: "ok", 3: "refused", 4: "usage", -signal.SIGKILL: "SIGKILL", -signal.SIGTERM: "SIGTERM"}.get(
        returncode, "other")


class Run:
    """Disposable host state for one measurement; cleanup removes all of it."""

    def __init__(self, operator, timeout, authority_binary, tools):
        self.operator, self.timeout, self.tools = operator, timeout, tools
        self.authority_source = Path(authority_binary)
        self.tag = secrets.token_hex(4)
        self.base = base_for(self.tag)
        self.owner_name, self.authority_name = f"rmzso{self.tag}", f"rmzsa{self.tag}"
        self.base_created = self.owner_created = self.authority_created = False
        self.uid_shared = False
        self.units, self.profile, self.profile_loaded = [], None, False
        self.build_hashes = {}

    # Setup ---------------------------------------------------------------------------------

    def setup(self):
        self.groups = os.getgrouplist(self.operator.pw_name, self.operator.pw_gid)
        if len(self.groups) > SO.MAX_GROUPS:
            raise RuntimeError("too many operator groups")
        os.mkdir(self.base, 0o755)
        self.base_created = True
        os.chmod(self.base, 0o755)
        for name, mode in (("build", 0o700), ("run", 0o755), ("cases", 0o755), ("profiles", 0o700)):
            os.mkdir(self.base / name, mode)
            os.chmod(self.base / name, mode)
        self.build_hashes = {"sources": {}, "binaries": {}}
        for name, (source, extra) in BUILDS.items():
            copy, output = self.base / "build" / f"{name}.c", self.base / "build" / name
            data = source.read_bytes()
            PL.write_root_file(copy, data, 0o600)
            self.build_hashes["sources"][name] = hashlib.sha256(data).hexdigest()
            if PL.run_owned([self.tools["cc"], *SO.CC_FLAGS, *extra, "-o", str(output), str(copy)],
                            min(60, 4 * self.timeout))[0] != 0:
                raise RuntimeError("fixture build failed")
            binary = output.read_bytes()
            self.build_hashes["binaries"][name] = hashlib.sha256(binary).hexdigest()
            if name == "command":
                for alias in COMMANDS:
                    PL.write_root_file(self.base / "run" / alias, binary, 0o755)
            else:
                PL.write_root_file(self.base / "run" / name, binary, 0o755)
        authority = SO.read_bounded(self.authority_source, 256 * 1024 * 1024)
        self.build_hashes["binaries"]["authority"] = hashlib.sha256(authority).hexdigest()
        PL.write_root_file(self.base / "run" / "authority", authority, 0o755)
        for flag, name in (("owner_created", self.owner_name), ("authority_created", self.authority_name)):
            PL.Run._create(self, flag, [self.tools["useradd"], "--system", "--no-create-home", "--home-dir", "/",
                                        "--shell", "/usr/sbin/nologin", "--user-group", name], (name,))
        owner, authority_account = pwd.getpwnam(self.owner_name), pwd.getpwnam(self.authority_name)
        self.owner_uid, self.owner_gid = owner.pw_uid, owner.pw_gid
        self.authority_uid, self.authority_gid = authority_account.pw_uid, authority_account.pw_gid
        if 0 in (self.owner_uid, self.owner_gid, self.authority_uid, self.authority_gid):
            raise RuntimeError("disposable identity is privileged")
        # PR1's condition: cleanup kills by UID, so it must never start from a UID already in use.
        if SO._user_processes(self.owner_uid, Path("/proc")) or SO._user_processes(self.authority_uid, Path("/proc")):
            self.uid_shared = True
            sys.stderr.write("A new disposable UID already has running processes. The run stops and kills "
                             "nothing by UID.\n")
            raise RuntimeError("disposable UID already in use")
        markers = self.base / "markers"
        os.mkdir(markers, 0o700)
        os.chown(markers, self.operator.pw_uid, self.operator.pw_gid)
        self.markers = markers
        apparmor = self._load_profile()
        operator_groups = set(self.groups)
        return {"serviceIdentitiesUnprivileged": True,
                "serviceOutsideOperatorGroups": self.owner_gid not in operator_groups
                and self.authority_gid not in operator_groups,
                "operatorUnprivileged": self.operator.pw_uid != 0 and 0 not in operator_groups,
                "apparmorProfileLoaded": apparmor}

    def _load_profile(self):
        """Kernel only (-K: no cache); -a refuses an existing name. Recorded before the tool runs."""
        if self.tools.get("apparmor_parser") is None or not (APPARMOR / "profiles").exists():
            return False
        self.profile, text = render_profile(APPARMOR_TEMPLATE.read_text(), self.tag, self.base)
        path = self.base / "profiles" / self.profile
        PL.write_root_file(path, text.encode(), 0o600)
        self.build_hashes["profile"] = hashlib.sha256(text.encode()).hexdigest()
        self.profile_loaded = True
        if PL.run_owned([self.tools["apparmor_parser"], "-a", "-K", str(path)], self.timeout)[0] != 0:
            raise RuntimeError("profile load failed")
        return self.profile in self._loaded_profiles()

    @staticmethod
    def _loaded_profiles():
        text = SO.read_bounded(APPARMOR / "profiles", 4 * 1024 * 1024).decode("utf-8", "replace")
        return {line.rpartition(" (")[0] for line in text.splitlines()}

    def _remove_profile(self):
        if not self.profile_loaded:
            return True
        try:
            if self.profile in self._loaded_profiles():
                with (APPARMOR / ".remove").open("w") as stream:
                    stream.write(self.profile)
            return self.profile not in self._loaded_profiles()
        except (OSError, ValueError):
            return False

    # Units ---------------------------------------------------------------------------------

    def show(self, unit, properties):
        code, output = PL.run_owned([self.tools["systemctl"], "show", f"--property={','.join(properties)}", unit],
                                    self.timeout)
        if code != 0:
            return {}
        try:
            return parse_show(output.decode("ascii", "replace"))
        except ValueError:
            return {}

    def systemctl(self, *arguments):
        return PL.run_owned([self.tools["systemctl"], *arguments], self.timeout)[0]

    def unit_name(self, case):
        return f"rmzso-{self.tag}-{case}.service"

    def start_owner(self, case, spec, directory, fds):
        """systemd-run starts the shim as the unit's main process; the shim receives O's descriptors
        over a rendezvous socket and replaces itself with O. Returns a UnitOwner."""
        stdout_write, listener, control_owner, log_fd = fds
        unit = self.unit_name(case)
        rendezvous = bind_listener(directory / "shim.sock", self.owner_gid)
        try:
            properties = unit_properties(self.owner_name, self.owner_name, spec["extra"], self.profile)
            arguments = [str(self.base / "run/fdshim"), str(directory / "shim.sock"), str(self.base / "run/owner"),
                         "3", str(directory / "authority.sock"), "4", "5", str(len(spec["modes"])),
                         str(DEADLINE_MS), str(self.base / "run" / spec["command"]), str(self.markers / case)]
            self.units.append(unit)  # recorded before the tool runs, so cleanup reaches it
            if PL.run_owned(unit_command(self.tools["systemd-run"], unit, properties, arguments),
                            self.timeout)[0] != 0:
                raise RuntimeError("unit start failed")
            if not select.select([rendezvous], [], [], self.timeout)[0]:
                raise TimeoutError()
            connection, _ = rendezvous.accept()
            connection.settimeout(self.timeout)
            with connection:
                pidfd = connection.getsockopt(socket.SOL_SOCKET, 77)
                credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                pid, uid, _gid = (int.from_bytes(credentials[i:i + 4], sys.byteorder) for i in (0, 4, 8))
                if uid != self.owner_uid or SO._pidfd_pid(pidfd) != pid or connection.recv(16) != b"SHIM\n":
                    os.close(pidfd)
                    raise RuntimeError("unexpected shim peer")
                socket.send_fds(connection, [b"FDS\n"], [stdout_write, listener, control_owner, log_fd])
        finally:
            rendezvous.close()
        return UnitOwner(pid, pidfd, None, unit, self.show)

    def retire_unit(self, unit):
        """Every process of the unit's cgroup is killed (KillMode=process leaves commands there), then
        the unit is stopped and its failed state reset. True once the unit is gone."""
        procs = CGROUP_SYSTEM / unit / "cgroup.procs"
        deadline = time.monotonic() + 3
        while True:
            try:
                pids = [int(item) for item in SO.read_bounded(procs, 65536).split()]
            except FileNotFoundError:
                pids = []
            except (OSError, ValueError):
                pids = []
            for pid in pids:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid, signal.SIGKILL)
            if not pids or time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        self.systemctl("stop", unit)
        self.systemctl("reset-failed", unit)
        return self.show(unit, ("LoadState",)).get("LoadState") in ("not-found", None)

    def start_frontend(self, socket_path):
        """C as the operator; three distinct pipes, so every stream has its own identity."""
        return subprocess.Popen([str(self.base / "run/frontend"), str(socket_path)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, user=self.operator.pw_uid,
                                group=self.operator.pw_gid, extra_groups=self.groups, env={}, cwd="/",
                                start_new_session=True)

    def start_authority(self, case, directory, spec, listener):
        store = directory / "store"
        os.mkdir(store, 0o700)
        os.chown(store, self.authority_uid, self.authority_gid)
        return AuthorityProcess(self.base / "run/authority", listener, store, self.owner_uid,
                                self.base / "run" / spec["command"], self.base / "run/frontend",
                                self.markers / case, (self.operator.pw_uid, self.operator.pw_gid, self.groups),
                                spec["modes"] if spec["kind"] == "owner" else ("normal", "normal"),
                                user=self.authority_uid, group=self.authority_gid, extra_groups=[])

    # Cases ---------------------------------------------------------------------------------

    def run_case(self, case, last_cap, host_mnt):
        directory = self.base / "cases" / case
        os.mkdir(directory, 0o755)
        if CASES[case]["kind"] == "controls":
            return self.controls_case(case, directory)
        if "apparmor" in CASES[case]["extra"] and not self.profile_loaded:
            return {"passed": False, "status": "not-run", "reason": "apparmor-unavailable"}
        return drive_case(case, self, directory, last_cap, host_mnt)

    def controls_case(self, case, directory):
        listener = bind_listener(directory / "authority.sock", self.owner_gid)
        authority = None
        try:
            authority = self.start_authority(case, directory, CASES[case], listener)
            service = {"user": self.owner_uid, "group": self.owner_gid, "extra_groups": [], "env": {}, "cwd": "/"}
            operator = {"user": self.operator.pw_uid, "group": self.operator.pw_gid, "extra_groups": self.groups,
                        "env": {}, "cwd": "/"}
            # The wrong peer is Root: the socket mode lets it connect, the authority's UID check refuses it.
            first, later, wrong, operator_connect = run_controls(directory / "authority.sock", service,
                                                                 {"env": {}, "cwd": "/"},
                                                                 operator_options=operator, timeout=self.timeout)
            events = authority_events(authority.stop())
            observed = control_observations(first, later, wrong, events, operator_connect)
            result = evaluate(case, observed)
            if operator_connect != "EACCES":
                result["passed"] = False
                result.setdefault("mismatches", []).append("operatorConnect")
            return result
        except (ValueError, OSError, subprocess.SubprocessError):
            return {"passed": False, "error_type": "CaseFailure"}
        finally:
            if authority is not None:
                authority.kill()
            listener.close()

    # Cleanup -------------------------------------------------------------------------------

    def cleanup(self):
        """Each step runs even when an earlier one fails; only state this run created is touched."""
        units = all([_step(self.retire_unit, unit) for unit in self.units])
        profile = _step(self._remove_profile)
        gone = not self.uid_shared
        for created, name in ((self.owner_created, self.owner_name), (self.authority_created, self.authority_name)):
            if created and not self.uid_shared:
                with contextlib.suppress(KeyError):
                    try:
                        gone = SO._kill_user(pwd.getpwnam(name).pw_uid) and gone
                    except OSError:
                        gone = False
        if self.base_created:
            PL._attempt(shutil.rmtree, self.base)
        for created, name in ((self.owner_created, self.owner_name), (self.authority_created, self.authority_name)):
            if created and not PL._absent(pwd.getpwnam, name):
                PL._attempt(PL.run_owned, [self.tools["userdel"], name], self.timeout)
            if created and not PL._absent(grp.getgrnam, name):
                PL._attempt(PL.run_owned, [self.tools["groupdel"], name], self.timeout)
        accounts = all(PL._absent(pwd.getpwnam, n) and PL._absent(grp.getgrnam, n)
                       for n in (self.owner_name, self.authority_name))
        return {"unitsRemoved": units, "profileRemoved": profile, "filesRemoved": not self.base.exists(),
                "serviceUsersRemoved": accounts, "serviceProcessesGone": gone}


def _step(action, *arguments):
    """One cleanup step: False when it fails, so the next step still runs."""
    try:
        return bool(action(*arguments))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        return False


def drive_case(case, run, directory, last_cap, host_mnt):
    """One case through O's barriers, with O in its unit and the Swift authority. Always retires
    what it started."""
    spec = CASES[case]
    dispatches = len(spec["modes"])
    log_path, listen_path = directory / "restart.log", directory / "frontend.sock"
    observed = {key: NA for key in CASE_KEYS}
    observed.update(authorityHello="missing", markerLines="0", ownerIsMainPID="no")
    owner = authority = None
    frontends, frontend_out = [], []
    pids = {"c": {}, "k": {}}
    snapshots = {}
    owner_out = bytearray()
    sockets, error = [], None
    deadline = time.monotonic() + run.timeout
    stdout_read = None
    try:
        try:
            listener = SO.Host._bind(socket.SOCK_STREAM, listen_path, run.operator.pw_gid)
            sockets.append(listener)
            authority_listener = bind_listener(directory / "authority.sock", run.owner_gid)
            sockets.append(authority_listener)
            authority = run.start_authority(case, directory, spec, authority_listener)
            control_owner, control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            sockets += [control_owner, control]
            stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
            try:
                os.fchown(log_fd, run.owner_uid, run.owner_gid)
                owner = run.start_owner(case, spec, directory,
                                        (stdout_write, listener.fileno(), control_owner.fileno(), log_fd))
            finally:
                os.close(log_fd)
                os.close(stdout_write)
            owner.stdout = os.fdopen(stdout_read, "rb", buffering=0)
            stdout_read = None
            control_owner.close()
            main_pid = run.show(owner.unit, ("MainPID",)).get("MainPID")
            observed["ownerIsMainPID"] = "yes" if main_pid == str(owner.pid) else "no"
            if spec["extra"] == ():
                observed["unitReadback"] = "yes" if readback_matches(run.show(owner.unit, SHOW_PROPERTIES)) else "no"
                with contextlib.suppress(OSError, ValueError):
                    nr_open = int(Path("/proc/sys/fs/nr_open").read_text())
                    observed["ownerLimitsMax"] = "yes" if limits_at_max(SO.read_limits(owner.pid), nr_open) else "no"
            if "apparmor" in spec["extra"]:
                observed["ownerLabel"] = _label(owner.pid, run.tag)
            with selectors.DefaultSelector() as selector:
                selector.register(owner.stdout, selectors.EVENT_READ, "owner")
                selector.register(control, selectors.EVENT_READ, "control")
                open_streams = {"owner", "control"}
                while open_streams & {"owner", "control"}:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    authority.read_available()
                    for key, _events in selector.select(min(remaining, 0.5)):
                        tag = key.data
                        if tag == "owner" or isinstance(tag, int):
                            buffer = owner_out if tag == "owner" else frontend_out[tag]
                            chunk = os.read(key.fd, 4096)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                open_streams.discard(tag)
                            buffer.extend(chunk)
                            if len(buffer) > MAX_OUTPUT_BYTES:
                                raise ValueError("output bound")
                            continue
                        try:
                            message = control.recv(256)
                        except ConnectionError:
                            message = b""
                        if not message:
                            selector.unregister(control)
                            open_streams.discard("control")
                            continue
                        match = SO.BARRIER_MESSAGE.fullmatch(message)
                        if not match or match[1].decode() not in SO.BARRIERS:
                            raise ValueError("bad barrier")
                        name, number = match[1].decode(), int(match[2])
                        if int(match[3]):
                            pids["c"][number] = int(match[3])
                        if int(match[4]):
                            pids["k"].setdefault(number, int(match[4]))
                        resume = True
                        if name == "start" or (name == "after-s6" and number < dispatches):
                            frontend = run.start_frontend(listen_path)
                            frontends.append(frontend)
                            frontend_out.append(bytearray())
                            index = len(frontends) - 1
                            selector.register(frontend.stdout, selectors.EVENT_READ, index)
                            open_streams.add(index)
                        if name == "k-ready" and dispatches == 2:
                            with contextlib.suppress(OSError, KeyError):
                                snapshot = {"owner": _links(owner.pid), "k": _links(pids["k"][number]),
                                            "c": _links(pids["c"][number])}
                                if number == 2:
                                    snapshot["command1"] = _links(pids["k"][1])
                                snapshots[number] = snapshot
                        for barrier, action in spec["actions"]:
                            if barrier == name:
                                resume = _act(action, run, owner, pids, observed, deadline) and resume
                        if resume:
                            control.send(b"C")
                with contextlib.suppress(subprocess.TimeoutExpired):
                    owner.wait(timeout=max(0.1, deadline - time.monotonic()))
                # Each command's report comes before it sleeps or ends; wait for every line.
                for index in range(len(frontends)):
                    while b"\n" not in frontend_out[index] and index in open_streams:
                        _drain(selector, frontend_out, open_streams, deadline)
                for number, mode in enumerate(spec["modes"], start=1):
                    k = pids["k"].get(number)
                    if k and mode != "sleep" and observed["ownerExit"] != "SIGKILL":
                        _wait_gone(k, deadline)
            authority_raw = authority.stop()
        except (TimeoutError, subprocess.TimeoutExpired):
            error = "TimeoutError"
        except (ValueError, OSError, RuntimeError):
            error = "CaseFailure"
    finally:
        with PL.deferred_cancel():
            clean = _retire_case(run, owner, authority, frontends, pids, sockets)
            if stdout_read is not None:
                os.close(stdout_read)
    if error:
        return {"passed": False, "error_type": error, "cleanupReapedAllFixtureProcesses": clean}
    try:
        start, reports = owner_reports(bytes(owner_out), dispatches)
        observed.update(start)
        events = authority_events(authority_raw)
        summary, per_authority = authority_summary(events, dispatches)
        observed.update(summary)
        observed["restartLogClean"] = restart_log_clean_all(SO.read_bounded(log_path), dispatches) \
            if log_path.exists() else NA
        observed.update(fd_checks(snapshots.get(1), snapshots.get(2)) if dispatches == 2 else {})
        items = []
        for number in range(1, dispatches + 1):
            item = {key: NA for key in DISPATCH_KEYS}
            item.update(reports[number - 1] if number <= len(reports) else {})
            item.update(per_authority[number - 1])
            raw = bytes(frontend_out[number - 1]) if number <= len(frontend_out) else b""
            item.update(command_checks(raw, last_cap, host_mnt, run.tag))
            frontend = frontends[number - 1] if number <= len(frontends) else None
            item["frontendExit"] = (SO._exit_category(frontend.returncode) if frontend is not None
                                    else "not-started")
            items.append(item)
        observed["dispatches"] = items
    except (ValueError, UnicodeDecodeError, OSError):
        return {"passed": False, "error_type": "InvalidReport", "cleanupReapedAllFixtureProcesses": clean}
    if observed["ownerExit"] == NA:
        observed["ownerExit"] = exit_category(owner.returncode)
    try:
        lines = SO.read_bounded(run.markers / case).count(b"\n")
    except FileNotFoundError:
        lines = 0
    except (OSError, ValueError):
        return {"passed": False, "error_type": "InvalidMarker", "cleanupReapedAllFixtureProcesses": clean}
    observed["markerLines"] = str(lines) if lines <= 2 else "more"
    result = evaluate(case, observed)
    result["cleanupReapedAllFixtureProcesses"] = clean
    result["passed"] = result["passed"] and clean
    return result


def _drain(selector, buffers, open_streams, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    for key, _events in selector.select(min(remaining, 0.5)):
        if not isinstance(key.data, int):
            selector.unregister(key.fileobj)  # O is gone: only the commands' output matters now
            continue
        chunk = os.read(key.fd, 4096)
        if not chunk:
            selector.unregister(key.fileobj)
            open_streams.discard(key.data)
        buffers[key.data].extend(chunk)
        if len(buffers[key.data]) > MAX_OUTPUT_BYTES:
            raise ValueError("output bound")


def _wait_gone(pid, deadline):
    while _alive(pid):
        if time.monotonic() >= deadline:
            raise TimeoutError()
        time.sleep(0.01)


def _act(action, run, owner, pids, observed, deadline):
    """One action at a barrier. Returns False when O must not be resumed."""
    if action not in ACTIONS:
        raise ValueError("unknown action")
    if action == "kill-owner":
        owner.kill()
        owner.wait(timeout=max(0.1, deadline - time.monotonic()))
        observed["ownerExit"] = exit_category(owner.returncode)
        return False
    command = pids["k"].get(1)
    if action == "unit-stop":
        run.systemctl("stop", owner.unit)
        owner.wait(timeout=max(0.1, deadline - time.monotonic()))
        observed["ownerGoneAfterUnitAction"] = "yes"
        observed["ownerExit"] = exit_category(owner.returncode)
        observed["commandAliveAfterStop"] = "yes" if _alive(command) else "no"
        return False
    if action == "unit-restart":
        run.systemctl("restart", owner.unit)
        owner.wait(timeout=max(0.1, deadline - time.monotonic()))
        observed["ownerGoneAfterUnitAction"] = "yes"
        observed["ownerExit"] = exit_category(owner.returncode)
        # The restarted shim finds no rendezvous and exits; the unit did start a new main process.
        started = run.show(owner.unit, ("ExecMainPID",)).get("ExecMainPID", "0")
        observed["unitRestarted"] = "yes" if started.isdigit() and started not in ("0", str(owner.pid)) else "no"
        observed["commandAliveAfterRestart"] = "yes" if _alive(command) else "no"
        return False
    # oom-check: at O's end barrier, after the hog was dispatched. Wait for the kernel's kill.
    hog = pids["k"].get(2)
    with contextlib.suppress(TimeoutError):
        _wait_gone(hog, deadline)
    events = CGROUP_SYSTEM / owner.unit / "memory.events"
    try:
        text = SO.read_bounded(events, 4096).decode("ascii")
        match = re.search(r"^oom_kill ([0-9]{1,20})$", text, re.MULTILINE)
        observed["oomKill"] = "yes" if match and int(match[1]) > 0 else "no"
    except (OSError, ValueError):
        observed["oomKill"] = "no"
    observed["ownerAliveAfterOom"] = "yes" if owner.poll() is None else "no"
    observed["commandAliveAfterOom"] = "yes" if _alive(command) else "no"
    state = run.show(owner.unit, ("ActiveState", "Result"))
    observed["unitActiveAfterOom"] = "yes" if state.get("ActiveState") == "active" and \
        state.get("Result") == "success" else "no"
    return True


def _retire_case(run, owner, authority, frontends, pids, sockets):
    """O first (no new K after it), then every command's session, the unit's cgroup, C and A."""
    clean = True
    if owner is not None:
        owner.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            owner.wait(timeout=3)
    for k in pids["k"].values():
        SO._end_session(k)
    if owner is not None:
        clean = _step(run.retire_unit, owner.unit) and clean
        owner.close()
    for frontend in frontends:
        if frontend.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                frontend.kill()
        try:
            frontend.wait(timeout=3)
        except subprocess.TimeoutExpired:
            clean = False
        for stream in (frontend.stdin, frontend.stdout, frontend.stderr):
            with contextlib.suppress(OSError):
                stream.close()
    for k in pids["k"].values():
        clean = SO._reap(k, time.monotonic() + 3) and clean
    if authority is not None:
        clean = authority.kill() and clean
    for item in sockets:
        item.close()
    return clean


def measure(timeout=30, authority_binary=None, run_factory=Run):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("requires Linux x86_64")
    if os.geteuid() != 0 or os.getuid() != 0:
        raise RuntimeError("requires root")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 20 <= timeout <= 120:
        raise ValueError("timeout must be at least 20 and at most 120 seconds")
    if authority_binary is None or not Path(authority_binary).is_file():
        raise ValueError("--authority must name the authority built with --build-authority")
    tools = {name: shutil.which(name, path=PL.TOOL_ENV["PATH"]) for name in TOOLS}
    missing = sorted(name for name, path in tools.items() if path is None and name != "apparmor_parser")
    if missing:
        raise RuntimeError("tools unavailable")
    operator = PL.operator_account()
    if not PL.root_owned_ancestry(BASE_PARENT):
        raise RuntimeError("experiment parent must be root-owned")
    host = PL.host_metadata()
    last_cap = SO.last_capability()
    host_mnt = os.readlink("/proc/1/ns/mnt")
    scripts = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in (Path(__file__).resolve(), PR1_RUNNER, SO.PROTECTED_RUNNER, APPARMOR_TEMPLATE)}
    run = run_factory(operator, timeout, authority_binary, tools)
    setup, cases, cleanup = {}, {}, {}
    with PL.subreaper():
        try:
            setup = run.setup()
            required = {key: value for key, value in setup.items() if key != "apparmorProfileLoaded"}
            if all(required.values()):
                cases = {case: run.run_case(case, last_cap, host_mnt) for case in CASES}
        finally:
            with PL.deferred_cancel():
                cleanup = run.cleanup()
                if not all(cleanup.values()):
                    sys.stderr.write(f"Disposable state not fully removed: see the cleanup steps in {__file__}.\n")
    passed, strict = admission(cases, setup, cleanup)
    return {"experiment": "linux-single-owner-v2",
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "supervised": True, "trustedCode": False, "strictAdmission": strict, "productionAdmission": False,
            "host": host, "scripts": scripts, "builds": run.build_hashes, "setup": setup, "cases": cases,
            "cleanup": cleanup, "passed": passed,
            "knownLimits": list(KNOWN_LIMITS),
            "limits": ["transient units through systemd-run, not an installed unit or installer setting",
                       "synthetic capture and software decision keys in the authority; no phone approval",
                       "a second dispatch while the first command runs, not two preparations at the same time",
                       "the sudo child's full Root capability sets are not measured",
                       "one host, one kernel"]}


def _cancel(_signum, _frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build-authority", action="store_true", help="build the Swift authority (no root)")
    mode.add_argument("--authority-selftest", action="store_true",
                      help="build the authority and run its control cases (no root)")
    mode.add_argument("--authority", help="the supervised Root run with this authority binary")
    parser.add_argument("--work-dir", help="build directory for the two non-root modes (absolute)")
    parser.add_argument("--timeout", type=float, default=30, help="seconds per case (20 <= timeout <= 120)")
    args = parser.parse_args()
    if args.build_authority or args.authority_selftest:
        if not args.work_dir or not os.path.isabs(args.work_dir):
            parser.error("--work-dir must be an absolute path")
        try:
            if args.build_authority:
                print(build_authority(args.work_dir))
                return 0
            result = authority_selftest(args.work_dir)
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
            parser.exit(2, f"Single-owner authority self-test failed: {type(error).__name__}.\n")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1
    previous = {number: signal.signal(number, _cancel) for number in (signal.SIGTERM, signal.SIGHUP)}
    try:
        try:
            report = measure(args.timeout, args.authority)
        except KeyboardInterrupt:
            parser.exit(130, "Single-owner PR2 experiment cancelled.\n")
        except (RuntimeError, ValueError, OSError, KeyError, subprocess.SubprocessError):
            parser.exit(2, "Single-owner PR2 experiment unavailable; no raw diagnostic data published.\n")
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
