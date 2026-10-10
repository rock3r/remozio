#!/usr/bin/env python3
"""Join the real frontend, authority journal and native target without installing services."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "experiments/command-frontend"
NATIVE = ROOT / "macos/core/Sources/RemozioMach"
BUILD = ROOT / ".build/live-command-frontend"
TRIALS = 3


def build():
    BUILD.mkdir(parents=True, exist_ok=True)
    arguments = ["swift", "build", "--package-path", str(PACKAGE), "--triple", "arm64-apple-macosx26.0",
                 "--disable-keychain", "--disable-netrc", "--product", "LiveCommandFixture"]
    result = subprocess.run(arguments, capture_output=True, text=True)
    log = BUILD / "swift-build.log"
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"Live frontend build failed; see {log}")
    location = subprocess.run(arguments + ["--show-bin-path"], check=True, capture_output=True, text=True)
    binary = Path(location.stdout.strip()) / "LiveCommandFixture"
    sources = {
        "monitor": [PACKAGE / "live-monitor.c", NATIVE / "CommandProcess.c",
                    NATIVE / "CommandChildSpecification.c", NATIVE / "CommandMonitorProtocol.c"],
        "child": [PACKAGE / "live-child.c", NATIVE / "CommandChildSpecification.c"],
        "target": [PACKAGE / "live-target.c"],
        "supervisor": [PACKAGE / "job-supervisor.c"],
    }
    helpers = {}
    for name, paths in sources.items():
        path = BUILD / name
        compiler = subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
                                   "-DREMOZIO_OWNED_LIVE_FIXTURE=1", "-I", str(NATIVE / "include"),
                                   *(str(item) for item in paths), "-o", str(path)], capture_output=True, text=True)
        if compiler.returncode:
            raise RuntimeError(f"{name} build failed: {compiler.stdout}{compiler.stderr}")
        helpers[name] = path
        # Finish first-launch policy evaluation before starting bounded request deadlines.
        probe = subprocess.run([str(path)], capture_output=True, timeout=15)
        if probe.returncode != 64:
            raise RuntimeError(f"{name} first launch returned {probe.returncode}")
    return binary, helpers


def invoke(binary, helpers, mode):
    target = "/bin/bash" if mode == "nested" else str(helpers["target"])
    process = subprocess.Popen([str(binary), "authority", mode, str(helpers["supervisor"]), str(helpers["monitor"]),
                                str(helpers["child"]), target], cwd="/private/tmp",
                               env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        output, errors = process.communicate(timeout=60)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        # The authority remains alive to supervise cancellation and reap the actual monitor and target.
        process.send_signal(signal.SIGTERM)
        output, errors = process.communicate(timeout=20)
        raise
    if process.returncode:
        raise RuntimeError(f"Live frontend returned {process.returncode}: {errors.decode(errors='replace')}")
    observations = json.loads(output)
    if observations.get("nativeSupervisorStatus") != 13 << 8 or observations.get("oneOriginalAdmission") is not True:
        raise RuntimeError(f"Incomplete native result: {observations!r}")
    for field in ["separateAuthorityAndFrontend", "actualMonitorAndTargetReaped", "durableVerifiedOutcome"]:
        if observations.get(field) is not True:
            raise RuntimeError(f"Missing live ownership evidence: {field}")
    frontend = observations["frontend"]
    if frontend.get("frontendCleanupCompleted") is not True:
        raise RuntimeError("Frontend cleanup was not verified")
    if mode == "nested":
        confirmed = (frontend["nestedPhase"] == 6 and frontend["nestedUnknownQueries"] == 1 and
                     frontend["freshRunningQueries"] == 1 and frontend["originalStopEvents"] == 0)
    else:
        confirmed = frontend["freshStoppedQueries"] >= 1 if mode == "job" else (
            frontend["freshStoppedQueries"] == 0 and frontend["freshRunningQueries"] >= 1)
    if not confirmed or frontend["originalContinuations"] != (0 if mode == "nested" else 1):
        raise RuntimeError(f"Incomplete stop/continue evidence: {frontend!r}")
    return observations


def main():
    if os.geteuid() == 0:
        raise RuntimeError("This experiment must run unprivileged")
    evidence_path = BUILD / "evidence.json"
    evidence_path.unlink(missing_ok=True)
    binary, helpers = build()
    files = [Path(__file__), PACKAGE / "Sources/LiveCommandFixture/Main.swift", PACKAGE / "Sources/OwnedTTY/Supervisor.c",
             PACKAGE / "job-supervisor.c", PACKAGE / "live-monitor.c", PACKAGE / "live-child.c", PACKAGE / "live-target.c",
             ROOT / "macos/app/CommandMonitor/MonitorMain.c", ROOT / "macos/app/CommandChild/ChildMain.c",
             NATIVE / "CommandProcess.c", NATIVE / "CommandMonitor.c", NATIVE / "CommandMonitorProtocol.c",
             *(ROOT / "macos/core/Sources/RemozioCore" / name for name in ["CommandExecution.swift", "AuthorityJournal.swift",
               "CommandReceiveHost.swift", "CommandCallerReadiness.swift", "CommandFrontendMain.swift", "CommandFrontendRelay.swift"])]
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    cases = {}
    for mode in ["job", "stale", "nested"]:
        observations = [invoke(binary, helpers, mode) for _ in range(TRIALS)]
        if any(value != observations[0] for value in observations[1:]):
            raise RuntimeError(f"Live frontend observations changed between {mode} trials: {observations!r}")
        cases[mode] = {"trials": TRIALS, "allTrialsMatch": True, "observations": observations[0]}
    for path in files:
        if hashlib.sha256(path.read_bytes()).hexdigest() != hashes[str(path.relative_to(ROOT))]:
            raise RuntimeError("A live frontend source changed during measurement")
    evidence = {"recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "runtime": platform.mac_ver()[0],
                "architecture": platform.machine(), "deploymentTarget": "arm64-apple-macosx26.0",
                "privilegedExecution": False, "biometricsTested": False, "bootstrapDiscoveryTested": False,
                "credentialOperations": "same-user fixture seams",
                "cases": cases, "sourceHashes": hashes}
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Live frontend, authority and target passed. Evidence: {evidence_path}")


if __name__ == "__main__":
    main()
