#!/usr/bin/env python3
"""Run the Debug-only frontend loop with anonymous, unprivileged Mach peers."""
import datetime
import json
import os
from pathlib import Path
import platform
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "experiments/command-frontend"
BUILD = ROOT / ".build/command-frontend"


def invoke(binary, mode, expected_status, supervisor=None):
    arguments = [os.fsencode(binary), mode.encode(), b"sudo" if mode == "signal" else b"run",
                 b"--uid", b"1234", b"--env", b"RAW=\xfe\x22", b"--", b"true", b"", b"\xff\x0a\x80"]
    if supervisor is not None:
        arguments.insert(0, os.fsencode(supervisor))
    process = subprocess.Popen(arguments, cwd="/private/tmp", env={**os.environ, "PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        output, errors = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            # This process group was created for this owned fixture only.
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
    if process.returncode != expected_status:
        raise RuntimeError(f"Frontend fixture {mode}: status {process.returncode}; {errors.decode(errors='replace')}")
    observations = json.loads(output)
    pty_checked = observations.pop("privatePTYChecked", None)
    if pty_checked is not mode.startswith("pty"):
        raise RuntimeError(f"Wrong terminal fixture mode: {mode}")
    cleanup_checked = observations.pop("interruptedCleanupChecked", None)
    if cleanup_checked is not (mode == "pty-cleanup"):
        raise RuntimeError(f"Wrong cleanup fixture mode: {mode}")
    failed_connection_checked = observations.pop("failedConnectionCleanupChecked", None)
    if failed_connection_checked is not (mode == "pty-failure"):
        raise RuntimeError(f"Wrong failed connection fixture mode: {mode}")
    suspend_retry_checked = observations.pop("suspendRestorationRetryChecked", None)
    if suspend_retry_checked is not (mode == "pty-suspend-retry"):
        raise RuntimeError(f"Wrong suspend retry fixture mode: {mode}")
    confirmed_job_checked = observations.pop("confirmedJobChecked", None)
    if confirmed_job_checked is not mode.startswith("pty-job"):
        raise RuntimeError(f"Wrong confirmed job fixture mode: {mode}")
    confirmed_job_retry_checked = observations.pop("confirmedJobRetryChecked", None)
    if confirmed_job_retry_checked is not (mode == "pty-job-retry"):
        raise RuntimeError(f"Wrong confirmed job retry fixture mode: {mode}")
    expected = {"authenticatedComposedLoop", "actualArgvAndDirectoryCaptured", "rawClaimsPreserved", "busyThenOneAdmission",
                "pipeInputUnread", "originalFlagsPreserved", "cleanupCompleted"}
    if set(observations) != expected or any(value is not True for value in observations.values()):
        raise RuntimeError(f"Incomplete frontend fixture {mode}: {observations!r}")
    return {"nativeStatus": process.returncode, "observations": observations,
            "privatePTYChecked": pty_checked, "interruptedCleanupChecked": cleanup_checked, "failedConnectionCleanupChecked": failed_connection_checked, "suspendRestorationRetryChecked": suspend_retry_checked,
            "confirmedJobChecked": confirmed_job_checked, "confirmedJobRetryChecked": confirmed_job_retry_checked}


def main():
    if os.geteuid() == 0:
        raise RuntimeError("This experiment must run unprivileged")
    BUILD.mkdir(parents=True, exist_ok=True)
    path = BUILD / "evidence.json"
    path.unlink(missing_ok=True)
    arguments = ["swift", "build", "--package-path", str(PACKAGE), "--triple", "arm64-apple-macosx26.0",
                 "--disable-keychain", "--disable-netrc"]
    result = subprocess.run(arguments, capture_output=True, text=True)
    log = BUILD / "swift-build.log"
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"Frontend fixture build failed; see {log}\n{result.stdout}{result.stderr}")
    location = subprocess.run(arguments + ["--show-bin-path"], check=True, capture_output=True, text=True)
    binary = Path(location.stdout.strip()) / "CommandFrontendFixture"
    supervisor = BUILD / "job-supervisor"
    subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
                    str(PACKAGE / "job-supervisor.c"), "-o", str(supervisor)], check=True, capture_output=True, text=True)
    evidence = {"recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "runtime": platform.mac_ver()[0], "architecture": platform.machine(),
                "deploymentTarget": "arm64-apple-macosx26.0", "privilegedExecution": False,
                "pipes": invoke(binary, "pipes", 13), "signal": invoke(binary, "signal", -signal.SIGINT),
                "pty": invoke(binary, "pty", 13), "ptyCleanup": invoke(binary, "pty-cleanup", 13), "ptyFailure": invoke(binary, "pty-failure", os.EX_PROTOCOL),
                "ptySuspendRetry": invoke(binary, "pty-suspend-retry", 13),
                "ptyConfirmedJob": invoke(binary, "pty-job", 13, supervisor),
                "ptyConfirmedJobRetry": invoke(binary, "pty-job-retry", 13, supervisor)}
    path.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Composed frontend Mach loop and native signal result passed. Evidence: {path}")


if __name__ == "__main__":
    main()
