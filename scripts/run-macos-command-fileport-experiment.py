#!/usr/bin/env python3
"""Measure descriptor transfer without installing a service or consuming real input."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/command-fileport/probe.c"
CASES = {"file_identity_offset_and_lifetime", "directory_identity_and_lifetime", "pipe_queued_and_later_input",
         "socket_queued_and_later_input", "pty_input_and_resize", "null_input", "write_only_input_rejected",
         "ordinary_port_rejected", "silent_peer_reaped", "passed"}


def run(arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=60)


def measure():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("This experiment requires an Apple Silicon Mac")
    with tempfile.TemporaryDirectory(prefix="remozio-command-fileport-") as temporary:
        directory = Path(temporary).resolve()
        binary = directory / "probe"
        run(["xcrun", "clang", "-arch", "arm64", "-mmacosx-version-min=26.0", "-Wall", "-Wextra", "-Werror", "-std=c11",
             str(SOURCE), "-lbsm", "-o", str(binary)])
        run(["codesign", "--force", "--sign", "-", "--options", "runtime",
             "--identifier", "dev.remozio.experiments.command-fileport", str(binary)])
        process = subprocess.Popen([str(binary), str(directory / "file"), str(directory)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            output, errors = process.communicate(timeout=30)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
        if process.returncode:
            raise RuntimeError(f"Fileport probe failed ({process.returncode}): {output!r} {errors!r}")
        observations = json.loads(output)
        if set(observations) != CASES or not all(value is True for value in observations.values()):
            raise RuntimeError("The fileport probe did not pass all observations")
        return {
            "experiment": "command-fileport-v1",
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "host": {"os": run(["sw_vers", "-productVersion"]).stdout.strip(),
                     "build": run(["sw_vers", "-buildVersion"]).stdout.strip(),
                     "architecture": platform.machine(),
                     "sdk": run(["xcrun", "--sdk", "macosx", "--show-sdk-version"]).stdout.strip(),
                     "deploymentTarget": "26.0"},
            "sources": {"probe.c": hashlib.sha256(SOURCE.read_bytes()).hexdigest()},
            "observations": observations,
            "limits": ["Unprivileged anonymous Mach endpoint; no service installation",
                       "Kernel sender attributes compared to spawned fixture; no release code policy",
                       "Synthetic data and disposable PTY; no command execution or real terminal",
                       "No hostile-sender resource budget or production admission/I/O transport",
                       "Socket transfer measured; application capture-schema classification remains integration work"]
        }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
