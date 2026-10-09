#!/usr/bin/env python3
"""Measure nested shell jobs with current native owners and private terminals."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "experiments/command-nested-shell"
NATIVE = ROOT / "macos/core/Sources/RemozioMach"
MONITOR = ROOT / "macos/app/CommandMonitor/MonitorMain.c"
LAUNCHER = ROOT / "macos/core/Tests/RemozioCoreTests/Fixtures/command-process/child.c"
TRIALS_PER_MODE = 15
EXPECTED = {
    "failure": 0,
    "nestedStopped": True,
    "nestedResumed": True,
    "foregroundInterrupted": True,
    "shellExecObserved": True,
    "shellExitObserved": True,
    "monitorReaped": True,
    "targetWait": 7 << 8,
}


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, capture_output=True, text=True,
                          timeout=35, **kwargs)


def compile_fixture(directory, name, sources):
    binary = directory / name
    run(["xcrun", "clang", "-arch", "arm64", "-mmacosx-version-min=26.0",
         "-Wall", "-Wextra", "-Werror", "-I" + str(NATIVE / "include"),
         "-I" + str(NATIVE), "-I" + str(MONITOR.parent),
         *(str(source) for source in sources), "-o", str(binary)])
    return binary


def launch_frame(directory):
    arguments = [b"/bin/bash", b"--noprofile", b"--norc", b"-i", b"-c",
                 b"printf 'READY_MARKER\\n'; exec /bin/bash --noprofile --norc -i"]
    environment = sorted([os.fsencode("HOME=" + str(directory)), b"PATH=/usr/bin:/bin",
                          b"PS1=TEST> ", b"TERM=dumb", b"LC_ALL=C"],
                         key=lambda value: value.split(b"=", 1)[0])
    fields = [b"/bin/bash", *arguments, *environment]
    body = b"".join(struct.pack(">I", len(value)) + value for value in fields)
    return struct.pack(">10I", 0x524D4331, len(body), os.getuid(), os.getgid(),
                       0, len(arguments), len(environment), 5000, 0o077, 1) + body


def run_probe(arguments, directory):
    with subprocess.Popen(arguments, cwd=directory, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as process:
        try:
            output, errors = process.communicate(timeout=35)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            # The probe handles termination by cancelling and reaping its owned monitor.
            process.terminate()
            try:
                process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            raise
        if process.returncode:
            raise RuntimeError(f"Nested shell probe failed: exit {process.returncode}; {errors}; {output}")
        return json.loads(output)


def require_observation(actual, mode, trial):
    if (not isinstance(actual, dict) or actual != EXPECTED
            or any(type(actual[key]) is not type(value) for key, value in EXPECTED.items())):
        raise RuntimeError(f"Nested shell observation changed: {mode}, trial {trial}, {actual!r}")


def measure():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("This experiment requires an Apple Silicon Mac")
    if os.geteuid() == 0:
        raise RuntimeError("Run this disposable experiment without elevation")
    observations = {}
    sources = [*sorted(FIXTURES.glob("*.c")), MONITOR, LAUNCHER,
               *(NATIVE / name for name in ["CommandMonitor.c", "CommandProcess.c", "CommandPTY.c",
                 "CommandChildSpecification.c", "CommandMonitorProtocol.c",
                 "include/RemozioCommandMonitor.h", "include/RemozioCommandMonitorProtocol.h",
                 "include/RemozioCommandProcess.h", "include/RemozioCommandPTY.h",
                 "include/RemozioCommandChild.h"]), Path(__file__).resolve()]
    hashes = {str(source.relative_to(ROOT)): hashlib.sha256(source.read_bytes()).hexdigest()
              for source in sources}
    with tempfile.TemporaryDirectory(prefix="remozio-nested-shell-") as temporary:
        directory = Path(temporary).resolve()
        specification = NATIVE / "CommandChildSpecification.c"
        protocol = NATIVE / "CommandMonitorProtocol.c"
        monitor = compile_fixture(directory, "monitor", [FIXTURES / "monitor-fixture.c",
                                  NATIVE / "CommandProcess.c", specification, protocol])
        launcher = compile_fixture(directory, "child", [LAUNCHER, specification])
        probe = compile_fixture(directory, "probe", [FIXTURES / "probe.c",
                                NATIVE / "CommandMonitor.c", specification, protocol])
        frame = directory / "frame.bin"
        frame.write_bytes(launch_frame(directory))
        for mode in ["signal", "typed"]:
            for trial in range(TRIALS_PER_MODE):
                actual = run_probe([str(probe), str(monitor), str(launcher), str(frame), mode], directory)
                require_observation(actual, mode, trial)
            observations[mode] = {"trials": TRIALS_PER_MODE, "allTrialsMatch": True, "observations": EXPECTED}
    for source in sources:
        if hashlib.sha256(source.read_bytes()).hexdigest() != hashes[str(source.relative_to(ROOT))]:
            raise RuntimeError("An experiment source changed during measurement")
    return {
        "experiment": "command-nested-shell-v1",
        "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"os": run(["sw_vers", "-productVersion"]).stdout.strip(),
                 "build": run(["sw_vers", "-buildVersion"]).stdout.strip(),
                 "architecture": platform.machine(),
                 "sdk": run(["xcrun", "--sdk", "macosx", "--show-sdk-version"]).stdout.strip(),
                 "deploymentTarget": "26.0"},
        "sources": hashes,
        "cases": observations,
        "limits": ["Disposable unprivileged Bash and sleep jobs in private terminals; no user terminal",
                   "Current monitor UID guard substituted; synthetic launcher changes no credentials",
                   "No protected installation, production elevation, actual CLI or cross-user proof",
                   "No external debugger, crash recovery, mixed streams or authenticated frontend job events",
                   "The runtime is recorded; deployment target does not prove macOS 26 runtime behavior",
                   "Fixture deadlines bound experiments only; no product command runtime limit"]
    }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
