#!/usr/bin/env python3
"""Exercise kernel-bound caller identity with disposable unprivileged peers."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "experiments/command-caller"
IDENTIFIER = "dev.remozio.experiments.command-caller.peer"


def run(arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=60)


def invoke(probe, peer, code_hash, rejected_at=None):
    process = subprocess.Popen([str(probe), str(peer), code_hash],
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        output, errors = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
    if rejected_at:
        if process.returncode != 3 or f'"{rejected_at}":false' not in output or "peer_retired=true" not in errors:
            raise RuntimeError(f"Expected rejection and peer cleanup: {process.returncode}: {output!r} {errors!r}")
        return None
    if process.returncode:
        raise RuntimeError(f"Caller probe failed ({process.returncode}): {output!r} {errors!r}")
    observations = json.loads(output)
    if len(observations) != 24 or not all(value is True for value in observations.values()):
        raise RuntimeError("The caller probe did not pass all observations")
    return observations


def sign(peer):
    run(["codesign", "--force", "--sign", "-", "--options", "runtime",
         "--identifier", IDENTIFIER, str(peer)])
    description = run(["codesign", "--display", "--verbose=4", str(peer)])
    match = re.search(r"^CDHash=([0-9a-f]{40})$", description.stderr, re.MULTILINE)
    if not match:
        raise RuntimeError("The peer has no CodeDirectory hash")
    return match.group(1)


def measure():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("This experiment requires an Apple Silicon Mac")
    with tempfile.TemporaryDirectory(prefix="remozio-command-caller-") as temporary:
        directory = Path(temporary).resolve()
        peer, probe = directory / "peer", directory / "probe"
        flags = ["xcrun", "clang", "-arch", "arm64", "-mmacosx-version-min=26.0",
                 "-Wall", "-Wextra", "-Werror", "-std=c11"]
        run(flags + [str(SOURCES / "peer.c"), "-o", str(peer)])
        run(flags + [str(SOURCES / "probe.c"), "-lbsm", "-framework", "Security",
                     "-framework", "CoreFoundation", "-o", str(probe)])
        code_hash = sign(peer)
        observations = invoke(probe, peer, code_hash)
        invoke(probe, peer, "0" * 40, "pinned_fixture_code_accepted")
        rejected = ["wrong_pin_retires_peer"]
        for label, define, rejected_at in [
            ("silent_peer_retires", "PROBE_SKIP_SEND", "first_message_has_audit_trailer"),
            ("malformed_phase_retires", "PROBE_WRONG_PHASE", "first_message_has_audit_trailer"),
            ("missing_exec_message_retires", "PROBE_SKIP_EXEC", "second_message_has_audit_trailer"),
        ]:
            variant = directory / label
            run(flags + ["-D" + define, str(SOURCES / "peer.c"), "-o", str(variant)])
            invoke(probe, variant, sign(variant), rejected_at)
            rejected.append(label)
        return {
            "experiment": "command-caller-audit-v1",
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "host": {"os": run(["sw_vers", "-productVersion"]).stdout.strip(),
                     "build": run(["sw_vers", "-buildVersion"]).stdout.strip(),
                     "architecture": platform.machine(),
                     "sdk": run(["xcrun", "--sdk", "macosx", "--show-sdk-version"]).stdout.strip(),
                     "deploymentTarget": "26.0"},
            "sources": {name: hashlib.sha256((SOURCES / name).read_bytes()).hexdigest()
                        for name in ["message.h", "peer.c", "probe.c"]},
            "observations": observations,
            "rejectionCases": rejected,
            "limits": ["Unprivileged anonymous Mach endpoint; no installed service",
                       "Ad-hoc fixture pin; no Developer ID trust or production code floor",
                       "Exec and exit; no forced PID reuse",
                       "No Root command admission, policy, execution, or device E2E"]
        }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
