#!/usr/bin/env python3
"""Reload one disposable file identity in fresh processes and exercise native TLS."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def invoke(binary, mode, directory):
    # subprocess.run kills and reaps this direct child if its external deadline expires.
    return subprocess.run([str(binary), mode, str(directory)], capture_output=True,
                          text=True, timeout=25, stdin=subprocess.DEVNULL)


def check_report(result, *, refusal=None):
    report = json.loads(result.stdout)
    if report.get("experiment") != "transport-file-tls" or report.get("schemaVersion") != 1:
        raise RuntimeError("The child did not report the file TLS experiment")
    if refusal:
        if result.returncode != 77 or report.get("status") != "blocked" or report.get("fileLoadRefusal") != refusal:
            raise RuntimeError("The file identity negative control did not refuse its input")
        if report.get("fileIdentityLoaded") or report.get("nativeSignatureVerified") or report.get("mutualTLS13Exchange"):
            raise RuntimeError("The refused file identity reached signing or TLS")
    else:
        if result.returncode != 0 or report.get("status") != "passed" or report.get("stage") != "complete":
            raise RuntimeError("The fresh-process file TLS exchange did not pass")
        for field in ("fileFixtureAnchorUsed", "fileIdentityLoaded", "nativeSignatureVerified",
                      "mutualTLS13Exchange", "wrongServerPinRejected", "wrongPinPolicyRejectionObserved"):
            if report.get(field) is not True:
                raise RuntimeError(f"The experiment did not establish {field}")
        if report.get("wrongPinChannelOutcome") not in ("failed", "closed", "timedOut"):
            raise RuntimeError("The rejected TLS peer did not report a closed channel")
    for field in ("productionRootAncestryTested", "dedicatedAccountIsolationTested", "preloginTested",
                  "authenticationUIAllowed", "persistentKeyRequested", "enclaveTokenVerified"):
        if report.get(field) is not False:
            raise RuntimeError(f"The fixture made an unsupported claim about {field}")
    return report


def main():
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise RuntimeError("Run this disposable experiment as an ordinary user")
    binary_dir = subprocess.check_output([
        "swift", "build", "--package-path", str(ROOT / "experiments/key-custody"),
        "--triple", "arm64-apple-macosx26.0", "--disable-keychain", "--disable-netrc", "--show-bin-path",
    ], text=True, timeout=30).strip()
    binary = Path(binary_dir) / "EnclaveTLSProbe"
    with tempfile.TemporaryDirectory(prefix="remozio-file-tls-") as temporary:
        directory = Path(temporary)
        created = invoke(binary, "--create-file-fixture", directory)
        if created.returncode != 0 or created.stdout:
            raise RuntimeError("The disposable identity fixture could not be created")
        identity, pin = directory / "identity.cbor", directory / "pin.spki"
        original_identity, original_pin = identity.read_bytes(), pin.read_bytes()
        if any(path.stat().st_mode & 0o777 != 0o600 for path in (identity, pin, directory / "wrong-pin.spki")):
            raise RuntimeError("The fixture files are not private")
        positive = []
        for _ in range(2):
            positive.append(check_report(invoke(binary, "--file-fixture", directory)))
            if identity.read_bytes() != original_identity or pin.read_bytes() != original_pin:
                raise RuntimeError("A child changed the identity or pin instead of reloading it")
        identity.chmod(0o640)
        check_report(invoke(binary, "--file-fixture", directory), refusal="unsafeMetadata")
        identity.chmod(0o600)
        pin.write_bytes((directory / "wrong-pin.spki").read_bytes())
        check_report(invoke(binary, "--file-fixture", directory), refusal="invalidIdentity")
        pin.write_bytes(original_pin)
        if len({report["osVersion"] for report in positive}) != 1:
            raise RuntimeError("The child runtime reports disagree")
    if directory.exists():
        raise RuntimeError("The disposable files were not removed")
    print(json.dumps({
        "experiment": "transport-file-cross-process-tls", "schemaVersion": 1, "status": "passed",
        "osVersion": positive[0]["osVersion"], "freshTLSProcesses": len(positive),
        "sameIdentityRetained": True, "nativeSignaturesVerified": True, "mutualTLS13Exchange": True,
        "wrongServerPinPolicyRejectionObserved": True, "unsafeModeRejected": True, "wrongIdentityPinRejected": True,
        "fixtureDirectoryRemoved": True, "productionRootAncestryTested": False,
        "dedicatedAccountIsolationTested": False, "preloginTested": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
