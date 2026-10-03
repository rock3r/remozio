#!/usr/bin/env python3
"""Verify timeout finalization without generating keys or opening sockets."""
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
binary_dir = subprocess.check_output(
    ["swift", "build", "--package-path", str(root / "experiments/key-custody"),
     "--triple", "arm64-apple-macosx26.0", "--disable-keychain", "--disable-netrc", "--show-bin-path"],
    text=True, timeout=30,
).strip()
result = subprocess.run([str(Path(binary_dir) / "EnclaveTLSProbe"), "--timeout-control"],
                        capture_output=True, text=True, timeout=10)
report = json.loads(result.stdout)
assert result.returncode == 77, "Timeout must not exit successfully"
assert report["stage"] == "timeout" and report["status"] == "blocked"
assert not report["enclaveTokenVerified"] and not report["identityCreated"]
assert not report["mutualTLS13Exchange"] and not report["wrongServerPinRejected"]
print("Enclave probe timeout control passed; no keys or sockets created.")
