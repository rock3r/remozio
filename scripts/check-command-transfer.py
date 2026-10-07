#!/usr/bin/env python3
"""Compile public command ownership probes without creating or approving a request."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "macos/core"


def main():
    binary = subprocess.check_output([
        "swift", "build", "--package-path", str(CORE), "--triple", "arm64-apple-macosx26.0", "--show-bin-path",
    ], text=True, timeout=30).strip()
    with tempfile.TemporaryDirectory(prefix="remozio-command-transfer-") as directory:
        scratch = Path(directory)
        module_map = scratch / "module.modulemap"
        header = CORE / "Sources/RemozioMach/include/RemozioMach.h"
        module_map.write_text("module RemozioMach { umbrella header " + json.dumps(str(header)) + " export * }\n")
        prefix = """import RemozioCore
func transfer(owner: ApprovalRequestCoordinator, command: sending RetainedCommandCapture,
              draft: ApprovalRequestDraft, policy: XPCPeerPolicy,
              now: () throws -> AuthorityMoment) throws {
"""
        admission = "    _ = try owner.admitCommand(command, draft: draft, currentPolicy: policy, now: now, receiptTimeMs: nil)\n"
        probes = {
            "valid": (prefix + admission + "}\n", True),
            "command-reuse": (prefix + admission + "    command.close()\n}\n", False),
            "alias-reuse": (prefix + "    let alias = command\n" + admission + "    alias.close()\n}\n", False),
        }
        journal_prefix = prefix.replace("owner: ApprovalRequestCoordinator", "owner: AuthorityJournal")
        probes.update({
            "journal-valid": (journal_prefix + admission + "}\n", True),
            "journal-command-reuse": (journal_prefix + admission + "    command.close()\n}\n", False),
            "journal-alias-reuse": (journal_prefix + "    let alias = command\n" + admission + "    alias.close()\n}\n", False),
        })
        for name, (source, accepted) in probes.items():
            path = scratch / (name + ".swift")
            path.write_text(source)
            result = subprocess.run([
                "swiftc", "-c", "-swift-version", "6", "-target", "arm64-apple-macosx26.0",
                "-I", binary, "-I", str(Path(binary) / "Modules"),
                "-Xcc", "-fmodule-map-file=" + str(module_map),
                "-module-cache-path", str(scratch / "cache"), str(path), "-o", str(scratch / (name + ".o")),
            ], capture_output=True, text=True, timeout=60)
            if accepted:
                passed = result.returncode == 0
            else:
                passed = result.returncode != 0 and "SendingRisksDataRace" in result.stderr
            if not passed:
                raise SystemExit("Command ownership probe failed: " + name + "\n" + result.stderr[:4096])
    print("Command ownership: coordinator and journal transfers accepted; command and alias reuse rejected.")


if __name__ == "__main__":
    main()
