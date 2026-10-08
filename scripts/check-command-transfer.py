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
        hello_prefix = """import Foundation
import RemozioCore
func transfer(hello: sending MachCommandHello, policy: XPCPeerPolicy, mac: Data, account: Data) throws {
"""
        hello_transfer = "    _ = try RetainedCommandHandshake(hello: hello, macID: mac, accountID: account, currentPolicy: policy)\n"
        input_prefix = """import Foundation
import RemozioCore
import RemozioProtocol
func transfer(owner: RetainedCommandHandshake, received: sending ReceivedMachCommandInputSubmission,
              policy: XPCPeerPolicy, target: CommandTarget, limits: CBORLimits, stream: Data) throws {
"""
        input_transfer = """    _ = try owner.assemble(received: received, currentPolicy: policy, captureSchemaVersion: 2,
        resolvedTarget: target, minimalEnvironment: [], streamBinding: stream, submissionLimits: limits, captureLimits: limits)
"""
        probes.update({
            "hello-valid": (hello_prefix + hello_transfer + "}\n", True),
            "hello-reuse": (hello_prefix + hello_transfer + "    hello.close()\n}\n", False),
            "hello-alias-reuse": (hello_prefix + "    let alias = hello\n" + hello_transfer + "    alias.close()\n}\n", False),
            "received-valid": (input_prefix + input_transfer + "}\n", True),
            "received-reuse": (input_prefix + input_transfer + "    received.input.close()\n}\n", False),
            "received-alias-reuse": (input_prefix + "    let alias = received\n" + input_transfer + "    alias.input.close()\n}\n", False),
        })
        registry_hello_prefix = hello_prefix.replace("hello: sending MachCommandHello, policy: XPCPeerPolicy, mac: Data, account: Data",
            "owner: CommandSessionRegistry, hello: sending MachCommandHello, policy: AuthorityCodePolicySnapshot")
        registry_hello_transfer = "    _ = try owner.accept(hello: hello, currentCodePolicy: policy)\n"
        registry_input_prefix = input_prefix.replace("owner: RetainedCommandHandshake", "owner: CommandSessionRegistry").replace(
            "policy: XPCPeerPolicy", "policy: AuthorityCodePolicySnapshot")
        registry_input_transfer = input_transfer.replace("currentPolicy: policy", "currentCodePolicy: policy")
        probes.update({
            "registry-hello-valid": (registry_hello_prefix + registry_hello_transfer + "}\n", True),
            "registry-hello-reuse": (registry_hello_prefix + registry_hello_transfer + "    hello.close()\n}\n", False),
            "registry-hello-alias-reuse": (registry_hello_prefix + "    let alias = hello\n" + registry_hello_transfer + "    alias.close()\n}\n", False),
            "registry-input-valid": (registry_input_prefix + registry_input_transfer + "}\n", True),
            "registry-input-reuse": (registry_input_prefix + registry_input_transfer + "    received.input.close()\n}\n", False),
            "registry-input-alias-reuse": (registry_input_prefix + "    let alias = received\n" + registry_input_transfer + "    alias.input.close()\n}\n", False),
        })
        producer_hello_prefix = registry_hello_prefix.replace("hello: sending MachCommandHello", "receiver: MachCommandCallerReceiver")
        producer_hello = "    let hello = try receiver.receiveHello(timeoutMilliseconds: 1)\n"
        producer_input_prefix = registry_input_prefix.replace("received: sending ReceivedMachCommandInputSubmission", "receiver: MachCommandCallerReceiver")
        producer_input = "    let received = try receiver.receiveInput(timeoutMilliseconds: 1)\n"
        next_receive = "    _ = try receiver.receiveNext(timeoutMilliseconds: 1)\n"
        probes.update({
            "producer-hello-valid": (producer_hello_prefix + producer_hello + registry_hello_transfer + next_receive + "}\n", True),
            "producer-hello-reuse": (producer_hello_prefix + producer_hello + registry_hello_transfer + "    hello.close()\n}\n", False),
            "producer-hello-alias-reuse": (producer_hello_prefix + producer_hello + "    let alias = hello\n" + registry_hello_transfer + "    alias.close()\n}\n", False),
            "producer-input-valid": (producer_input_prefix + producer_input + registry_input_transfer + next_receive + "}\n", True),
            "producer-input-reuse": (producer_input_prefix + producer_input + registry_input_transfer + "    received.input.close()\n}\n", False),
            "producer-input-alias-reuse": (producer_input_prefix + producer_input + "    let alias = received\n" + registry_input_transfer + "    alias.input.close()\n}\n", False),
        })
        pipeline_prefix = """import Foundation
import RemozioCore
import RemozioProtocol
func transfer(receiver: MachCommandCallerReceiver, registry: CommandSessionRegistry, journal: AuthorityJournal,
              policy: AuthorityCodePolicySnapshot, peer: XPCPeerPolicy, target: CommandTarget, limits: CBORLimits,
              stream: Data, draft: ApprovalRequestDraft, now: () throws -> AuthorityMoment) throws {
"""
        pipeline = """    let received = try receiver.receiveInput(timeoutMilliseconds: 1)
    let command = try registry.assemble(received: received, currentCodePolicy: policy, captureSchemaVersion: 2,
        resolvedTarget: target, minimalEnvironment: [], streamBinding: stream, submissionLimits: limits, captureLimits: limits)
    _ = try journal.admitCommand(command, draft: draft, currentPolicy: peer, now: now, receiptTimeMs: nil)
    _ = try receiver.receiveNext(timeoutMilliseconds: 1)
    _ = try registry.prune(currentCodePolicy: policy)
"""
        probes["pipeline-valid"] = (pipeline_prefix + pipeline + "}\n", True)
        probes["pipeline-command-reuse"] = (pipeline_prefix + pipeline + "    command.close()\n}\n", False)
        alias_pipeline = pipeline.replace("    _ = try journal.admitCommand", "    let alias = command\n    _ = try journal.admitCommand")
        probes["pipeline-alias-reuse"] = (pipeline_prefix + alias_pipeline + "    alias.close()\n}\n", False)
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
    print("Command ownership: coordinator, journal, handshake, and registry transfers accepted; object and alias reuse rejected.")


if __name__ == "__main__":
    main()
