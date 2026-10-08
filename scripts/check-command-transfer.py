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
        readiness_probe = """import Foundation
import Darwin
import RemozioCore
import RemozioProtocol
func submit(template: CommandSubmission, policy: XPCPeerPolicy, limits: CBORLimits,
            mac: Data, account: Data, lookup: () throws -> mach_port_t) throws -> VerifiedCommandAdmissionResult {
    try CommandCallerReadiness.submit(template, inputDescriptor: 0, authorityPort: lookup,
        authorityPolicy: policy, macID: mac, accountID: account, submissionLimits: limits,
        configuration: CommandCallerReadinessConfiguration(timeoutMilliseconds: 30000))
}
"""
        probes = {
            "valid": (prefix + admission + "}\n", True),
            "caller-readiness-valid": (readiness_probe, True),
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
        admission_pipeline = pipeline.replace("receiveInput", "receiveAdmissionInput")
        probes["admission-pipeline-valid"] = (pipeline_prefix + admission_pipeline + "}\n", True)
        probes["admission-reply-reuse"] = (pipeline_prefix + admission_pipeline + "    try received.sendAdmissionReply(Data([0xa0]))\n}\n", False)
        aliased_admission = admission_pipeline.replace("    let command", "    let alias = received\n    let command")
        probes["admission-reply-alias-reuse"] = (pipeline_prefix + aliased_admission + "    try alias.sendAdmissionReply(Data([0xa0]))\n}\n", False)
        host_prefix = """import Foundation
import RemozioCore
import RemozioProtocol
func transfer(host: CommandReceiveHost, journal: AuthorityJournal, peer: XPCPeerPolicy, target: CommandTarget,
              limits: CBORLimits, stream: Data, draft: ApprovalRequestDraft, now: () throws -> AuthorityMoment) throws {
"""
        host_body = """    _ = try host.poll { received in
        let command = try host.assemble(received: received, captureSchemaVersion: 2, resolvedTarget: target,
            minimalEnvironment: [], streamBinding: stream, submissionLimits: limits, captureLimits: limits)
        _ = try journal.admitCommand(command, draft: draft, currentPolicy: peer, now: now, receiptTimeMs: nil)
    }
    host.close()
"""
        probes["host-poll-valid"] = (host_prefix + host_body + "}\n", True)
        probes["host-input-reuse"] = (host_prefix + host_body.replace("        _ = try journal.admitCommand", "        received.input.close()\n        _ = try journal.admitCommand") + "}\n", False)
        probes["host-input-alias-reuse"] = (host_prefix + host_body.replace("        let command", "        let alias = received\n        let command").replace("        _ = try journal.admitCommand", "        alias.input.close()\n        _ = try journal.admitCommand") + "}\n", False)
        probes["host-command-reuse"] = (host_prefix + host_body.replace("receiptTimeMs: nil)", "receiptTimeMs: nil)\n        command.close()") + "}\n", False)
        probes["host-command-alias-reuse"] = (host_prefix + host_body.replace("        _ = try journal.admitCommand", "        let alias = command\n        _ = try journal.admitCommand").replace("receiptTimeMs: nil)", "receiptTimeMs: nil)\n        alias.close()") + "}\n", False)
        probes["host-run-valid"] = (host_prefix + host_body.replace("_ = try host.poll", "try host.run") + "}\n", True)
        probes["proof-observe-valid"] = ("import RemozioCore\nfunc observe(_ result: VerifiedCommandAdmissionResult) -> CommandAdmissionRetryClass { result.retryClass }\n", True)
        probes["proof-forge"] = ("import RemozioCore\nfunc forge() -> VerifiedCommandAdmissionResult { VerifiedCommandAdmissionResult() }\n", False)
        attempt_prepare = "    _ = try owner.prepareAdmission(received: received, currentPolicy: policy, submissionLimits: limits)\n"
        registry_prepare = attempt_prepare.replace("currentPolicy: policy", "currentCodePolicy: policy")
        for name, probe_prefix, prepare in [
            ("attempt-handshake", input_prefix, attempt_prepare),
            ("attempt-registry", registry_input_prefix, registry_prepare),
        ]:
            probes[name + "-valid"] = (probe_prefix + prepare + "}\n", True)
            probes[name + "-reuse"] = (probe_prefix + prepare + "    received.input.close()\n}\n", False)
            probes[name + "-alias-reuse"] = (probe_prefix + "    let alias = received\n" + prepare + "    alias.input.close()\n}\n", False)
        attempt_prefix = """import RemozioCore
import RemozioProtocol
func transfer(journal: AuthorityJournal, attempt: sending RetainedCommandAdmissionAttempt,
              draft: ApprovalRequestDraft, now: () throws -> AuthorityMoment) throws {
"""
        attempt_admit = "    _ = try journal.admitCommandAttempt(attempt, resolve: { _ in .refuse(.updateWaiting) }, draft: { _ in draft }, now: now, receiptTimeMs: nil)\n"
        probes["attempt-journal-valid"] = (attempt_prefix + attempt_admit + "}\n", True)
        probes["attempt-journal-reuse"] = (attempt_prefix + attempt_admit + "    attempt.close()\n}\n", False)
        probes["attempt-journal-alias-reuse"] = (attempt_prefix + "    let alias = attempt\n" + attempt_admit + "    alias.close()\n}\n", False)
        attempt_host = """    _ = try host.poll { received in
        let attempt = try host.prepareAdmission(received: received, submissionLimits: limits)
        _ = try journal.admitCommandAttempt(attempt, resolve: { _ in .refuse(.updateWaiting) },
            draft: { _ in draft }, now: now, receiptTimeMs: nil)
    }
    host.close()
"""
        probes["attempt-host-valid"] = (host_prefix + attempt_host + "}\n", True)
        probes["attempt-host-input-reuse"] = (host_prefix + attempt_host.replace("        _ = try journal", "        received.input.close()\n        _ = try journal") + "}\n", False)
        probes["attempt-host-reuse"] = (host_prefix + attempt_host.replace("receiptTimeMs: nil)", "receiptTimeMs: nil)\n        attempt.close()") + "}\n", False)
        probes["attempt-host-alias-reuse"] = (host_prefix + attempt_host.replace("        _ = try journal", "        let alias = attempt\n        _ = try journal").replace("receiptTimeMs: nil)", "receiptTimeMs: nil)\n        alias.close()") + "}\n", False)
        controller = """    _ = try host.pollAdmission(journal: journal, submissionLimits: limits,
        resolve: { _ in .refuse(.updateWaiting) }, draft: { _ in draft }, now: now,
        receiptTimeMs: nil, onResult: { _ in })
    host.close()
"""
        probes["attempt-controller-valid"] = (host_prefix + controller + "}\n", True)
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
            elif name == "proof-forge":
                passed = result.returncode != 0 and "fileprivate" in result.stderr
            else:
                passed = result.returncode != 0 and "SendingRisksDataRace" in result.stderr
            if not passed:
                raise SystemExit("Command ownership probe failed: " + name + "\n" + result.stderr[:4096])
    print("Command ownership: coordinator, journal, handshake, registry, and host transfers accepted; object and alias reuse rejected; verified result construction remains private.")


if __name__ == "__main__":
    main()
