# Accepted implementation limits

The user approved these amendments on 2026-10-03. They supersede the earlier requirements for an independent whole-backup witness and a pending command-execution decision. They do not claim that production integration or platform tests are complete.

## Whole-Mac backup rollback

Restoring an entire Mac to an older backup is outside the security guarantee. Such a restore can restore revoked enrollment, old policy or floors, and consumed control state. Remozio does not promise to detect that complete, internally consistent restoration.

An independent hardware or online witness is no longer a prerequisite for this threat. Keep normal offline and LAN operation. Do not add recurring authorization, forced re-pairing or a mandatory network startup check.

The following protections remain required:

- Root-controlled installation and state paths, with protection against an unprivileged process replacing files or trusted code.
- Signature verification, current enrollment checks, fresh challenges and durable replay prevention during ordinary operation and restart.
- Committed security floors and authenticated policy revisions outside replaceable application binaries. Reject older binaries against the retained current state.
- Atomic consumption, crash-consistent state transitions, a protected local checkpoint, and recovery markers. Reconcile interrupted commits before enabling permissive authority.
- Automatic retry for transient storage faults. Retain consumed actions and Unknown outcomes; never retry an uncertain external action.
- Detection and safe handling of partial replacement, inconsistent state and conflicting retained evidence. Never silently reset trust or clear history to make startup succeed.
- Device-bound, non-exportable authority keys, cross-device clone protection, and explicit re-enrollment for hardware replacement or lost identities.

The [journal experiment](experiments/macos-authority-journal.md) still demonstrates a real limitation: a matching old database and checkpoint are indistinguishable locally. The accepted boundary does not turn that observation into successful rollback detection. It also does not authorize an unprivileged caller to restore arbitrary files.

## Command execution by pathname

Execute the captured command by pathname after a final executable identity/content and working-directory recheck. Preserve the captured argv, deterministic environment, caller lifetime and input-source contract. Do not add an implicit shell.

A process can still replace or modify the executable after the recheck and before the OS executes it. Scripts and dependencies can also change. Approval binds the invocation; it does not guarantee immutable approved program bytes or transitive behavior.

Do not silently relocate executable files, force another interpreter, or restrict commands to an immutable allowlist. The user accepted the documented race to preserve ordinary executable-location and argv behavior.

The [macOS 26 and 27 experiment](experiments/macos-execution-binding.md) provides the measured evidence. Production execution still needs protected service integration, authorization policy, durable consumption, process I/O and recovery. Acceptance of this contract does not enable an unimplemented executor.

## Test order and signing

The user made an Android 17 Pixel available through LAN ADB. Prepare and run its app tests first, with the user performing biometric interactions. Do not change biometric enrollment or debugging configuration automatically.

Reuse the user's existing Developer ID Application identity where suitable. Keep credentials outside the repository and select the intended identity explicitly. A certificate inspection alone does not establish private-key access, notarization or protected service behavior.

Mac service installation, lock/logout/restart, and CRD/Screen Sharing tests come last. The [interactive handoff](experiments/interactive-handoff.md) remains the test procedure, with this ordering amendment.
