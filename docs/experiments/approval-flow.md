# Synthetic approval flow

This harness joins the native Swift authority verifier with the Kotlin request owner used by Android. It exchanges real canonical request, decision, and status bodies with P-256 signatures. It uses child-process pipes, synthetic identities, and an invented command capture. It never executes the captured command.

```mermaid
sequenceDiagram
    participant C as Kotlin test controller
    participant M as Swift fake authority
    participant A as Phone session A
    participant B as Phone session B
    C->>M: Provision disposable test keys and capture
    M->>A: Signed issued request and pending status
    M->>B: Same signed request and status
    A->>M: Signed decision arrives first
    B->>M: Competing signed decision
    M->>M: Verify A; commit consumption and audit event
    M-->>B: Reject unavailable request
    M->>A: Signed status names accepted phone
    M->>B: Same signed status
    C->>M: Simulate lost outcome
    M->>M: Commit Unknown and its audit event
    M->>A: Signed Unknown outcome
    M->>B: Same Unknown outcome
    A->>A: Remove owned command capture
    B->>B: Remove owned command capture
```

## Run

Use an Apple Silicon Mac, Xcode with a macOS 26 or later SDK, and JDK 21:

```sh
python3 scripts/build-approval-flow.py
./gradlew :phone-core:test :phone-core:approvalFlowTest
```

The native build is also part of `scripts/check.sh`. The Mac CI job runs the integration task after building it. The Kotlin CI job runs the portable phone tests on Linux. Android consumes the same `phone-core` module.

The build script normalizes the executable path to `.build/approval-flow/ApprovalFlowPeer`, independent of SwiftPM's build-directory layout. Its build log is `.build/approval-flow/swift-build.log`. The peer refuses root execution. Both pipe readers bound frames before allocating an unbounded line. The controller bounds response waits and terminates its child after each case.

The controller creates a private temporary parent directory and passes it as the peer’s second argument, after the capture path. The peer creates a 0700 journal directory with 0600 files. The controller removes the fixture only after confirming the child has stopped. A Debug-only `@testable` import permits normal-user fixtures through the internal storage initializer. The public production initializer remains root-only. A compile-time guard rejects Release builds of this peer; that negative build check passed locally. No app, device, or network endpoint is contacted.

## Trust and simulation boundary

The test controller generates disposable Mac and phone keys in memory. It supplies the Mac private scalar through the private test-control pipe, and pins the corresponding public key independently of the peer's response. The Swift peer signs through CryptoKit; Kotlin signs through the host JDK. No key is written to a fixture or included in a release app.

This bootstrap is test provisioning, not a pairing protocol or a production trust channel. Control messages for revocation, clock changes, and outcome loss exist only in the harness. A key labelled Biometric in this fixture is an ordinary disposable test key. These checks do not prove Android Keystore protection, biometric consent, Secure Enclave custody, or application signatures.

The peer keeps one request in memory and serializes input from its pipe. It calls the real `JournalDatabase` consumption transaction, which verifies the decision and commits consumption with its audit event. It publishes Accepted only after the write returns successfully. Outcome transitions use the same store and publish status only after commit. The harness queues both phone decisions before reading either response and repeats with each arrival order.

Fault controls throw inside the transaction callback after its mutations, before the outer commit. These prove rollback and publication ordering for callback failure. They do not simulate physical disk failure or an ambiguous commit. Unsigned snapshots expose journal metadata only to the private test controller; they are not the audit transport protocol.

The reopen control closes and reopens the database in the same process, then creates a fresh audit epoch linked to the previous head. It discards the retained capture. Consumed requests without a terminal outcome receive an explicit authority-restart observation and become Unknown. Existing terminal outcomes remain unchanged. An unconsumed pending request becomes Cancelled without reconstructing its capture.

This is a journal lifecycle simulation, not process-crash recovery. Disposable keys, the synthetic clock, status revision, and cached request identity remain in memory. It does not implement production startup continuity, durable admission coordination, rollback protection, checkpoint verification, or a dispatch permit.

Unknown comes from an explicit outcome-loss or authority-restart observation. It is not inferred from a timeout. The success control is also a synthetic observation: no command or UI action occurs.

## Cases

Eleven integration tests cover:

- Either phone wins when its valid decision arrives first; a competing decision and a replay cannot win again.
- Both phone sessions accept the same signed status, retain the winning phone, and clear captures on Unknown. Replayed pending status cannot restore details.
- Revoking one phone rejects its decision while leaving the other able to decide.
- The retained Mac deadline rejects an otherwise valid phone signature.
- Altered request bindings and a wrong signing purpose leave the request available for a later valid decision.
- A narrow decision key cannot authorize a command, and tampered Mac status cannot replace verified phone state.

- A rolled-back consumption publishes no Accepted status, leaves no consumption or audit event, and lets the other phone win.
- A rolled-back outcome publishes no Unknown status and retains the capture until a later committed transition.
- Reopening after consumption or simulated dispatch preserves the winner, starts a fresh epoch, and records Unknown. Further reopening preserves that terminal outcome.
- Reopening a pending request clears its capture and publishes Cancelled without consuming it.
- A verified synthetic success survives reopening without becoming Unknown or creating another outcome event.

Transport authentication, encrypted channels, fresh reconnect synchronization, persistent trust, durable admission coordination, checkpoint and rollback witnesses, real device keys, and target execution remain outside this experiment. The harness establishes interoperability of the current production codecs and verifiers, not completion of the full approval product.

The Kotlin peer signs with standard `SHA256withECDSA` DER output. The shared strict P-256 converter produces the 64-byte wire signature consumed by the Swift verifier. This exercises the format conversion needed by Android Keystore without claiming hardware-backed signing on the host JVM.
