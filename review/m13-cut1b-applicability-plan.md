# M13 cut 1b — Report recovery applicability in Setup status

This plan follows PR #871 at `66e5f051`. Reconcile main after #871 merges and get Toni's review before implementation. Cut 1b supplies the status contract for the Mac client. The panel and real action controls remain in cut 2.

## Contract

- Keep the current status selector. Preserve the v1 bytes and the library-only v2 grammar. Propose v3 for the redacted v1 facts plus one applicability field. Keep status codec negotiation separate from Setup recovery IPC 13. Declare the new codec for both the app and Setup in the verified release. A v1-only release keeps status readback and offers no action.
- Report one advisory result for the observed reservation and incarnation. Use null when evidence is unavailable, an explicit no-action value when the current evidence rules out an action, or one of restore, adopt recorded completion, and release a window-free reservation. A reply cannot grant rights or reconstruct a protected binding. Send no account, scope, path, authorization form, or internal error.
- Keep the request ID and canonical CBOR checks. Reject a recognized action without the matching identity and required facts. Reject unknown codes and mismatched replies without deriving a replacement action from v1. Use the same peer and connection checks on both sides of the status exchange.

## Source of the evidence

`SetupRetainedInvocationReservation.recoveryApplicability` runs after the recovery claim joins. The live status producer currently reads an in-memory observation through `SetupRetainedInvocationStatus.Reader`. Neither the captured row nor its absence proves that a completion is absent or that a window has never been written.

Add a nonblocking snapshot of completed evidence at the existing reservation and ledger boundary. Bind it to the current authenticated owner, reservation, incarnation, expected row and revision where applicable, and the evidence's generation. Reuse already-confirmed join and restoration facts. A status request must not create a claim, start or join work, borrow admission, or perform store I/O for applicability. Use existing try-lock semantics without introducing a second lock order. Drop the hint on contention, an active claim, a failed or pending join, a changed generation or row, or a restart-only projection. Where the owner has no way to prove an action before a real claim, return null and leave the action disabled.

Derive restore only from a matching captured window and confirmed absence of unsettled completion. Derive adoption only from matching, confirmed unsettled completion. Derive release only for a bound, window-free reservation with explicit proof that writing a window was never possible. Do not add nil-identity release or use Restore as a probe. Keep the existing recovery endpoint's exact target, current authorization, and post-join action checks. A stale hint cannot bypass them.

## Verification and forecast

Preserve the v1 and v2 golden bytes. Cover request negotiation, known action and null values, malformed or noncanonical replies, foreign peers, stale snapshots, joined and unjoined evidence, invalidation on replacement, and no mutation from status. Check the built release declarations on both sides. Reconcile the actual test selection before the gate.

The approved cut 1 rerun took 352.623 seconds end to end. Its three Core shards took 83.808 seconds including compile and discovery. All 28 new methods totaled 0.011 seconds of recorded case time, with a 0.003-second maximum in that run. Replace the blanket 60 seconds per new method with a provisional 1-second allocation for deterministic in-memory cases. Estimate signed-bundle, native and store fixtures from the corresponding measured cases, including setup, and keep build and runner overhead separate. Use measurements from the eventual diff to set timeout and cap proposals. No cut 1b runtime or gate is measured yet.
