# Signed expiry for a re-pair attempt

Review proposal for [#901](https://github.com/rock3r/remozio/issues/901). The reference base is `771797a0`. This proposal covers Android re-pair under #840.

## Reachability comes first

Today Android opens `remozio-receipt/1` with the retained transport identity. The Mac admits that connection through `DirectApprovalSession`. Both that admission and the Root receipt lookup require an active enrollment. A candidate whose setup never committed cannot pass those checks. Its revoked predecessor cannot act for it.

Add a separate, versioned recovery listener path for one read-only lookup. The phone pins the Mac transport key saved in the prepared transcript. The listener authenticates possession of the candidate transport key and binds that proof to the specific setup ID and digest. Transport forwards the bound identity through authenticated local IPC. Root compares it with the key in its own stage. A request contains only the fields needed to locate and match that stage. It cannot supply a transcript, create a stage, submit a biometric proof, or receive approvals.

First demonstrate this route through the real listener, IPC, and Android client with a revoked predecessor and a never-enrolled candidate. This proves that the new path works after the setup listener closes. If the path cannot reach Root under these conditions, keep client cleanup disabled. Keep committed receipt recovery on its existing path.

## Root owns expiry

Root writes the stage before it sends the transcript. The stage binds the canonical transcript digest, setup ID, Mac, account, stable phone ID, candidate epoch and transport key, predecessor, staged trust revision, and both expiry representations. Root records the issuing authority incarnation and its clock epoch. That owner enforces the admitted deadline with its monotonic clock. The wall time in the transcript binds the signed result to what the phone retained.

The authority writer serializes both transitions from the exact stage.

| Event | Required durable result |
| --- | --- |
| Valid commit before the deadline | Commit the enrollment and mark the stage committed in one transaction. Preserve the existing positive receipt. |
| Verified expiry at or after the deadline | Mark the stage expired without commit. A later commit for this setup ID fails. |
| Recovery after the issuing authority stops | Mark a pending stage expired without commit only after the replacement owner proves the old commit path is closed and reads the recovered journal under its lease. |
| Missing stage, unavailable store, uncertain ownership, or a clock error in a live incarnation | Leave the outcome inconclusive. |

Root rechecks its current authority lease in the transaction. The commit path also checks the stage, the digest, the current policy, and the deadline there. A successful enrollment commit always wins over expiry if it already holds the durable outcome. A nil receipt from the enrolled lookup never proves the absence of an enrollment.

### Startup with a previous incarnation

The shipped commit path requires a live `PairingEnrollmentAttempt` held by the Root XPC endpoint. `stagePairing` stores it in that endpoint. `commitPairing` takes it from the same endpoint and checks the setup ID and digest before calling the journal writer. A new endpoint creates a fresh setup ID. I found no production path that restores a pending attempt or resumes its commit after the authority process stops. The receipt lookup only reads an enrollment that already committed. [Endpoint staging and commit](../macos/core/Sources/RemozioCore/AuthorityPairingXPCEndpoint.swift#L158-L189) · [Setup ID creation and commit binding](../macos/core/Sources/RemozioCore/AuthorityPairingSetup.swift#L160-L183) · [Journal commit and receipt](../macos/core/Sources/RemozioCore/ApprovalRequestCoordinator.swift#L246-L266)

Before opening setup admission at startup, the replacement owner acquires and validates the authority lease. It recovers the journal and checks the durable outcome for each pending stage from a retired owner. A committed outcome takes precedence, including when the reply was lost or the enrollment was revoked later. Otherwise, when the issuer is fenced and its in-memory endpoint cannot commit, Root marks the stage expired without commit in the writer. This applies after a Mac restart and after a verified authority process replacement. It requires no comparison with the old monotonic clock.

A different clock epoch alone is insufficient. If Root cannot prove the old owner stopped or cannot settle the journal, the result remains inconclusive. The stage archive is evidence and cannot restore a commit-capable attempt. During the life of the same owner, Root advances due stages through its maintenance loop with a comparable clock and an elapsed deadline. The lookup reads the result. The phone's clock never decides expiry.

Before signing, Root checks that the stage is durably expired without commit. The response uses its own signing domain and version. It binds the setup ID, transcript digest, scope, candidate epoch, predecessor, staged revision, transcript expiry, terminal outcome, and the reason. The reason distinguishes an elapsed deadline from a retired authority incarnation. The latter proves the commit window is closed even if the advertised wall time has not passed. The phone verifies the response with the Root authority key pinned in its prepared transcript. A later trust revision alone never proves expiry.

## Admission and storage limits

The limits below are proposed starting values for review. An upper bound applies before any enrollment or stage lookup.

| Scope | Proposed limit and behavior |
| --- | --- |
| Listener ingress | At most 8 concurrent handshakes or exchanges per Mac, 24 new exchanges per minute, and a burst of 8. Close excess connections before a Root lookup. |
| Single exchange | At most 1 request, 1 KiB per application frame, and a 10-second deadline including the authenticated lookup. Close on excess. |
| Verified identity | At most 3 lookups per minute and a burst of 2 for a stable Mac, account, and phone ID. Candidate key or epoch changes share the same budget. |
| Stage and terminal storage | At most 1 pending or latest terminal record per stable identity and 32 identity slots per account. Only the authorized setup path can reserve a slot. |

Require proof of possession before giving a stage-specific result. Before that proof, unknown IDs, wrong keys, and rate rejection disclose no stage state. Bound failed authentication work with the listener budget. Allocate per-identity budget state only for verified staged identities. Hold stage storage under the same authority writer.

Keep the latest terminal record for each stable identity until an authorized new stage for that identity is durably reserved. The reservation replaces the old terminal record in the same transaction. Failure to reserve leaves the old result available. A pending stage cannot be displaced. There is no time-based eviction, so a phone can retrieve the result after a long period offline. When a new stage has replaced the old result, lookup of the old setup becomes inconclusive.

The cap counts identities with either a pending stage or a terminal record. At 32 slots, existing identities can reuse their own terminal slots. A new identity receives a capacity error before Root releases a transcript. Root does not evict another phone's result to make room. Any policy to release a slot explicitly needs separate review. A missing record can never authorize a late commit or cause the phone to drop keys.

Measure a normal deliberate retry and load at the caps in the native listener test. Adjust the proposed values in review. Stage caps and rate caps cover different resources and both apply.

## Android retirement

Use the existing prepared-record owner and lease. Match the response to the retained record and verify its signature. Close the channel and wait for its work to stop. Under the enrollment lock, recheck the lease, record identity, phase, and exact retained transcript before writing a retirement result. Retire only the unused keys of that entry. Keep enough durable evidence to finish key retirement after process death. Check shared references and public keys before deletion. Repeated verified results are safe to apply.

An old peer, timeout, missing record, invalid response, or uncertain Root result leaves the record and its keys available for recovery. A paused or interrupted lookup sends no enrollment proof. Keep the existing ordinary pairing option for a user with an unresolved entry.

## Review order and proof

1. Define the Root stage transitions and shared wire contract. Use versioned canonical fixtures. Prove commit versus expiry at the deadline. Exercise restart before the deadline with a fenced issuer, loss of a commit reply, an unresolved journal, and a clock change while the issuer can still commit. Verify that an older setup cannot commit after retirement or slot reuse.
2. Qualify the dedicated route with the first real never-committed setup. Exercise the caps and verify that a candidate cannot use the approval path. Check long-offline lookup, same-identity replacement, and refusal of a new identity at capacity. For mismatched identities, check that Root returns no stage information.
3. Enable Android retirement after those proofs. Cover the wrong signature, scope, digest, revision, expiry, and setup ID. Cover response replay, concurrent activation or removal, and interruption after the archive write but before key retirement. Verify the existing positive and unknown receipt outcomes.
4. Before each PR, report the exact selectors, expected runtime, and proposed cap. Keep iOS outside this change. Any release or installed-platform verification remains a separate gate.

Prove the recovery route and confirm the capacity behavior before the Android client relies on the signed result. This branch contains the review document only.
