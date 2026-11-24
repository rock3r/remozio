# PR5 plan for Android re-pair retirement

[Issue #901][issue] requires Android to resolve a retained re-pair attempt after the first reply is lost. This plan follows the [approved recovery plan][pr4-plan] and the [protocol at PR #920][pr4-protocol]. Start implementation after #920 merges. Recheck the protocol at the merged head before choosing test selectors.

The app can activate after it verifies a commit receipt or retire after it verifies a signed expiry receipt. **A refusal or closed connection is inconclusive. Never retire from either result, even when all retries fail.** A deadline on the phone also gives no authority to retire. The Mac can record expiry only through its existing owner. The Paired Phones discard in [#916][discard] remains a separate administrator action. If that leaves the phone with a refusal, the phone keeps its preparation.

## Record and lease

- Use the existing `StoredPhoneEnrollment` in the `PREPARED` phase. `AndroidEnrollmentStore` keeps it in the encrypted, credential-protected `noBackupFilesDir/enrollments/state` archive. `EnrollmentFile` uses an exclusive file owner and atomic replacement. The archive retains the exact transcript, setup ID, predecessor reference, candidate key references and re-pair proof marker. The private keys stay in Android Keystore.
- Route the saved incomplete re-pair through the existing receipt check. Select the record by its local ID. Under the `StoredPairingHost` enrollment mutex, acquire the existing `PreparedPairingAccess` and lease only for that exact `PREPARED` row with `proofMayHaveBeenSent == true` and no live setup owner. Ordinary pairing keeps the enrolled version 1 receipt flow. Safe cleanup of a re-pair that never submitted proof keeps its current path.
- Allow one recovery owner for the record. A second check must observe the in-progress check or return without opening I/O. Register the owner and transfer its lease to cleanup before the next cancellation point. Keep the lease through retries, connection joins and any verified local transition. `PreparedPairingLease` is an in-process liveness token. It cannot prove that another owner has drained.
- Check the lease before opening a route, sending the query, signing the challenge and accepting the reply. Under the mutex, re-read the current row before activation or retirement. Require the same record ID, phase, canonical transcript and connection material. A rename need not invalidate the check. A replaced row, revoked lease or competing owner prevents the transition.

## Recovery connection

1. Load the existing candidate TLS identity from its retained transport alias and public key. Confirm that it matches the candidate key in the transcript. Pin the Mac transport SPKI from the same transcript. Use TLS 1.3 with the exact `remozio-pairing-recovery/1` ALPN on the existing Transport listener. Require a fresh handshake. Disable resumption, tickets and early data for recovery. The recovery path uses its own framing after TLS. Keep approval and enrolled receipt modes separate.
2. Reuse the direct route discovery and bounded carrier selection. When a relay credential is already authorized for this same endpoint and Mac/account, use the opaque relay as the alternate carrier for the same pinned TLS handshake. The candidate row currently has no relay credential. Before enabling that path, confirm that the retained credential of the exact predecessor is eligible for recovery under the existing routing policy. Recheck its endpoint and binding under the enrollment mutex. If there is no eligible credential, the app has only a direct route. Denied LAN permission skips the direct route and does not invalidate a separately eligible relay. This plan adds no relay provisioning or credential copying.
3. The current `PinnedTLSClient` wraps an `SSLEngine` and exposes no exporter. Add a recovery-only interface to export 32 bytes from the exact authenticated TLS connection. Use `EXPORTER-dev.remozio.pairing.recovery-lookup/1` with empty context. Prove that a supported provider exports identical bytes on both peers, over direct and relay. Require the same Android Keystore signing identity. If the provider cannot meet these requirements, keep recovery unavailable for it. Do not use a session ID, handshake hash or application nonce as an exporter substitute.
4. Send one bounded lookup frame with the retained setup ID, transcript digest and scope in Mac, account, phone and candidate epoch order. Receive one 32-byte challenge. Sign the exact PR4 input with the candidate transport key and submit one raw 64-byte P-256 proof. Use the protocol domain `dev.remozio.pairing.recovery-lookup/1`, its zero separator, the exporter, challenge and lookup body in that order. Put the signing operation behind the typed recovery interface, bound to the retained record and live session. There is no biometric enrollment proof submission.
5. Read one response using the four-byte big-endian length, protocol tag and exact bounds in #920. Reject oversized, truncated, unexpected and malformed frames. The accepted results are a valid `MAC_COMMIT`, a valid signed expiry receipt, or inconclusive. Treat an unavailable ALPN or exporter, a failed proof, a refusal, EOF and a timeout as inconclusive. Do not reuse an exporter or challenge across attempts. Do not log keys, credentials or proof inputs.

## Bounded retries

Propose three serial lookup attempts per explicit check, with delays of one and two seconds after inconclusive replies. Use one 30-second monotonic budget for route selection, network exchanges and backoff, with at most eight seconds of network work per attempt. Use the remaining budget if it is shorter. The lease belongs to the check through closure and cleanup. The network deadline cannot release it while workers still own the identity.

Close and join each failed route before retrying. Open fresh TLS and obtain a new challenge each time. Choose an alternate carrier within the same limits only after the failed carrier drains. After one valid proof, stop retrying. Cancel promptly when the check stops and drain its I/O. Do not schedule a background retry. After budget exhaustion or cancellation before a verified transition, keep the same record, marker and keys.

## Verify and retire

1. For a commit reply, verify the existing `MAC_COMMIT` signature against the exact retained transcript and pinned Root authority key. Drain recovery I/O, then use the existing verified activation path under the lease and enrollment mutex. Do not consider the local expiry date a reason to reject a valid commit.
2. For expiry, decode the canonical `PairingExpiryReceipt` with its existing 1 KiB limit. Verify the signature and all claims against the retained re-pair transcript and pinned Root authority key. The claims bind the setup ID, transcript digest, scope, predecessor epoch, retained trust revision, original expiry and signed reason. Accept the two protocol reasons. A retired incarnation does not require the wall deadline to have passed.
3. Stop retries and further sends. Close the TLS session and carrier, join workers and pending signer calls, then close the candidate key manager. Wait for actual completion, including the relay carrier. Closing alone does not establish that providers or workers have finished. Keep the record and lease while joining. Do not join while holding the enrollment mutex.
4. Under the enrollment mutex, confirm that the lease and sole recovery owner are still current, no other candidate I/O is live, and the archive still has the exact `PREPARED` row. Verify the signed expiry again against that row. If cancellation won before the storage boundary, leave `PREPARED`. Once the verified local transition begins, finish it without caller cancellation. A storage or ownership failure before that transition leaves the attempt ineligible for retirement.
5. Add a proof-gated transition on the existing encrypted store. Atomically write only that candidate as `REMOVED`, retaining its exact key references for cleanup. Do not call the generic removal path or the manual ambiguous-abandonment operation. Leave the predecessor, active enrollment, other candidates and any successor links as they were. Delete unused candidate transport, decision and biometric keys only after the committed archive confirms this removal. Keep the enrollment mutex for durable mutation and key reference checks. Then release the lease and refresh the saved Mac list from the archive.

## Interrupted cleanup

Use the existing removed re-pair row as the durable cleanup record. When startup or the next enrollment operation reopens the archive, reconcile only from a readable, committed snapshot under the existing owner.

| Last durable state | Recovery |
| --- | --- |
| Exact attempt still `PREPARED`, or the archive write cannot be resolved | Preserve the candidate and its keys. A later explicit check needs a new authenticated lookup. While storage is uncertain, close the recovery owner and defer cleanup. |
| `REMOVED` committed, process stopped before key deletion | Resume cleanup of that row only after live owners drain. Recheck current references and the expected public key for each alias. |
| Some candidate keys already deleted | A missing alias needs no further action. Keep any alias that an active or prepared enrollment or reservation references. Preserve a different key at the same alias. Retry transient deletion failures from the same cleanup row. |

Do not restore `PREPARED`, delete the predecessor's keys, or send another enrollment proof while finishing a committed removal. Keep the existing archive schema and cleanup conventions unless implementation finds a concrete incompatibility.

## Evidence for implementation

| Scenario | Required outcome |
| --- | --- |
| One uniform refusal or inconclusive reply | Keep the exact `PREPARED` row and its keys. Join recovery I/O before release. |
| All attempts hit refusal or inconclusive outcomes | The final state contains the same preparation and keys, with zero retirements and zero enrollment proof resubmissions. Check attempt count, monotonic cap and delays with a fake clock. |
| Valid signed expiry after earlier refusals | Verify the same leased record again, join I/O and retire only that row and its unused keys. Test both expiry reasons. |
| Root-produced proofs over direct and opaque relay | Verify exporter equality and exact raw frames through real Transport/Root fixture entry points. Include actual candidate-key signing. Test how the route behaves with denied LAN permission, an absent relay credential and an unavailable exporter. |
| Replay and invalid proof | Vary the exporter, challenge, setup ID, digest, scope, predecessor, retained revision, expiry, reason or signer. Reject stale, malformed and cross-attempt input with zero retirements. |
| Verified commit after earlier ambiguity | Use the existing activation path. No expiry, refusal or local wall deadline removes the committed enrollment. |
| Cancel, replace or race activation | Hold route open, signing, read, join or archive commit at controlled barriers. Check that no deletion precedes the join or touches a changed row. Include two checks on the same local record. |
| Process stops before or after archive replacement, or between alias deletions | Reopen from the committed state. Preserve uncertain preparations and resume authorized cleanup idempotently. Preserve all live, reserved or mismatched keys. |
| Legacy and ordinary pairing | Keep enrolled version 1 receipt recovery and approvals working. A companion without the recovery ALPN leaves a re-pair candidate intact. Check that the dedicated route cannot open an approval session. |

Use the shared expiry vectors for claim and signature checks. Add exact selector inventory, runtime forecast and a proposed cap before running the implementation gate. The software-key loopback proves protocol exchange and local state transitions within the fixture. The Android TLS provider and Keystore integration, installed Root, and the physical Mac–Pixel flow require their own evidence.

[issue]: https://github.com/rock3r/remozio/issues/901
[pr4-plan]: https://github.com/rock3r/remozio/blob/9f7c7ce5/review/901-pr4-recovery-route-plan.md
[pr4-protocol]: https://github.com/rock3r/remozio/blob/e1b0fab8/protocol/pairing-receipt.md
[discard]: https://github.com/rock3r/remozio/issues/916
