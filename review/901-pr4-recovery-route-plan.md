# PR4 plan for the re-pair recovery route

[Issue #901](https://github.com/rock3r/remozio/issues/901) needs a recovery path that works when the candidate has no active enrollment. This review covers the Mac route and its proof. The storage changes in PR3 must merge first. Android retirement and the Paired phones action are separate changes.

## Admission and request

Use the existing Mac transport listener and address. Select a dedicated recovery purpose in the TLS handshake before choosing a handler. The phone pins the Mac transport identity from its retained pairing setup. Recovery has its own admission limit within the listener’s existing capacity. The relay forwards the connection without interpreting the purpose. The route works after the setup UI and invitation close, over both direct and relay connections.

The connection accepts one lookup. The phone supplies the exact setup ID, transcript digest, and scope. Root issues a fresh 32-byte challenge for all well-formed lookups, including an unknown setup ID. It expires at the handshake deadline and is consumed once. Bind the proof to the TLS exporter, challenge, setup ID, digest, and scope. Encode the fields with fixed widths or length prefixes. Use a signing domain distinct from both receipt and expiry proofs. Root verifies possession of the candidate transport key from the retained transcript.

The recovery capability permits only lookup and reply. It grants no approval, enrollment, route change, or access to another setup. Root must verify the Transport caller and its current code policy. Keep the version 1 enrolled receipt flow and its admission unchanged. Legacy clients continue to use that flow for active enrollments.

## Root decisions

Root reads the stage and committed enrollment under the existing owner and verified checkpoint. The recovery path is read-only. The maintenance and startup owners remain responsible for making expiry durable. A pending row past its deadline stays inconclusive until one of those owners records the terminal state. The phone treats a refusal as inconclusive. It keeps the preparation and keys even after it reaches the retry limit. It can retry with bounded backoff.

| Evidence for the authenticated query | Reply |
| --- | --- |
| Exact committed enrollment that still satisfies existing receipt checks | Return the existing positive proof over the retained transcript with the MAC_COMMIT purpose. This lookup uses the committed enrollment ledger. A successful commit has already released its stage slot. |
| Exact pending stage, before or after its deadline | Return an inconclusive result. The phone retains the preparation and keys. |
| Exact durable deadline-elapsed stage | Return a Root-signed expiry receipt with reason deadline elapsed. Use the signed payload from [PR #911](https://github.com/rock3r/remozio/pull/911). |
| Exact durable retired-incarnation stage | Return the same signed receipt format with reason retired incarnation. This makes no claim about the wall deadline. |
| Missing, replaced, discarded, or removed stage with no exact eligible commit | Use the same refusal as for wrong binding or proof. Absence alone never authorizes retirement. |
| Wrong digest, scope, proof, or key | Return a single refusal with the same response shape as an unknown setup ID. The challenge and refusal reveal no separate reason. |
| Revoked enrollment, uncertain clock or lease, broken checkpoint, or failed signature | Return no useful proof. The phone retains the preparation and keys. |

The expiry signature binds the exact setup ID, transcript digest, Mac and account, candidate phone and epoch, predecessor epoch, retained Root revision, expiry, and reason. Recheck the relevant retained record, caller policy, scope, and lease before releasing either signature. If any check fails after signing, discard the result. Revisions in the expiry proof come from the stored transcript. A change to unrelated trust does not change those signed claims.

Do not introduce a route to resend an enrollment proof. An authenticated client that loses its reply can repeat the read. It can accept a positive or negative proof only by verifying it against the exact stored transcript. Two valid signatures can have different bytes. Tests compare the claims and verify the signature.

## Evidence before the phone uses the route

| Scenario | Required proof |
| --- | --- |
| First real expired re-pair with no active enrollment | Use the real Transport and Root entry points with an ordinary-user fixture. Close setup, let the owner record expiry, and recover a valid proof with the candidate key. Run over both direct and relay connections. Confirm the same peer cannot establish an approval session. |
| Pending on both sides of the deadline | Read before deadline and again after deadline while maintenance is held. Both reads leave the journal and checkpoint unchanged. Release maintenance and prove the owner records expiry. Query again and verify the signed deadline reason. The restart case proves the alternative progress path. |
| Retired incarnation | Reopen after startup reconciles the checkpoint and closes a prior incarnation's pending stage. Verify the retired-incarnation reason and the unchanged bytes across the lookup. |
| Commit wins and its first reply is lost | Commit through the existing writer, then recover a valid positive proof through the intended route. The slot stays free. No expiry proof can be returned, including on retry or restart. |
| Expiry wins a concurrent commit | Use barriers at the owner. The late commit refuses. The recovery reply remains a valid expiry proof with the same claims. An uncertain intermediate checkpoint gives no proof. |
| Missing and replaced attempts | Query unknown IDs and old IDs after replacement, local revocation, or authorized discard. Confirm no expiry proof is issued. Include old-format journals and ordinary pairing. |
| Proof binding and replay | Vary the transport key, digest, setup ID, scope, challenge, and TLS exporter. Reject every mismatch and replay. Verify one challenge per lookup and compare the challenge and refusal shapes for unknown IDs, wrong bindings, and invalid proofs. |
| Authority failure and closing | Change caller policy, retire the lease, interrupt signing, and inject a storage error. Refuse the reply and release the connection. Check deadlines, cancellation, malformed input, second-query refusal, and admission capacity. |
| Compatibility | Run version 1 active receipt lookup and enrolled approval smoke tests. Test a legacy Transport without recovery support. An unavailable route leaves the phone's record intact. |

Use existing signed vectors for the payload format. Add a route test that verifies real Root-produced bytes against the same transcript. A desktop software-key fixture does not establish installed Root, hardware custody, or a physical Mac–Pixel result. Confirm exact test selectors and forecast before the implementation gate.

## Required PR5 Android retirement tests

| Phone observation | Required outcome |
| --- | --- |
| One uniform refusal or an inconclusive reply | Keep the exact PREPARED record and its keys. Join the recovery connection before releasing the lease. |
| Every attempt in a bounded retry sequence returns a refusal or an inconclusive reply | After the final attempt, the same PREPARED record and keys remain usable. Record zero retirements and zero enrollment proof resubmissions. |
| A valid signed expiry proof arrives after earlier refusals | Verify it against the same PREPARED record under its lease. Join recovery I/O and retire only that record and its unused keys. |

## Follow-up boundaries

- Android retirement verifies the proof again against the exact PREPARED record under its lease. It closes and joins network I/O before retiring that record and its unused keys. Recovery after interrupted cleanup must preserve this order.
- [#916](https://github.com/rock3r/remozio/issues/916) adds the list and explicit admin discard action under Paired phones. This route queries one attempt and never lists or discards records. An account at 32 retained rows can refuse a new identity until a slot is freed. Close #916 before #901 is complete.
- Keep the recovery route out of PR3. This branch proposes the behavior for review and contains only this plan.
