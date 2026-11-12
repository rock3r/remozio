# Native promotion scope design for E01 review

Draft for Toni and chiacchiersaturn. Assignment: Telegram message 1695.

Keep G7 owned-only. Add the native adapter only after this design passes review.
The adapter must borrow G4 custody and G3 pair evidence. It must never derive authority from publication values or callbacks supplied by a caller.
G6 must supply the actual current frame during each callback. File replacement must use a separate scope outside every machine-store transaction.

This design proposes no weaker security check. The concurrency proof remains an acceptance condition, as described below.

## Source and current behavior

The source reference is commit `65b912db7db6ed0e7876d80d33824232c79666d9`, tree `5e1399a0dc8da093ba217140ebeed65889df9678`.
This is Bepi's G7 source. Toni reports a different integration tree, `71fc5ce7`, above PR 700.
Reconcile the design against the eventual integration commit before implementation.

| Current owner | What the source establishes | Source location under `macos/core/Sources/RemozioCore` |
| --- | --- | --- |
| G4 NativeContext | Root, fixed machine and bundle paths, custody, code identity, release, owner, services, material and activity checks | `MachineUpdateRetainedSetupPromotionNativeContext.swift`, lines 79–142 and 145–191 |
| G4 approval | Exact initial frame, or the permitted promotion metadata change; no 27-to-28 change | Same file, lines 226–237 |
| G3 pair reader | Fixed existing journal and continuity paths; read-only stores; boundary checked around the callback | `MachineUpdateRetainedSetupPromotionNativeSupport.swift`, lines 59–106 |
| G5 pair validation | Complete boundary and recorded classification checked repeatedly | `MachineUpdateRetainedSetupPromotionSourceValidation.swift`, lines 20–38 |
| G6 frame loan | Process, thread, callback lifetime and actual private writer frame | `PreparationIntentStore.swift`, lines 3707–3774 and 3848–3885 |
| G6 transitions | Four callback stages; the last stage also runs in a read transaction | Same file, lines 3887–3907 |
| G7 file operations | Initial observation, exact read-back, mandatory retained-file confirmation and no exchange for selected files | `RuntimeRetainedSetupCompletionPublication.swift`, lines 84–100 |
| Admission | A borrowed scope expires on return; ordinary admission uses a shared kernel lock | `UpdateOrdinaryAdmissionLease.swift`, lines 6–27 and 78–107; `UpdateAdmissionBarrier.swift`, lines 68–100 |

G4 currently keeps its machine directory, admission owner and placement lease inside `withNativeScope`.
G6 still takes separate directory and admission arguments. Those arguments must become loans from that G4 owner on the native path.
G7 requires `retainSelected` as a separate callback. It rejects Root in its owned helpers.
Do not remove that rejection to create a native path.

## Required invariants

1. Only the actual G4 factory can issue native custody evidence. Owned Controls and value constructors cannot issue it.
2. G3 opens only the fixed existing read-only pair. It must never initialize, migrate, repair or register either store.
3. Every file check uses the actual current machine frame, the complete pinned pair boundary and recorded pair classification.
4. SQL writes retain G6's producer preflight, writer identity, admission, catalog, other-account digest and exact transition checks.
5. Native paths use existing Root ownership, file metadata, link, directory and exact-byte checks. No generic arbitrary-path write API is added.
6. Replacement and retained-file synchronization run outside machine-store transactions. Callback observation remains read-only.
7. A failure revokes its scope and stops the operation. No automatic replay follows an uncertain swap or commit.
8. Completion means exact selected bytes and successful file and parent synchronization before the marker is requested.
9. No scope authorizes startup, activation, policy changes, service lifecycle, health success or ordinary admission reopening.

## Lease ownership and borrowing

G4 remains the sole owner of its directory, ordinary admission owner and installed placement lease.
Add a sealed machine-lease loan in the G4 implementation file. Its initializer stays inaccessible to other files.
The loan binds the NativeContext instance, process, thread, owner lifetime, machine identity and expected admission identity.
Its public-to-module surface provides bounded validation and synchronous operation entry. It provides no close, unlock, raw descriptor or replacement-lease constructor.

G6 enters `withMachineAdmission` through that loan, using the existing admission owner once per store operation.
G7's external file operation enters a separate scope through the same owner after G6 returns.
Never nest those operation scopes. The existing admission owner rejects nesting as busy.
Creating successive scopes does not release the underlying admission and shared activity tokens held by G4.

Preserve the actual machine-store versus directory identity comparison now in `requireUpdateAdmissionDirectory`.
The facade must forward that comparison and validate the actual borrowed admission scope. A stored path string is insufficient.
G4 keeps placement validation and installed-copy identity checks. A lease loan must not replace those checks with directory validation alone.

On return, expire child scopes before closing their owners. A retained child or callback fails after expiry.
Reject cross-thread, forked-process and recursive use. A caller cannot prolong authority by retaining an object.
The scope must become unusable when its owner closes or a check fails.

## NativePairScope and its constructors

Define NativePairScope as a sealed synchronous loan in the source-validation implementation.
It retains no independent authority after its enclosing G4 and G3 callbacks return.
It binds the candidate evidence, account, initialization, full pair boundary, recorded classification and the exact publication bytes.
Construction reruns G4 checks and the existing G5 boundary/classification checks. Supplied Data, a Boolean or a verification closure cannot construct it.

There are two distinct uses. Keep their mutation permissions distinct through sealed types, not a caller-controlled mode flag.

**Callback observation.** G6 issues a short-lived loan from its private writer authorization for the actual stage and actual full promotion snapshot.
Create NativePairScope inside G6's existing G3 pair callback, after the recorded boundary equals the expected boundary.
Pass the scope to the caller with that same actual snapshot. Revoke it before returning from the callback.
Its G7 adapter can only create Observation. It exposes no replacement or retention operation.

**External publication.** After G6 returns, open a G3 read-only pair under the still-active G4 owner.
Read and compare the actual durable promotion snapshot through the real machine reader, then close that read transaction.
Only the actual `.publishing` row can issue a separate publishing scope for bounded file operations.
This factory must reject an active writer-frame loan. It cannot be entered from a G6 callback, including `afterCommit`.

The external scope compares exact record identity, revision, phase, publication bytes and the full machine snapshot.
An ID, phase or publication digest alone is insufficient. Use the canonical record and existing `requireSame` comparisons.
Validate the publication's source binding and recorded pair boundary as well as its embedded bytes.
The factory accepts expected operands for comparison; it does not accept a caller's assertion that they were read durably.

## Current frames during G6 callbacks

G6 currently creates RetainedSetupPromotionFrameLoan inside each verification callback.
Its closure reads `authorization.capture(in: self)`, so G4 does not open another machine-store connection inside the transaction.
Keep that path. Never call the public snapshot readers or `captureNative` from callback Observation.

The current frame loan verifies only the completion snapshot. The new pair scope also binds the full promotion row and stage.
Extend the sealed G6 loan with a bounded full-frame comparison using the same private authorization capture.
Its initializer must remain private to `PreparationIntentStore.swift`. Do not replace this check with a closure supplied by an adapter.
Before each use, compare the complete supplied frame to that actual private capture.

| G6 stage | Actual frame supplied to Observation | Allowed operation |
| --- | --- | --- |
| `beforeTransaction` | Current durable row, read inside G6's read transaction | Read and validate only |
| `inTransaction` | Current row before the mutation | Read and validate only |
| `afterMutation` | Newly adopted row, revision and machine digest | Read and validate only |
| `afterCommit` | Committed row, read inside G6's final read transaction | Read and validate only |

Do not capture the initial publishing snapshot permanently. It becomes stale after a phase write changes the machine digest.
Do not set `approved` from caller values without the private loan check.
Retain G4's exact approval rules: 26-to-27 promotion retention and supported same-schema metadata changes; no new schema admission.
Retain G6's independent catalog and protected-row checks. A valid G4 completion frame alone does not authorize the writer.

## External file operation sequence

1. Finish and verify the G6 commit that records `.publishing`. An uncertain result stops before file operations.
2. Leave every G6 callback and machine-store transaction. Enter the borrowed external admission scope.
3. Create the publishing scope from a fresh full durable snapshot and the actual pinned G3 pair.
4. Observe all six protected files. Accept only their canonical previous or selected bytes.
5. Before each replacement, repeat the full durable publishing comparison and G4/G3 checks. Validate the actual protected directory and previous bytes.
6. Replace with the existing guarded primitive. On any error, stop. On success, read back exact selected bytes and repeat the scope checks.
7. Confirm every selected file through retention: exact bytes and metadata, file fsync, parent fsync, then exact read-back. Retention performs no exchange.
8. Read all six selected files again. Finish and revoke the external file scope before entering G6 for the marker.
9. G6 requests the adjacent `.filesPublished` transition with fresh callback Observation using each callback's actual frame.
10. Preserve G6's final checks and uncertain-commit behavior. A successful file operation alone is not a successful marker commit.

The marker's callback Observation must not reuse the expired external publishing scope.
It checks the same exact publication under a new read-only pair scope for the actual frame.
Observation performs no fsync or replacement inside SQL. File synchronization completed in the external operation.

An actual `.publishing` row with mixed files may resume after a fresh scope is acquired.
Already selected files receive retention confirmation, without another exchange.
An actual `.filesPublished` row grants no further replacement. Its later handling belongs to the reviewed E01 state machine.
Unknown bytes, changed row identity, changed pair or lost custody cause refusal without repair.

## Concurrency proof required before native writes

G4 custody and ordinary admission are not an exclusive publisher lock.
Admission uses `LOCK_SH`; ReleaseDestinationLease pins ancestry rather than serializing publishers.
A process-local synchronous scope prevents reentry on that scope. It does not exclude a second process.

The durable comparison and filesystem exchange are separate operations. Checks before and after an exchange do not make them atomic.
The existing expected-byte swap and adjacent row transitions limit races, but their complete cross-process proof is not established here.
In particular, review simultaneous publishers, other-account updates, drain attempts, a marker racing a retained-file confirmation, and identity substitution.

Before implementation, Toni and chiacchiersaturn must select and prove one of these designs:

- Establish that existing transition and exact-byte rules make every permitted interleaving safe. Enumerate all relevant writers and test the interleavings.
- Require a protected, shared operation owner across the relevant writer and file paths. Review its identity, lifetime, ordering and crash behavior separately.

Do not silently upgrade ordinary admission to drain or exclusive activity. That would change a separate contract and can conflict with G4's held shared tokens.
Do not claim a same-process mutex or a queue establishes cross-process exclusion.
Do not use a long SQL transaction across file writes to conceal the gap.
No new native mutation is ready until this proof and the selected ownership model pass review.
Any proposed weakening goes to Seb through Toni, as requested in message 1695.

## Required validation and review decisions

| Area | Required checks |
| --- | --- |
| Construction | Owned Context, arbitrary values, fake callbacks and wrong G3 pair cannot construct either native scope |
| Lifetime | Escape, cross-thread, fork, reentry, owner close and verification failure revoke access before the next read or write |
| Lease borrowing | No new admission or destination acquisition; no borrower close; no nested operation entry; loss of the original inode stops access |
| Current frame | Each G6 stage uses its actual full frame; the initial frame fails after mutation; no nested public machine reader runs |
| Durable row | Wrong account, ID, revision, phase, bytes, machine digest, candidate or pair refuses before an exchange |
| File recovery | Source, mixed and selected states; exact read-back; retention without exchange; stop after uncertain swap; successful file and parent fsync required |
| Marker | File operations forbidden in all callbacks; stale external scope refused; G6 checks all selected bytes with its actual frame |
| Concurrency | Two processes and all relevant writers follow the accepted interleaving or ownership proof; no automatic retry after ambiguity |

The existing G7 recovery test proves a separate retention call and unchanged inode.
Its cleanup may already have synchronized the parent. It does not isolate an earlier fsync failure.
Keep that limit explicit. Add a bounded native durability test only under a separately reviewed seam and owner-controlled gate.

Toni reports G7 build success and 12 passes. These owned-file checks do not prove native placement, producer compatibility or the complete driver.
Actual producer evidence, the native positive path and canonical acceptance above the ordinary SQLite record limit remain separate E01/C06 requirements.

Review must approve the two scope constructors, the full-frame loan, the borrowed-lease facade and the concurrency proof.
Until then, this is a design document only. It changes no code, manifest, schema, producer declaration or product entry point.
