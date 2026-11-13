# A09 initial retained publication and completion

Base:32fc0753abcfcc94e12783903d6836e49d05f895, treed4168ae997aa46590bb4cc7417bba564f684bd6d.
Toni2157 requests the plan before code. No product source, build, test or native operation changes in this preparation.
The approved source plan is5b2d745e:review/schema27-writer-plan.md, SHA2566472c6637dfca667c25abdeb98745c86beaac31097109154dce43505efd9e99c.
Its A09 row covers initial retained publication and completion after recorded policy25. Its donor estimate is not the current implementation footprint.

## Source findings

1. RuntimeRetainedSetupInitialConfiguration already binds the recorded policy, startup policy, runtime material, import options and exact canonical bundle.
RuntimeRetainedSetupPublishedSelection and RuntimePublishedArtifactValidation already read and validate the existing files.
The first publication uses the ordinary eight-file set: elevation policy, command configuration, transport identity, transport configuration, gateway host and three clients.
It does not publish command-host or job manifests. Those belong to the later activation stage.

2. RuntimePublicationController.publishNative already owns fixed paths, file modes, protected directories and the publication primitive.
A narrow retained wrapper can reuse it after validating the retained binding. No general file replacement API is needed.
AdministrativeSetupPublication.publish creates absent files or retains exact existing bytes. Conflicting files refuse.
A failure after rename does not prove that nothing was published. Recovery must read actual bytes before another action.

3. completeStableRuntimePublication is not a retained writer. PreparationIntentStore.swift:4217 rejects every origin except currentRelease.
StableRuntimePreparationAuthorization repeats this guard. MachineUpdateStableRuntimePreparationSnapshot.requireRuntimeInputs also preserves it.
The donor completion path calls this ordinary writer, so copying the two donor files would be incomplete and unsafe.
A09 needs an explicit retained-only authorization. The ordinary guard and its refusal classification must stay unchanged.

4. PolicySnapshot has no requirePublication comparison. The retained material snapshot forbids a published state.
A separate exact false-to-true comparison is required. It must keep the recorded policy row and every other runtime operand fixed.
No material snapshot bypass or ordinary decoder fallback is proposed.

5. P04a Context.verify accepts only an equal frame or policy retention/transition. It cannot accept the publication bit change.
Do not widen P04a or reuse its policy context for completion. The missing donor native pair/single-machine helpers also cannot be assumed present.
The native facades therefore need an explicit later closure, described below, rather than temporary stubs.

## Proposed source cuts

Each proposed cut has a200-line cap across all production paths, including helpers, guards and deletions.
These are estimates. Measure the complete production diff before adding test source. Revise the plan if a complete responsibility exceeds the cap.
Each cut gets its local build/new-class gate. Toni owns wider tests, publication, actual merge order and main reconciliation.

| Cut | Complete responsibility | Expected production paths | Estimate |
| --- | --- | --- | --- |
| A09a | Exact retained publication transition model | MachineUpdateRetainedSetupPolicySnapshot.swift; a narrow new comparison helper only if needed |80–140 |
| A09b | Private retained publication SQL authorization | PreparationIntentStore.swift, including transaction gates and writer exclusions |160–195 |
| A09c | Owned initial file publication with fixed native file primitive | new MachineUpdateRetainedSetupInitialPublication.swift; RuntimePublicationController.swift |140–195 |
| A09d | Owned completion and actual-state recovery | new MachineUpdateRetainedSetupInitialCompletion.swift |150–195 |

A09a must compare the same recorded intent, owner, preparation, initialization, inventory, installed epoch, seal, admission, schema and reservations.
Only runtime_preparation_v1.complete may change from0 to1, with the same exact material reference. Plan, jobs and enrollment stay unchanged.
An already-published recovery read accepts only the exact recorded pair and actual matching files. The comparison itself grants no write authority.

A09b must add a private retained-only writer. It updates one existing matching runtime row and requires sqlite_changes==1.
Bind the authorization to this store, process, thread, held admission, exact candidate, original frame and typed next frame.
Pin the entire catalog and every other row, including policy intent and activation. No schema migration, table creation or policy commit occurs.
Check formats before BEGIN. Preserve the ordinary writer refusal and mutually exclude all other writer authorizations.
Lend checked actual frames during callbacks. Do not start a nested public snapshot transaction.
Failures before commit roll back. Attempted or uncertain commit closes the writer and requires fresh state resolution.
Repeated exact published state must cause no second UPDATE.

A09c requires recorded policy and the exact paired boundary before any file operation. Prepared and unresolved writing refuse.
Check admission, current machine frame, material bytes, service activity, configuration digest and the pair around each callback.
Read material twice and reject changed bytes. Preserve current import, relay and client tunables.
Use the existing eight-file artifact set and publication rules. Read back every artifact after publication.
This step does not change metadata. Partial or uncertain publication is resolved through fresh reads; conflicting bytes refuse.
Verification loans must expire on return, throw, recursion, another thread or another process.

A09d verifies files and material before invoking A09b, around each actual writer frame and after the final actual read.
Use borrowed transaction frames without querying the same store again. Preserve the exact recorded pair throughout.
Any error leaves the invocation. A new attempt reads the actual disk state and does not reuse an advanced frame after rollback.
After a lost acknowledgement, an actual published row plus exact files can be observed without republishing or another UPDATE.
Missing or changed material, source, pair or artifacts refuse. No jobs are registered and no ordinary-ready result is added.

## Native closure proposal requiring Toni's direction

Keep A09a–d as complete library/owned responsibilities. Add no incomplete native facade or fabricated custody proof.
Move the donor prepareNative/completeNative facades into the explicit A11 native-runtime-provider closure.
A11 must build a stage-specific publication custody context and the read-only pair scope before those facades can call the owned operations.
It must preserve P04a's policy-only transition guard and reuse P04b's fresh current-authority selection contract.
This is a proposed schedule change, not permission to omit native work. If native facades must remain in A09, add separately sized native cuts before coding them.
No command, RPC, service or automatic activation calls the new operations in A09. No new manifest writers are enabled here.

## Tests and gates

- A09a: valid recorded control, exact bit transition, already-published equality, changed reference/intent/revision/checkpoint/owner/runtime inputs, foreign or ordinary account.
- A09b: exact one-row update, duplicate no-op, unrelated-row/catalog protection, pre-BEGIN format refusal, writer exclusion, callback rollback and uncertain/post-commit closure.
- A09c: all eight artifact bytes and access kinds, valid existing-file retention, conflicting/symlink/metadata refusal through existing primitives, partial publication and changed material/pair/import evidence.
- A09d: actual publication then one metadata update, callback frames without nested queries, escaped scopes, rollback then fresh invocation, lost acknowledgement, changed files and idempotent actual-state recovery.

Use fresh owned stores and isolated temporary artifacts. Group independent negative cases around a valid control where that preserves isolation.
Injected publication and identity controls prove ordering only. They do not prove Root, service identities, signatures or protected installed placement.
Build and run only the new or changed classes through installed ATC when Toni returns native ownership. Retain exact per-case timings and actual terminals.
Toni owns full regression capacity and publication; the reviewer owns CI weights. Do not raise budgets or skip assertions to fit a slice.

## Decisions and excluded work

Toni2161 and issue722 comment6856960221 decide P05 separately. It follows the busy check in725.
P05 is an attended owner action only, with exact fresh source policy/revision/checkpoint equality. Resume stays unavailable and P05 never writes the journal.
A09 is not blocked by P05. A09 requires recorded policy; a writing marker stops it before publication. A09 adds no reset or replay path.

Issue725 applies to the first real caller, not A09. Derive its authority ID from verified peer/account authority instead of an argument.
Before writing that caller, perform the attended busy check with the authority service active. Retain the end-to-end commit and inspection timing checks too.
No live Root, key, service, device or installed publication check runs during this plan. Existing UX, consent, admission and ready-state semantics stay unchanged.

Status: proposal sent for Toni's scope direction. No A09 code is applied or qualified. The full Remozio objective remains incomplete.

## Review requirements (binding, from chiacchiersaturn's plan review, accepted by toni)

1. A09b: `completeStableRuntimePublication` on a `.retained` account still refuses with the same classification as before. The new retained writer refuses a `currentRelease` account.
2. A09a: after publication, the P02 and P03 policy writers refuse, because they require `!configurationPublished`. A recorded policy cannot change under published files.
3. A09c: resuming from k of 8 published files completes the others without rewriting the exact ones. A present file with different bytes refuses without touching the others.
4. A09d: all files published with the row still at `complete = 0` (a crash between A09c and A09b) makes exactly one `UPDATE` and no new file write. This is separate from the lost acknowledgement after the `UPDATE`.
5. A09c: every published byte derives only from the recorded material, so a retry by A09 always produces the same bytes. Add a test. Different bytes therefore mean something outside A09 wrote the file; A09 refuses and never overwrites. That case is an owner intervention, recorded on #722 beside P05.

## A09c contract (decided by toni after bepi found the override and import-scope gap)

Problem found before the gate: `RuntimeConfigurationBundle.retainedSetupInitial` and `RuntimeRetainedSetupInitialConfiguration` accept free `presencePolicyOverride` and `relayPortOverride` values, so two calls with the same recorded snapshot can produce different bytes. A recorded import also fails `SharedSetupImportIntent.Scope`, because that scope is built from the retained preparation and the current inventory, while the import was recorded for the historical ones.

Contract:
1. The retained publication path takes no free overrides. Add a retained-only entry without the override parameters; the existing ordinary entries keep theirs unchanged.
2. The tunables come only from durable records read fresh inside the publication scope: the retained account's actual journal import record and its relay record. If the journal holds no import record, the defaults apply, but the absence must come from an actual read, never from a nil argument.
3. An import record is accepted only when its scope equals the scope of the historical preparation and provisioning inventory it was recorded for. Those come from the pinned snapshot (`provisioningHistory`, `preparations`), with an exact account binding. Do not weaken `SharedSetupImportIntent.Scope` for other callers.
4. A typed adapter maps the accepted import and relay plan to the new files' presence and relay settings. Pin the import and relay digests in the configuration digest, so a changed record changes the digest and refuses.
5. Bytes are a function of: recorded snapshot, current pair, candidate, current code policy, import record and relay record. Tests: the same inputs give identical bytes twice; a non-default import fixture gives its own values; a changed import or relay record refuses; a free override cannot reach the retained path.

Split: A09c1 is the value contract above (retained entry, import adapter, digest pins; no file writes). A09c2 is the owned publication of the eight files through the fixed publisher wrapper, using A09c1. Each stays within 200 production lines.
