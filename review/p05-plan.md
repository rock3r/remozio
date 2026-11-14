# P05: attended replacement of an unresolved writing marker

## Authority and prerequisites

This document-only revision follows Toni's maintenance decision 2740 and recovery requirements 2742/2754 and per-account decision 2763/2767. No code, build or native action ran.
Fetched main is `b899e1ad34836b37745f9099db8d2594ea384150`, tree `3117e2d9c6460a2c52bea8a55c25dd80f8328f3a`; A11k #753 is merged.
Use [issue 722's decision](https://github.com/rock3r/remozio/issues/722#issuecomment-6856960221), not an inferred retry policy.
P05 is an explicit attended owner action. It discards an unresolved `writing` marker and prepares a new marker with a fresh revision.
It can do this only after a fresh read within that action shows the pair exactly equals `source.accountPolicy`.
The policy revision, role tokens, canonical policy bytes and checkpoint are all part of that equality.
P05 never writes the journal. Normal `resume` keeps refusing the unresolved source as `unavailable`.

The [source analysis](725-busy-analysis.md) established structural busy; no discovery experiment is needed to choose the design.
P05 depends on the [explicit maintenance owner](maintenance-window-plan.md), including durable recovery, visible status and its attended restoration-only exit.
Use the revised [725 validation plan](725-experiment-plan.md) to prove the chosen installed composition before enabling attended P05.
P05 runs under ordinary shared machine admission while the outer owner drains only A, proves live work settled and stops A.
It keeps the existing ordinary-admission APIs. No machine-wide closed-quiescence loan is needed.
Do not use marker replacement to hide contention, close machine admission or create a second A drain.
Toni owns the cut order, native capacity, publication, review and merges. Each ready cut merges before the next one starts.
Authenticated reachability waits for the maintenance gates, approved caller prerequisites and required installed validation. No temporary Root endpoint is planned.
The current authority A and retained target B remain distinct. Stop only A; B has no registered jobs. Root Setup stays running for recovery.

## Existing owners to reuse

- `MachineUpdateRetainedSetupPolicyIntentRecord` owns canonical v2 operands, phases, source equality and receipt reconciliation.
- `MachineUpdateRetainedSetupPolicySnapshot` owns exact machine/runtime comparisons. Its ordinary transition admits prepared→writing and writing→recorded only.
- `MachineUpdateRetainedSetupPolicyFrame` owns synchronous frames, callback lifetime and exact closed-machine boundaries.
- `PreparationIntentStore` owns `retained_setup_policy_intents_v1`, writer admission, record size limits, protected-row digests and commit retirement.
- `MachineUpdateRetainedSetupPolicyOwner.resume` owns normal policy sequencing. Keep its unresolved-writing refusal and committed-result reconciliation.
- P04/A11 native support owns current authority custody, release/code validation and typed read-only target access.

Do not add a general phase rollback, mutable intent setter, administrative SQL endpoint or repair mode to those ordinary owners.
P05 needs one explicit replacement operation. It cannot grant the existing first-writing-use receipt or a startup journal permit.
Keep the existing record format and supported schema/manifest guards. A writing row already exists; P05 does not migrate schema 24.
P05 itself changes no table, codec, completion floor, activation, enrollment or consent. The separate maintenance owner supplies its own reviewed durable record.

## Eligibility: actual state, not an error string

Require all of these inside the new action:

1. The attended administrator action and current peer/account binding are valid for this machine and retained target.
   The actual maintenance owner holds A's actual account drain and shared machine lease, proves live A idle and exact process/child exit, and retains the body scope.
2. The actual selected target is still retained, unpublished and unactivated, with the same owner/directory identity and recorded choices.
3. Exactly one eligible retained operation is selected through the concrete protected-state predicate, not a test-only count.
4. Its actual canonical marker equals the expected account, ID, revision and bytes; its phase is unresolved `writing`.
5. Reconstruct and validate the original source from protected machine operands and the marker. Validate the selected candidate and release contracts.
6. Hold the actual target pair read-only and read it freshly inside the action, including during the protected machine mutation boundary.
7. Compare that full pair with `source.accountPolicy`, including policy/role revisions and exact checkpoint bytes.
8. Keep the current authority code policy distinct from the target's historical source policy. The target cannot choose executing-code floors.

`reconciling` classification alone is not the fresh-read proof. Never infer unchanged source from a prior busy error, callback failure or lost reply.
A writing marker whose actual pair is already a provable startup result follows the existing normal reconciliation path; P05 refuses it.
This includes a no-op startup plan that normal receipt validation can already classify as recorded. Do not reset it as unresolved.
Any foreign, changed, partial, corrupt or unclassifiable pair refuses without replacing the marker.

## Replacement value and storage contract

Propose a dedicated replacement value for writing→new prepared. Do not widen `requireTransition` to allow a backward phase transition.
Generate the new marker ID and revision inside the owner; require both to differ from the old marker's values.
The new `.prepared` marker keeps the exact validated source, target, owner, initialization, candidate, startup and completion operands.
Its committed policy/checkpoint fields remain absent. Reject a supplied ID, revision, source or target from the external request.
The extra fresh ID is a proposed implementation choice for retiring the old marker identity; the decided requirement is a fresh revision.

Logically discard and replace in one machine transaction. There must be no committed interval with the row missing.
Prefer one compare-and-swap UPDATE of the existing account row's ID, revision and canonical record.
Match the exact previous account, ID, revision and record bytes; require exactly one changed row.
Do not implement two independently committed DELETE/INSERT calls or drop the table to get around an existing transition guard.

Add a dedicated scoped authorization/comparison for this replacement. Preserve all ordinary mutation restrictions.
Reuse the writer's schema checks, 131072-byte record limit and protected digest covering every unrelated row/table.
Keep the existing ordinary-admission proof at every frame/store boundary; no caller Boolean or alternate weak proof is added.
The marker CAS preserves the maintenance record exactly. Only the outer window owner may advance its separate lifecycle state.
The only permitted metadata delta is this target marker replacement. The schema, inventory, runtime material, activation and other accounts remain exact.
Recheck native custody, target/source equality and borrowed frames at the existing before/in/after transaction boundaries.
The callback receives the actual transaction frame; it performs no public machine query or nested machine transaction.
Return a dedicated metadata result. Never return `RetainedSetupPolicyWriteReceipt` or call `withFirstWritingUse` for a P05 replacement.

## Hold the pair; write only the machine marker

The action must hold a verified read-only target journal/continuity scope across its source check and machine transaction.
The maintenance-aware native context also pins stopped AuthorityA's full read-only policy/checkpoint pair through the body.
P05 writes neither A's nor B's journal. Its sole mutation is the selected target's protected machine marker.
No other writer can change that pair between proof and replacement. Revalidate the same actual scope at each relevant boundary.
Reuse existing typed read-only storage openers. Do not initialize, migrate, recover-write or open `.startup` storage in P05.
`RuntimeNativeAuthority.withTargetPair` requires a recorded policy; do not relax it for a writing marker.
Add a narrowly owned P05 target-reader adapter using the existing lower-level protected opener if needed.

Normal production Setup machine access is scoped: `Machines.scoped` opens and closes on every use.
Close each exact capture/writer handle before returning. There is no persistent production pool to suspend.
If production storage changes to `.retained`, revisit the ownership plan before implementation.
Keep process, thread, re-entry, poison and expiry guards. A captured read callback cannot survive its owning action.
The P05 owner receives read-only pair capability, not a general `AuthorityJournal` writer callback supplied by an external caller.

## Outcome, uncertainty and later resume

The P05 body ends after the new prepared marker is durably observed and its read-only pair still matches the original source.
It does not call `resume`, commit startup policy, publish files, advance ACK, register jobs or release A's account drain.
The outer maintenance owner must then join cleanup, close all pair/store loans and restore or adopt the exact existing AuthorityA.
It verifies readiness and applicable unchanged floors before releasing A's account drain; shared machine admission remains held through restoration. Registration alone is insufficient.
Transport/gateway stay registered. Target B stays unactivated; restoring A cannot advance B's completion or activation floors.
On reboot, an already-running exact A is verified and adopted without a second stop. No retained fence blocks A's journal startup.
A later normal resume is a separate explicitly authorized invocation with fresh state and a newly issued first-writing-use capability.
The original writing receipt, callbacks and expected revision remain invalid after replacement.

| Actual boundary | Required behavior |
| --- | --- |
| Refusal before mutation | Keep the original writing row and pair unchanged; return the actual cause |
| Exception before commit | Roll back the machine transaction; close the scope; do not retry the action body |
| Commit attempted, result unknown | Retire/close the affected store using the existing uncertainty rules; report uncertainty, not success or rollback |
| Fresh reopen sees exact new prepared marker | Observe that state without replacing it again or generating another revision |
| Fresh reopen still sees old writing marker | Only a new explicit owner action may repeat the eligibility checks; no automatic reset loop |
| Fresh reopen sees changed or foreign state | Refuse stale/changed scope; no repair or overwrite |

Operation outcome and service restoration are separate durable results. A committed replacement plus restart failure remains committed plus restart failure.
Setup startup/interruption recovery only reads protected state and restores service availability; it never calls P05 or normal resume again.
An uncertain B result can remain blocked while A is restored, if A and shared state are independently proved safe.
Repeated failure is visible through authenticated Setup status and the explicit restoration-only owner action.
If safe restoration cannot be proved, show `repairRequired` and the reviewed attended repair route; no force flag or silent outage.
Missing recovery/status/attended exit prevents enabling the window at all.

An old request against an already replaced marker refuses as stale. It does not create another marker.
Normal `resume` on the original unresolved writing state remains unavailable, including after restart.
Normal `resume` on a genuinely committed writing state retains its existing receipt-based reconciliation.
No test or recovery path may relabel an uncertain replacement as a known committed one.

## Focused cuts

Every changed production line counts, including helpers, guards, adapters and deletions. The hard cap is 200 per cut.
Measure the complete responsibility before tests. Replan if it does not fit; never publish a permissive intermediate branch.
The paths below are proposed new files under `macos/core/Sources/RemozioCore` unless an existing owner is named.

| Cut | Responsibility | Estimate | Required proof |
| --- | --- | ---: | --- |
| P05a | Replacement value and exact snapshot comparator; intent/snapshot files or narrow new replacement file | 80–160 | Writing only, fresh ID/revision, exact source/operands, prepared result; ordinary transition rules unchanged |
| P05b | Scoped machine CAS writer; `PreparationIntentStore` and private authorization adapter | 130–195 | One atomic marker delta; old bytes/revision match; every unrelated row and table exact; no journal permit |
| P05c | Borrowed replacement frames and expiry; dedicated P05 frame adapter reusing existing lifetime machinery | 90–175 | No public callback queries, actual transaction frames, poisoned/expired/foreign-thread refusal and closed handles |
| P05d | Owner orchestration and read-only pair loan; new owner file and narrow typed reader adapter | 120–195 | Fresh exact pair held through mutation; journal/startup writer calls zero; all failures close without body retry |
| P05e | Native custody facade inside the actual per-account maintenance owner; reuse verified caller/current authority scopes | 110–190 | Real peer/rights and stopped A custody; ordinary shared lease intact; no arbitrary IDs/paths or synthetic native token |
| P05f | Explicit attended reachability and separate operation/restoration display on the approved Setup boundary | 100–190 | Clear intent, decline/expiry, stale/lost reply and recovery; no automatic P05 call from resume |

P05a–d may follow M03 as library work. P05e/P05f wait for M05–M07 and M15, then the qualified maintenance composition and must reconcile with actual C01–C06 code.
Reuse its identity/rights owners and maintenance recovery endpoint; do not build a second resolver or restoration action.
If the caller scope is not yet available, stop at the library cuts; do not add a temporary unauthenticated native endpoint.
P05c must remain specific to replacement. Do not add a general changed-source switch to P04's policy-only context.
P05f requires a separately reviewed explicit owner confirmation; ordinary resume and application startup never trigger P05.

## Test matrix

Use actual protected temporary stores and existing retained fixtures. A fake count, cached pair or decoded JSON alone is not the predicate.
Share expensive setup only where each test still owns its state and proves its own refusal boundary.

| Case | Required observation |
| --- | --- |
| Eligible unresolved writing | Exact old pair held; one new prepared marker with fresh identity/revision; no other mutation |
| Zero or multiple retained operations | Concrete protected-state predicate refuses before marker SQL |
| Missing/prepared/recorded marker | P05 refuses; it never turns an ordinary state into a reset candidate |
| Wrong account, owner, directory, initialization, candidate or retained choice | Refusal with original row/pair unchanged |
| Changed policy bytes or global revision | Refusal even if the release identity or policy contents otherwise look equivalent |
| Changed role token or checkpoint generation/digest/head/epoch | Refusal; full source equality is mandatory |
| Startup already committed, including no-op policy | P05 refuses; existing normal reconciliation remains correct |
| Busy target pair, changed file identity or expired loan | Refusal before replacement; no retry loop or weaker lock |
| Stale marker revision/bytes, concurrent invocation or request replay | CAS changes zero rows and refuses; at most one replacement wins |
| Before/in/after mutation callback failures | Exact rollback or retired uncertain store according to actual commit boundary |
| Commit acknowledgement lost | Fresh actual reopen distinguishes old/new/foreign state; no second reset on observation |
| Read callback escapes, re-enters, changes thread or process | Invalidated/poisoned capability; no extra machine or journal query |
| Old writing-use receipt after reset | It cannot write the journal or validate the new marker |
| Committed marker, failed A restart | Marker remains exact new prepared; visible restoration failure; recovery never replaces or resumes it |
| Setup restart or reboot | Read old/new/foreign state without body replay; adopt healthy A after readiness/floors; no second stop |
| Unknown B, independently safe A | A restored and its account admission reopened; B remains blocked with its actual unknown outcome |
| Foreign/expired native scope, missing A drain or machine update race | Refuse; A gate stays closed through restoration; other account admission remains open |
| Ordinary resume regression | Unresolved old writing still unavailable; committed result still reconciles; later prepared resume uses fresh authorization |
| Durable conservation | Journal/checkpoint bytes and logical pair unchanged; all unrelated machine records, phases, schema and catalog exact |

Keep counters proving zero journal commit/startup-open calls and zero file publication/job registration calls in the P05 body.
Test outer window restoration separately: exact A registration/readiness can be required, and must not be counted as a P05 journal mutation.
Check full row bytes after reopen, not only the reported result. Retain old and new hashes without logging sensitive payloads.
Fault injection uses disposable fixtures only. Do not kill a real authority, reset a product marker or edit SQLite by hand to manufacture evidence.

## Qualification and attended result

Build and run every added/changed class on the exact source through ATC after Toni grants the native slot.
Retain commands, source hashes, environment, per-case outcomes and actual consumed terminals. Failed runs remain failed.
Keep the existing 120-second command limit and 1800-second allocation unless Toni explicitly replans the cut.
Source/owned controls do not prove installed Root identity, real administrator authorization, service contention or physical durability.
The attended P05 session uses a separately selected qualified artifact after the maintenance owner and required #725 installed gates pass.
Prepare exact status, restoration-only and repair procedures before stopping A. Crash/reboot recovery gates remain unexecuted until attended evidence exists.
It must observe an actual eligible writing marker; never create one on production just to exercise this action.

Record the old unresolved state, full fresh pair equality, explicit intent, actual replacement outcome and unchanged journal.
Record final marker observation separately from A stop/exit, restoration/adoption, readiness, floors, A admission reopening, other account continuity and measured A outage.
Record decline, busy and stale refusals separately. No age-based expiry is assumed beyond the approved caller plan's open product decision.
The [conflicting published-file case](https://github.com/rock3r/remozio/issues/722#issuecomment-6857268710) remains outside P05.
Do not overwrite or delete a mismatching runtime file, regenerate material, repair another account or change the signed drain/admission contracts.
Hardware, provider semantics, installed activation and the full interactive handoff remain separate obligations.
The full Remozio objective remains incomplete.
