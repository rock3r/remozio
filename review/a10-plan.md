# A10: retained initial runtime sequence

## Status and source

This plan describes the inspected source. Implementation and runtime validation have not started.
Toni requested this plan in message 2305. The proposed review branch contains only this document.
Toni owns publication of the review branch, wider tests, PR readiness and merge order.
The inspected source is `be602bc838a30f967f8bfe151a89323ac7afb6f7`.
Toni reported publishing A09d2 for review as `review/bepi-A09d2-20261114`.
Its wider qualification and merge remain Toni's responsibility.
A09d1 is merged in `4ed1cc9cb4635d98ff70eeb0b2e1f9edbe243198`.
Implementation starts only after A09d2 actually merges and the implementation base is reconciled with main.
Every implementation cut requires its own source-bound gate, qualified PR and preceding merge.

A10 joins material, recorded policy, initial files, the publication marker and the import acknowledgement.
It adds no authenticated Setup dispatch, activation plan, job registration, enrollment or ordinary-ready result.
A11 supplies native providers and the A09 facades deferred from the earlier plan.
The authenticated Setup caller remains in the later caller slices.

## Current APIs and missing closure

- `MachineUpdateRetainedSetupMaterialSnapshot` accepts unpublished material, including a missing reference.
  `requireRetained` already compares the exact material transition. Reuse it.
- `MachineUpdateRetainedSetupPolicySnapshot` requires an activation snapshot with a material reference.
  `MachineUpdateStableRuntimeActivationSnapshot` cannot construct that snapshot before material exists.
  The sequence therefore needs an explicit typed entry for both states. Do not fabricate a material reference or publication bit.
- `MachineUpdateRetainedSetupPolicyOwner.resume` is the only startup-policy owner.
  It closes the machine connection before the paired journal write.
  Unresolved writing with the unchanged source remains unavailable. Preserve its existing recovery and one-use receipt rules.
- A09c2 publishes exactly eight files without changing metadata. A09d2 verifies those files and changes only the publication marker.
  Its published recovery performs no UPDATE and no repair. Reuse that recovery for an already-published runtime.
- `MachineUpdateRetainedSetupRuntimeInputs` captures the actual journal, import record and relay evidence.
  Its `requirePublicationAcknowledgement` already compares retained to runtimePublished inputs.
  It is a value comparison, not a writer or a current-source proof.
- `PreparationIntentStore.advanceStableRuntimeImport` explicitly requires `.currentRelease`.
  `MachineUpdateStableRuntimePreparationSnapshot.requireChange` and `requirePublished` have the same ordinary-only boundary.
  Do not weaken those guards or use them for retained transitions.
- The old two-file sequence design also assumes native facades that A11 has not supplied.
  Its free import and tunable parameters are incompatible with the current actual-input selection.
  Port the responsibilities through current APIs. Do not copy its wrappers or recursive verification graph.

## Proposed cuts

Each cut has a complete responsibility and a cap of 200 changed production lines, including every helper, guard and deletion.
The estimates below are provisional. Measure the full diff before writing tests. Replan before code if a complete cut exceeds its cap.
The original two-file estimate does not include the missing retained acknowledgement closure.

| Cut | Complete responsibility | Proposed production paths | Estimate |
| --- | --- | --- | --- |
| A10a | Typed actual entry and exact stage comparisons | new initial-runtime entry model; narrow read-only getter in `PreparationIntentStore.swift` | 120–185 |
| A10b | Retained import acknowledgement storage ownership | `PreparationIntentStore.swift`; only a required typed result or guard helper | 140–195 |
| A10c | Owned acknowledgement with actual material, pair and file checks | new retained import-acknowledgement owner | 115–185 |
| A10d | Initial publication and completion sequence | new `MachineUpdateRetainedSetupInitialRuntime.swift` | 100–170 |
| A10e | Material → policy → publication → acknowledgement sequence | new `MachineUpdateRetainedSetupRuntimeSequence.swift` | 150–195 |

No cut adds a temporary stub or a reference to a future concrete native context.
A10a's comparisons grant no write authority. A10b privately binds authority to actual storage and loans.
A10c supplies the file and pair obligation that A10b cannot infer from a Boolean alone.
Native factories, native custody and production callers stay in A11 and the later caller work.

## A10a: typed entry and transitions

Capture one actual entry inside a read transaction, using the existing private loaders.
The entry distinguishes unpublished material from the policy/publication snapshot available after the reference exists.
Read the activation state and actual policy row in the same entry. Refuse contradictory rows, installed completion, plans, registration or enrolled accounts.
A missing reference is valid only for the material entry. Published state requires the actual reference and recorded policy.
Keep account, owner, initialization, preparation, reservations, plan, seal, inventory, candidate and admission exact.
Use operation-specific comparisons. Do not add a general guard-bypass flag.

Reuse the existing retained material and publication comparisons.
Policy changes must stay within P04's actual source and phase rules, including its sole 24→25 migration.
Do not add a prepared→recorded shortcut or reinterpret an unresolved writing marker.
The outer sequence checks the actual P04 result and fresh source without performing another policy write.

For import acknowledgement, compare the exact published runtime and recorded policy.
Only the proven external import record may advance. Its recipe, operation, scope, proposal digest and relay evidence remain exact.
The aggregate external-source digest can change only when A10b proves every machine row and the catalog unchanged.
A10a alone must not authorize that digest change or mint native authority.

## A10b and A10c: retained acknowledgement

Add an explicit retained-only storage entry. Preserve the ordinary acknowledgement API and its refusal behavior.
Require recorded policy, a published runtime, the exact material reference, actual admission and accepted file custody.
Check the actual supported codecs and candidate requirements before mutation. Add no schema or manifest writer declaration.
Open the actual import journal without creating storage. Pin its real lease, directory, scope and relay evidence.
Absence and an empty journal are distinct actual observations. Neither creates an import or an acknowledgement.

Hold a private process/thread/store authorization across the two machine reads and the journal advance.
Mutually exclude other writers across that interval. An external-journal commit must not permit a reentrant machine writer.
Hash all machine rows and the catalog before and after the advance. Exclude no account or runtime row.
Lend actual pre/post machine frames and actual input evidence. Callback verifiers must not open a public machine transaction.
Call the existing journal phase advance once, from the exact retained record to runtimePublished.
Keep its conditional revision, operation, canonical record and commit semantics.
No machine SQL row changes during acknowledgement.

A10c verifies the actual pair, material and eight derived files before and after that advance.
Expected bytes come from the actual imported choices and recorded startup policy, never from tunables found in published files.
Use the existing pure bundle and artifact validators. Do not reopen the held journal through another observer.
If shared observation code needs extraction, include its full diff and all existing guards in the responsible cut.
A read-only frame or a caller-supplied Boolean is not acknowledgement authority.

Already-runtimePublished inputs take a read-only recovery path after the same file and pair checks.
Any missing or conflicting file refuses without repair or another acknowledgement.
An error ends the invocation. An uncertain commit closes the affected handles and requires fresh state resolution.
A new invocation may observe the exact committed phase. It must not replay the old advance or reuse an advanced callback frame.

## A10d: initial runtime owner

Keep C1's unpublished selection loan inside C2. Expire it before D2 can change the marker.
For unpublished metadata, publish through C2, then complete through D2.
Verify the actual returned state and a fresh capture after each owning operation closes its connection.
Use the exact A09 publication comparison for false→true. Reject every other change.
For published metadata, skip C1 and C2. Use D2's checked no-op recovery and verify an identical result.
No missing-file repair belongs to this branch, including recovery after a lost acknowledgement.
A failed operation propagates. There is no automatic write retry in the same invocation.

## A10e: runtime sequence

Refuse missing custody before invoking a provider. Require the exact retained account and supported source at entry.
Use the actual import, presence and relay inputs. Callers cannot replace them with optional choices.
Keep import credentials out of logs and serialized stage receipts.
Prepare or verify material through A08. Existing references must retain exact material; do not regenerate identities.
Inspect an existing policy marker before material work that could alter its operands.
Delegate policy handling to P04. Writing may proceed only through P04's already-authorized actual-pair recovery.
A writing marker whose source pair is unchanged remains unavailable and causes no publication or acknowledgement.
After recorded policy, call A10d. Only its actual published result permits A10c acknowledgement.
Skip acknowledgement for actual absent or empty input storage. Recover an already-acknowledged exact import without another advance.
Compare fresh inputs between stages. Allow only A10b's exact acknowledgement transition.
Return an internal snapshot/input result. It grants no jobs, enrollment, readiness, consent or request authority.

Each provider closes its machine connection before returning.
A provider's borrowed writer frame is compared directly; it must not trigger another capture from the outer sequence.
Host and admission callbacks remain mandatory. A11 supplies their real native dependencies.
Do not let the word resume authorize policy replay, arbitrary recovery or a second commit attempt.

## Proposed read budgets

These are review targets, not measured implementation claims. Assert them in the owned tests before publication.
Count outer captures separately from the existing owners' internal validated reads.

| Scope | Outer capture bound | Callback rule |
| --- | --- | --- |
| A10d unpublished path | 3 actual policy captures: entry, after publication, after completion | 0 new captures from a verification loan |
| A10d published recovery | 2 actual policy captures: entry and final | 0 new captures from a verification loan |
| A10e full path | 6 entry/stage/final captures; at most 6 outer input captures |0 public machine or input captures inside writer callbacks |
| A10b acknowledgement | 2 actual input captures, before and after; keep their existing internal stability checks |Use actual borrowed frames, not nested public readers |
| A10c acknowledgement |At most 4 bounded artifact observations; at most 2 for an already-acknowledged no-op |Each observation: 2 pair, 2 material and 8 artifact reads |

C2 retains its 18 full checks and 42 C1 snapshot reads. D2 retains its 10/4 observations and two public snapshots.
Those internal counts are not hidden inside a promise that the whole sequence performs only two reads.
Cheap callback loans check lifetime, process, thread, re-entry and admission only.
Do not compose a full source verifier recursively around every file or borrowed value.

## Tests and qualification

- Entry: missing material, existing material, absent/prepared/writing/recorded policy, published state and unsupported contradictions.
- Transitions: exact allowed change, wrong account/owner/reference, changed source or pair, changed reservations and ordinary-entry refusal.
- Acknowledgement: one actual advance, no machine-row or catalog change, writer exclusion, changed inputs/relay, and closed or escaped loans.
- Recovery: absent/empty/already-acknowledged storage, missing files, changed material, lost commit acknowledgement, fresh reopen and no second advance.
- Initial owner: C2→D2 order, complete=0 with exact files, partial publication, conflicting bytes, and complete=1 without repair.
- Sequence: actual stage order, each failure boundary, provider rejection, stale returned state, import change and unresolved writing intervention.

Use fresh owned stores. Seed the eight derived files directly for most cases.
Keep one real C2 publication integration and one complete owned stage-order integration where required.
Injected providers prove ordering and refusal only. They are not native caller or provider compatibility evidence.
Retain exact per-case outcomes and timings, plus the read-count assertions.
A09d2 measured 43–58 test seconds for most cases. Its grouped three-failure case took 74.996 seconds.
The earlier 10–25 second donor estimate is not a valid capacity promise for these fixtures.
Measure each new case. Keep the existing local allocation of 1800 seconds and report exceptions to the target of 60 seconds.
Do not drop guards, hide grouped costs or silently increase command or CI budgets.
Toni owns native-slot assignment, wider tests, publication, readiness and merge order. CI weights remain with the reviewer.
Failed runs remain failed. Any admitted reuse must keep its source, actual terminal, exact inputs, environment and retained outputs.

## Work still outside A10

No native success, Root execution, installed placement, key custody, signing identity, service activation or physical-device result is claimed.
A11 still needs the native material/publication/acknowledgement providers and the deferred A09 facades.
The first real caller still needs the authenticated authority identity and the attended busy check from issue 725.
The separate issue 722 action remains attended. It does not write the journal or enable a general resume path.
Keep closed admission, the durable manifest and floors, the restart-health contract and the existing Setup UX unchanged.
Do not add ordinary-ready output before promotion and the remaining final gates.
Provider semantics, hardware checks and the exact attended handoff remain incomplete.
The full Remozio objective remains incomplete.
