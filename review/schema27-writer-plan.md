# Schema 27 writer plan

This is a source-only plan for Toni1429,1434,1436 and1438, with reviewer1437. No product code, build, parse or test ran for this plan.
Inspected checkout: eeb9f346e3f75e15495b4818620946e25adc5626, tree fb2b91cc37ee4743a26c79686ad1f5ebee003b73.
Donor: 669ec2e99edb89d6f10e8b964b60c7405f5a9415. The Mac belongs to Toni after his acknowledgment1429.
The F pre-gate passed on this checkout. It does not qualify Toni's rebased candidate c2e28b77.

Toni1436 puts policy codec alignment first. Slice55 stays unchanged during its gate.
The current policy record emits and accepts v2. The prospective promotion guard still requires policy v1 from the donor.
The F positive fixture declares a policy-v1 writer. Its passing guard test does not prove real producer compatibility.
Change that guard in the first writer slice. Do not publish a fictitious v1 producer or change the record codec.

## Order and size

Paths below use `macos/core/Sources/RemozioCore/` unless a full repository path appears.
A line budget counts additions plus deletions across all production paths. Tests have a separate footprint.
Every slice must stay below400 changed production lines, including imports, helpers, validators and declaration changes.
The ranges below are estimates. They are not implemented diff counts. Measure the complete diff before adding test fixtures.
If a complete responsibility exceeds its cap, revise this plan before writing it. Do not omit guards to fit.
Merge each qualified slice before the next. Reconcile actual main and retain the exact review and gate receipts.
Only Toni assigns native ownership and publication work. This plan grants neither.

| Slice | Purpose | Production files | Estimate; stop cap |
| --- | --- | --- | --- |
| G0 | Align the producer guard with policy codec v2 | `MachineUpdateRetainedSetupPromotionStorage.swift` | 50–90;140 |
| G1 | Read typed v6 compatibility through a checked stable entry | `PreparationIntentStore.swift`, `RuntimeReleaseCompatibilitySnapshot.swift`, new `RuntimeActivationCompatibilityProjection.swift` | 240–340;380 |
| G2 | Declare the retained file codecs honestly | `scripts/generate-macos-release-manifest.py`; check the existing Swift requirement tables | 80–140;200 |
| G3 | Add read-only pair access and synchronous verification loans | new `MachineUpdateRetainedSetupPromotionNativeSupport.swift` | 90–150;220 |
| G4 | Authenticate native metadata, material, custody and admission | new `MachineUpdateRetainedSetupPromotionNativeContext.swift` | 180–270;340 |
| G5 | Pin the actual pair and validate the original files | new `MachineUpdateRetainedSetupPromotionSourceValidation.swift`; narrow wrappers in the existing activation snapshot if needed | 100–170;240 |
| G6 | Retain and change one promotion row under a private writer gate | `PreparationIntentStore.swift`, `MachineUpdateRetainedSetupPromotionStorage.swift`; generator changes only when the producer prerequisites hold | 250–340;380 |
| G7 | Replace and re-read the six selected files | `RuntimeRetainedSetupCompletionPublication.swift`, new `MachineUpdateRetainedSetupPromotionFiles.swift` | 110–180;240 |
| G8 | Coordinate retained phases, closed connections and file publication | new `MachineUpdateRetainedSetupPromotionOwner.swift` | 250–330;380 |
| G9 | Bind the native selector and entry to the checked owner | new `MachineUpdateRetainedSetupPromotionNative.swift`, new `MachineUpdateRetainedSetupPromotionProposalNative.swift` | 180–280;360 |

G0–G5 add no file or metadata writes. G6 is the first SQL writer. G7 is the first file replacement code.
G8 joins these operations. G9 supplies their native dependencies. No new automatic Setup dispatch belongs in these slices.

## G0: producer contract

Use the three records' `currentFormatVersion` constants for their respective requirements.
The policy version is2; completion and promotion are1. Preserve the complete role and format union from F.
Do not leave a literal version1 for any of the three record kinds.
Preserve installation readers24–27, writers25–27, the completed-host requirements, and the Setup-only promotion writer.
Do not weaken the guard to the reader subset. Do not alter schema numbers, codecs, canonical bytes or migration declarations.

Tests: extend `MachineUpdateReplacementTests.testRetainedPromotionProducerRequirementsRemainSeparateAndComplete`.
Its valid control must use policy v2. Reject a candidate with only v1, a missing v2 reader, or each missing required writer role.
Test every remaining format and role. Fail if a codec constant changes without its producer guard.
Also compare actual canonical record versions and generated declarations; a shared-constant assertion alone is insufficient.
Ordinary readers must still accept an adequate reader-only candidate.

Unproven: producer availability for schemas25/26 and the native writer. No manifest writer claim is enabled by this guard correction.

## G1: typed compatibility

There are two ordinary decode sites: store loading and `RuntimeReleaseCompatibilitySnapshot.describe`.
Fix them as one complete read responsibility. A store-only change would still fail when `describe` decodes the retained bytes.

Add a private checked projection that distinguishes ordinary plans from `RuntimeRetainedSetupActivationPlan`.
Use the bounded canonical codec for each branch. Keep material, account, machine, digest, registration and final-row checks.
Carry the exact activation bytes, historical reference, host properties and phone feature versions into compatibility requirements.
For v6, include the retained-release requirements and the actual typed host requirements. Preserve existing ordinary requirements.
Never put a v6 plan into `RuntimeActivationState`, and never widen `RuntimeActivationPlan.decode`.

Keep the current public ordinary guard: schema<=22. Preserve the separate finishing-schema23 path.
Add an explicit stable entry bound to the checked retained snapshot and signed candidate.
Capture and recapture its private stable frame inside one read transaction. Do not call public transaction wrappers from it.
Do not route stable metadata through the ordinary finishing projection or use a Boolean to skip its guard.
Keep `lease.sharedImportCompatibilitySnapshot` inside the transaction, with the actual installation identity.

Tests: `RuntimeReleaseCompatibilityTests`, the v6 SQL cases in `MachineUpdateReplacementTests`, and a checked stable-entry fixture.
Cover ordinary v1–v5, typed v6, a mixed account set, malformed or unknown versions, wrong columns, wrong ownership and registration.
Compare the full declared requirement sets, including phone features and host versions. Reject changed external import evidence.
Retain the ordinary v6 decoder refusal and schema23/24 ordinary-entry refusals as regression controls.

Unproven: signed release inspection, actual native enrollment and registration. A typed projection grants no startup or migration authority.

## G2: release declarations

Update the existing generator, not the donor's entire2635-line JSON contract.
Add `runtime.retained-setup-release` v1 and consumer-host v3 for authority, transport, gateway and Setup.
The three consumers receive readers. Setup receives the writers that the checked file codecs implement.
Include the typed activation v6 requirement for authority and Setup, with its writer limited to Setup.
Include the completed-host v4 and completion binding/archive/configuration/publication requirements used by F.
Derive the complete matrix from the current Swift requirement tables. Do not copy every donor declaration.
Keep schema28 and later writers disabled. Do not add deployment or service actions.

Tests: `tests/test_macos_release_manifest.py`.
Check every component, reader and writer set, the absence of unrelated writers, deterministic ordering and duplicate rejection.
Update current manifest expectations. Preserve historical manifest bytes and legacy golden controls.
Test the missing-version and wrong-role cases against the current requirements, including policy v2 from G0.

Unproven: a signed product artifact and a callable native producer.
Schema25/26 and intent-row writer declarations remain gated on their actual producers. A synthetic candidate is not that proof.

## G3: read-only native support

The donor's ActivationNative, PolicyNative and scoped-verification types are absent in this checkout.
Do not import their complete activation and policy owners to obtain small helpers.
Port only the checked account paths, read-only pair opener, and synchronous process/thread-bound verification loan.
Use fixed account-derived paths. Require separate journal and continuity leases, their identity exclusion, SQLite preflight and current limits.
The opener must enforce read-only access. It must close both stores on normal return and every error.
Expired, reentrant, cross-thread or cross-process callbacks must fail before use.

Tests: a new `MachineUpdateRetainedSetupPromotionNativeSupportTests` class with owned journal and continuity fixtures.
Check wrong paths, aliased directories, mutable storage, open failures, body failures, expired callbacks and a retained callback after return.
Check that the opener never creates missing storage and never requests mutable journal access.

Unproven: native Root placement, protected production stores and the later writer.

## G4: native custody context

Port the donor's read-only scope and material checks, adapted to current typed snapshots.
Use `runtime.setup`, typed retained plans and actual current constructor declarations. Do not cast through an ordinary plan.
The context must authenticate the exact policy intent, preparation, initialization, runtime state and service reservations.
It must bind the historical inventory, stable seal, installed epoch, candidate, admission and expected current schema.
Use fresh local account and service identity checks. Check both the app and Setup code identities against the current signed release.
Pin installed placement identity. Verify the Setup executable path, self code policy and current service activity.
Read and re-read the runtime material under protected custody. Close every acquired directory and admission lease on failure.
The synchronous context expires on return. It exposes no registration, policy-write or startup operation.

The current promotion row may advance only through a checked writer frame later. The completion and startup operands remain fixed.
Avoid the donor's stale schema-equality assumption across26→27: authenticate each approved next frame and its protected-row anchor.
Do not weaken the stable reader's inventory==installed-epoch check to make a fixture pass.

Tests: a new `MachineUpdateRetainedSetupPromotionNativeContextTests` class.
Ordinary identity must fail before path access. Inject changed intent, initialization, owner, reservations, code identity, placement or material.
Verify rejection both before and after each external read. Check cleanup and context expiry on every failure stage.

Unproven: real Root execution, signatures from a built artifact, service activity and protected installed placement.
Owned fixtures and injected identity operations test ordering only.

## G5: actual pair and source files

Capture the full `MachineUpdatePolicyBoundary` and its classification kind once for each validation scope.
Re-read and compare the actual boundary, including global and role revisions and checkpoint, before and after every file read.
Compare classification kinds, not recovered proposal values. Those values have fresh random revisions.
A schema27 promotion requires `completionRecorded`. Startup, receipt-pending and unknown pair states cannot authorize publication.
A writing-phase validator must reject a changed boundary or classification even when each independent read is valid.

Reuse E's complete runtime validation and the checked publication source factory.
Add the original command-host bytes and the two checked job manifests from the donor's activation-artifact list.
Pin the source clients and runtime material, then verify all source artifacts again before proposing new operands.
Use the read-only pair helper from G3. Close it before any operation that requires the pair to be closed.
This responsibility needs no health listener, native service startup, challenge or schema28 readiness type.

Tests: a new `MachineUpdateRetainedSetupPromotionSourceValidationTests` class, plus the E paired-read regressions.
Change the global revision, one role revision, checkpoint, classification or completion row between reads.
Prove that regenerated proposal revisions do not cause false changes when the actual boundary and classification stay fixed.
Reject an altered host, job manifest, client or material after a successful first read.

Unproven: native health and actual running jobs. File validation is not live service verification.

## G6: schema27 SQL writer

Port the complete donor authorization, retain/change operations and protected-row digest as one unit.
Add only a private promotion authorization to `transaction`. Ordinary writes to stable schemas must remain closed. Preserve their current error classification.
Bind the authorization to this store, process, thread, synchronous admission scope, original frame and expected next frame.
Require one active authorization. Capture before the body, after mutation and before commit.
Use the borrowed actual writer frame in callbacks. Never start a nested public snapshot transaction.

Run the complete G0 producer check and the26→27 migration check before any BEGIN that can poison this store.
Keep `incompatibleStore` as the declaration error. Its location outside the transaction avoids the quarantine path.
The candidate is immutable for the operation. Do not substitute a reader-only declaration check inside the transaction.

Allow schema26→27 only when retaining the prepared intent. Keep the exact existing table declaration and bounded record limit.
An existing schema27 or28 may accept only the allowed operation. Do not write schema28 readiness data or add an unrelated migration.
Use exact account/id/revision predicates and require one changed row. Keep capacity, duplicate and canonical-byte checks.
Scope the SQLite size allowance around both INSERT and UPDATE. Preserve the normal limit for unrelated operations.
Use the existing retained-record helper and its padding. Do not widen the connection limit permanently.
Retain the exact embedded completion receipt. Idempotent return requires the actual intent and full source to match.

The transition comparison excludes `currentRowsDigest`. Therefore the authorization must pin every other protected row.
Exclude only this account's promotion row. Hash every other table and every other promotion row under the donor's domain tags.
Pin the schema catalog too, apart from the exact new promotion table and allowed user_version transition.
Recapture the complete strict frame after each authorized row change. Do not relax ordinary snapshot equality.
Before recording filesPublished, really re-read all selected files with the existing F Observation and G4/G5 fences while admission stays closed.
G6 accepts only that read-only observation. It has no dependency on G7 replacement operations.
G7 later adapts its write-capable operations to the unchanged read-only observation for the SQL marker.
A post-commit uncertainty poisons this invocation. It does not grant a retry; recovery starts from fresh actual reads.

Tests: a new `MachineUpdateRetainedSetupPromotionWriterTests` class using owned SQLite and the real admission mechanism.
Cover migration, exact receipts, stale revisions, repeated exact retention, foreign intents, row capacity and a reopened read.
Exercise both insertion and update with a valid canonical record above the ordinary278528-byte allowance.
Check the restored limit and rollback behavior. Do not use malformed padding as a positive large-record control.
Inject a change in each protected table and another account's promotion row at every callback stage.
Check that missing producer declarations leave the store usable and schema/table/rows unchanged.
Inject rollback failures before and after mutation. Verify schema26 and table absence after a pre-commit failure.
Reject filesPublished without actual selected bytes, with mixed files, or after admission changes.
Keep intentional corrupt-record reads last. Resolve the current store after every fixture reopen.

Unproven: real schema25/26 producers and a native enrolled/registered input. Do not fabricate either to obtain a positive product result.
If those prerequisites are absent, retain source/unit evidence and leave the writer unreachable from product dispatch.

## G7: file replacement

Add a write-capable operation interface beside the existing read-only Observation. Keep Observation unchanged.
Port the donor's complete source/mixed/selected handling and read-back after each replacement.
Use fixed runtime, service and client directories. Keep ownership, permissions, links, identity checks and native Root refusal.
The native file access comes from the checked context, not a caller-supplied success marker.
Every replacement requires a durable publishing intent and closed admission, checked through the owning scope.
An unknown exchange result stops the call. A later invocation must read actual bytes before deciding whether another exchange is needed.
Never replace a file already at the selected bytes. Reject unknown bytes without repairing them.

Tests: a new `MachineUpdateRetainedSetupPromotionFileTests` class using owned protected directories.
Cover all six artifacts, a late unsafe file, symlink/hardlink and permission substitution, expired fences and admission loss.
Inject uncertainty after exchange. Reopen and observe selected bytes without repeating that exchange.
Prove exact read-back and refusal of mixed or changed files before the final marker.

Unproven: production paths and Root file ownership. The owned-directory tests grant no installed access.

## G8: publication owner

Port the196-line donor owner with its complete invocation and step lifetime checks.
Retain prepared operands, then retain publishing, then publish files, then retain filesPublished.
A returned machine connection must be closed. A provider cannot invoke its body twice, retain it or report a different snapshot.
During storage callbacks use the writer's actual borrowed frame. External validation must not query that same transaction again.
For file operations, open a fresh checked machine view and close it before returning from the fence.
Carry G5's actual pair token and G4's custody context through every observation and write.
Revalidate all six selected files for an existing filesPublished marker as well as a new one.
Keep cancellation, stage failures and unknown results fail-closed. Nothing here reopens ordinary admission.

Tests: a new `MachineUpdateRetainedSetupPromotionOwnerTests` class.
Cover every phase, body reentry, unclosed connections, an escaped fence, a changed pair and metadata between file reads.
Inject each storage and publication stage failure. Resume only with a fresh scoped observation and the exact recorded operands.
Reject unknown files after an already recorded marker. Assert no ordinary startup or admission reopening callback exists.

Unproven: native placement, real caller authentication and fresh health. These await G9 and later attended evidence.

## G9: native selector and entry

Adapt the donor's96-line entry and86-line proposal selector to G3–G8.
Inspect every constructor, optional chain and helper signature against this checkout before writing calls.
Authenticate the actual intent row and all setup metadata through the stable reader in every verifyCurrent fence.
Use the borrowed writer frame only during its storage callback. Use a fresh closed read outside that callback.
Pin actual pair boundaries and classification. Revalidate custody and closed admission around each real file read and replacement.
If an intent already exists, use its exact publication bytes. Never derive a replacement plan from partially published source files.
For a new intent, validate the original material, clients, command host and job files through G5 before constructing the publication.
Do not import the donor's immutable-archive cache as a correctness dependency; fresh uncached reads can keep the same fences.

Tests: ordinary-identity refusal before any path or callback, read-only pair cleanup, changed metadata and changed protected files.
Use the owner and file tests together for the full sequence with owned fixtures. Test a reopened partial publication and an unchanged completed marker.
Retain the exact source, stage outcomes and unsupported native boundaries in the later handoff.

Unproven: authenticated installed Setup dispatch, actual Root paths, service state and end-to-end recovery on an installed machine.
No service, signing secret, physical device or attended provider test is authorized by this plan.

## Donor dependency decisions

| Donor item | Measured selected source | Required for writer27? | Decision |
| --- | ---: | --- | --- |
| Promotion authorization, writer and protected digest |133+24 lines | Yes | Port together in G6; add current-source guards and schema pinning. |
| Promotion owner |196 lines | Yes | Adapt the complete owner in G8. |
| Publication Operations and resume |5+13 lines | Yes | Add in G7; keep the existing read-only interface. |
| Protected promotion file adapter |66 lines | Yes | Adapt in G7, including all custody checks. |
| Promotion native entry and recorded-pair helper |64+30 lines | Yes | Split the read-only pair into G3/G5; entry in G9. |
| Promotion proposal selector |86 lines | Yes | G9; adapt source validation through G5. |
| ActivationNative scope and material checks |111+31 lines | Yes, selected checks only | G4. Keep the full validation; adapt typed fields and metadata transitions. |
| Other ActivationNative methods |79 lines outside those ranges | No direct dependency | Leave activation registration/pair sequencing outside. The promotion owner handles its own connection lifetime. |
| PolicyNative paths and read-only storage opener |11+21 lines | Yes | G3. No policy mutation or policy owner. |
| Remaining PolicyNative code |253 lines outside those ranges | No | Leave its policy writer, source-phase pair machinery and native resume outside. |
| Scoped verification loan |20 lines plus wrapper/imports | Yes | G3. Do not import the226-line stable publication module. |
| RootStartup source artifact list |6 lines | Yes | G5 checks the command host and two job files directly. |
| CompletionStartup/RootStartup health wrappers |Not proposed for import | No | G5 supplies the file and pair checks. Health listeners, startup selection and challenges remain separate. |
| Donor retained-format JSON |2635 lines | No wholesale dependency | Use current generator and current requirements in G2. |

The stored source excerpts and hashes are in `source-inspection.json` and `inspection-excerpts/`.
Selected donor line counts are physical source lines. They are not the sum of future additions and deletions.

## Requirement coverage

| Toni1429 requirement | Slices |
| --- | --- |
|1. Typed v6 compatibility row |G1; declaration matrix in G2 |
|2. Every other protected row stays fixed |G6; strict frame and pair checks in G4/G5/G8 |
|3. Retained release v1 and consumer host v3 declarations with Python tests |G2; completed-host union and codec alignment in G0 |
|4. Native verifyCurrent checks actual intent, setup metadata, custody and admission |G3/G4/G5/G9; G8 supplies fresh reads or the actual borrowed frame |
|5. Pin actual pair and classification across validation |G5; enforced throughout G8/G9 |
|6. Producer declarations checked before transaction |G0/G2/G6; no fictitious policy-v1 producer |
|7. Re-read published files under closed admission |G7/G8/G9 and the G6 final marker check |

## Qualification and prerequisites

Each implemented slice needs source review and the repository's source-bound local gate before publication.
Only the assigned native owner may compile or test it. A later slice cannot reuse this F pre-gate by relabeling its source.
Use existing fixtures where they preserve independent assertions. Build an actually valid control before each rejection.
Name new test methods only when implemented; this plan claims no new test count, type-check or runtime result.
The current known baseline is5718 Core cases on eeb9f346. Derive every later count from its actual source.

Schemas25/26 need their actual producers and authenticated enrolled/registered inputs before a native schema27 success can be claimed.
The stable reader still requires inventory==installed epoch. This plan does not weaken that invariant to synthesize an input.
If valid registration needs a separate reader/producer contract, schedule and qualify it explicitly before G6/G9 become reachable.
The real release must truthfully satisfy the complete producer union. Missing prerequisites must fail outside the SQL transaction.
Owned pairs, injected callbacks and structural probes do not prove native custody, signatures, service health or installed startup.
Schema28 readiness, final health, ordinary startup, job registration, admission reopening and unattended dispatch remain outside this writer plan.
All original failed runs and historical receipts remain unchanged. No source was applied and no native operation ran for this plan.
