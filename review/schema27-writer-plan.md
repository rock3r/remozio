# Schema 27 writer plan

This small plan delta records Toni1458/1460 and reviewer1459. It follows the approved dependency plan on G0 source d8972ae1.
The original170ebb44 and delta8b109091 plans stay immutable. G0 is compiled, with focused tests running separately. This plan change runs no build or test.
The original inspection used F source eeb9f346, tree fb2b91cc. Current G0 is d8972ae1, tree53cbf0c1.
Donor: 669ec2e99edb89d6f10e8b964b60c7405f5a9415. Toni returned the Mac to Bepi in1456 for G0 validation.
The F pre-gate remains separate. Toni reported his full F gate passed on b6ef0bb2/treec2e28b77 in1456.

Toni1436 put policy codec alignment first. F retained the old policy-v1 guard and positive fixture during its gate.
Those passing F tests did not prove compatibility with the actual policy-v2 producer.
G0 now uses the three current codec constants. Its fixture declares policy v2.
G0 has an accepted source review and a successful compile. The focused and full runs remain separate obligations.
Do not publish a fictitious v1 producer or change the record codec.

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

Unproven: producer availability for schemas25/26 and the native writer. No manifest writer claim is enabled by this guard correction. The Python test in G0 checks generated reader versions and empty intent writer sets only.
It does not require the real manifest to satisfy the prospective producer union, so G0 has no dependency on G2 or the producers.

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
A valid retained v6 row must not quarantine the machine. Test store usability after a successful stable read and after ordinary compatibility refusal.
Reject a known valid unsupported v6 row with a non-corruption error before the ordinary decoder can poison the transaction.
Malformed records retain their corruption behavior. Do not widen the ordinary codec.
The stable-entry callers are G4 native verifyCurrent, E03 activation verification and G9 selection, always with a checked retained snapshot and candidate.
These callers bind the activation snapshot and separately authenticate the exact policy/completion/promotion rows through the corresponding readers.

Unproven: signed release inspection, actual native enrollment and registration. A typed projection grants no startup or migration authority.

## G2: release declarations

Update the existing generator, not the donor's entire2635-line JSON contract. G2 declares readers only.
Add `runtime.retained-setup-release` v1 and consumer-host v3 for authority, transport, gateway and Setup.
All four roles receive only the corresponding readers in G2. Setup writers wait for the slice that makes each write reachable.
Include typed activation v6 readers for authority and Setup. Its Setup writer is declared with the reachable activation producer in C06.
Include the completed-host v4 and completion binding/archive/configuration/publication readers used by F.
C06 enables only the actual initial host3/retained-release/v6 producers. G9 enables completed-host4 and completion-publication producers.
G7/G8 add library code; they do not enable those declarations before the authenticated route exists.
Derive the complete matrix from the current Swift requirement tables. Do not copy every donor declaration.
Keep schema28 and later writers disabled. Do not add deployment or service actions.

Tests: `tests/test_macos_release_manifest.py`.
Check every component, reader and writer set, the absence of unrelated writers, deterministic ordering and duplicate rejection.
Update current manifest expectations. Preserve historical manifest bytes and legacy golden controls.
Test the missing-version and wrong-role cases against the current requirements, including policy v2 from G0.

Unproven: a signed product artifact and a callable native producer.
Schema25/26 and intent-row writer declarations remain gated on their actual producers. A synthetic candidate is not that proof.
The appendix assigns those producer slices and their authenticated route. It does not leave them as unscheduled prerequisites.

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
| Other ActivationNative methods |79 lines outside those ranges | Not in direct G4; required by prerequisites | E03 and R02 carry the actual activation/registration path. The G8 promotion owner retains its separate connection lifetime. |
| PolicyNative paths and read-only storage opener |11+21 lines | Yes | G3. No policy mutation or policy owner. |
| Remaining PolicyNative code |253 lines outside those ranges | Not in direct G3; required by P04 | P04 implements the native policy producer and mutable pair. Do not import it merely to obtain the read-only G3 opener. |
| Scoped verification loan |20 lines plus wrapper/imports | Yes | G3. G3 does not import the226-line stable publication module. E04 adapts its retained file responsibility later. |
| RootStartup source artifact list |6 lines | Yes | G5 checks the command host and two job files directly. |
| CompletionStartup/RootStartup health wrappers |57+242 donor lines | Required by native-input prerequisites | H03 and H13 supply the health/startup path. G5 alone still needs only file/pair validation. |
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
The appendix below assigns the source and native-input producer closure before G6/G9; its code is not applied by this plan.
The stable reader still requires inventory==installed epoch. This plan does not weaken that invariant to synthesize an input.
If valid registration needs a separate reader/producer contract, schedule and qualify it explicitly before G6/G9 become reachable.
The real release must truthfully satisfy the complete producer union. Missing prerequisites must fail outside the SQL transaction.
Owned pairs, injected callbacks and structural probes do not prove native custody, signatures, service health or installed startup.
Schema28 readiness, final health, ordinary startup, job registration, admission reopening and unattended dispatch remain outside this writer plan.
All original failed runs and historical receipts remain unchanged. No source was applied and no native operation ran for this plan.


# Appendix: complete producer route before schema27

Toni1440 asks for the missing distance to a usable writer. This appendix plans42 additional prerequisite slices.
Together with G0–G9, the current source-port plan contains52 focused slices from the F baseline.
G0 has a source-only commit. None of the42 prerequisite slices is implemented or qualified here.
This is a proposed slice count, not a count of features or historical files. Measured source and future changed-line estimates are separate.

The directed closure includes stable preparation, policy25, typed enrollment, native health registration and completion26.
Stopping at two SQL methods would leave no legitimate producer of the input that G6/G9 consume.
Schema28 readiness, final ordinary startup, providers and the wider audit/update/export/scheduling goal remain beyond this writer route.
Thus52 is not a full-project completion count.

## Required order

G0 → G1 → G2 → G3 → G4 → G5
→ A01–A08 → P01–P04 → A09–A11 → E01–E05
→ H01–H13 → R01–R02 → C00–C06 → G6 → G7 → G8 → G9.

The P block belongs between material creation and initial file publication. A09 needs recorded policy25 from P04.
The H block produces authenticated registration/completion proofs. R02 must never replace those proofs with a fixture flag.
C06 supplies the authenticated Setup route that creates a real recorded completion26 input.
The input code exists after these slices; actual native success still needs the separately allowed installed test.
C05/C06 must preserve the existing Setup UX. They add no visible state or changed ready result.
If correct integration requires a visible change, stop that part and obtain Seb's product decision through Toni.
G6/G9 may consume that input only after its actual source/registration/receipt checks succeed.
No writer calls code from a later slice. Before its owner exists, a helper is unreachable and its writer declaration stays disabled.

G3/G4/G5 add read-only promotion helpers, not the entire donor activation/policy owner hierarchy.
The P/E blocks introduce the actual stage-specific producer owners. They reuse only helpers whose complete contracts match.
The activation stage cannot borrow the promotion context by dropping its completion or registration checks.

## Per-slice validation and test placement

G0 keeps the assigned compile, focused12 and full5720 pre-gate sequence.
From G1, Bepi compiles and runs the new or affected test classes. Toni's gate runs the full Core suite.
If a slice changes PreparationIntentStore or shared fixtures, Bepi also runs the entire MachineUpdateReplacementTests class.
The full local publication gate remains Toni's responsibility before each push.

Add new test classes per block. Do not add prerequisite tests to the already heavy MachineUpdateReplacementTests class.
Existing regressions in that class remain required. G0's completed source is unchanged by this placement rule.
Keep fixture isolation and all assertions. The reviewer owns CI weights in separate measured PRs.

## Additional slices

Every production cap below is less than400 additions plus deletions. Names refer to RemozioCore sources unless another path appears.
The source column names measured donor locations. It does not claim that every donor line is missing or safe to apply unchanged.
Current public fixes, typed state, private constructors and policy-v2 canonical bytes must survive each adaptation.
No raw donor type may replace a current checked typed plan. Audit every added call against its current declaration.
The Core column is a test-design budget, not an executed timing or a guaranteed forecast.

### Stable preparation and initial runtime

| Slice | Complete responsibility and measured donor source | Production estimate; cap | Required tests | What remains unproven | Core addition budget |
| --- | --- | --- | --- | --- | --- |
| A01 | Stable account reservation. PreparationIntentStore.swift:4234–4358 (125 donor lines) | 150–240; 320 | Actual admission loan, revision/owner/target UID and disclosure refusals; other rows fixed | No account keys or initialized stores | 5–15s |
| A02 | Stable account storage SQL. PreparationIntentStore.swift:3985–4233 (249) | 270–350; 390 | Private authorization; exact public key and paired initialization; stale/rollback/foreign rows | No native credential or directory writes | 10–25s |
| A03 | Native account preparation. MachineUpdateStableAccountPreparation.swift (143) | 160–260; 340 | Owned key/storage operations, ordinary UID first, partial-state recovery, no disclosure bypass | Real protected identity and stores remain attended | 3–10s |
| A04 | Stable service account producer. PreparationIntentStore.swift:3212–3327 (116); MachineUpdateStableServiceAccountPreparation.swift (146) | 290–360; 390 | Reserve/complete exact plan; user/group identity conflicts; protected rows; native refusal first | Actual OS users/groups are not exercised by unit fixtures | 10–25s |
| A05 | Runtime material metadata and import change. PreparationIntentStore.swift:3837–3984 (148) | 190–290; 360 | Private runtime authorization, material/published flags, import exact source and rollback | No runtime file producer yet | 10–25s |
| A06 | Read-only initial configuration and view. RuntimeRetainedSetupInitialConfiguration.swift (56); MachineUpdateStableRuntimeView.swift (173); MachineUpdateStableRuntimePublishedSelection.swift (89) | 300–360; 390 | Exact source view, clients, canonical config, unsafe path and policy-revision changes | No initial file write; adapt to current typed snapshots | 5–15s |
| A07 | Retained runtime inputs and import preparation. MachineUpdateRetainedSetupRuntimeInputs.swift (92); MachineUpdateStableRuntimeImportPreparation.swift (131) | 240–320; 380 | Fresh shared-import snapshot, relay selection, import acknowledgement, expired input loan | No credential disclosure or invented import acknowledgement | 5–15s |
| A08 | Native material preparation. MachineUpdateRetainedSetupMaterialPreparation.swift (167); selected Scope/loan from MachineUpdateStableRuntimePublication.swift (238 total) | 190–280; 360 | Material retain/re-read, custody acceptance, activity/metadata fences and ordinary UID refusal | Port only the required scope; ordinary publication path stays out | 5–15s |
| A09 | Initial retained publication and completion. MachineUpdateRetainedSetupInitialPublication.swift (104); MachineUpdateRetainedSetupInitialCompletion.swift (165) | 290–360; 390 | Owned source files, exact bytes and material before/after publication, phase changes, source policy stays exact | Needs recorded policy from P04; no jobs registered | 15–35s |
| A10 | Initial runtime sequence. MachineUpdateRetainedSetupInitialRuntime.swift (150); MachineUpdateRetainedSetupRuntimeSequence.swift (174) | 320–365; 390 | Material→policy→publication→acknowledgement order; changed inputs; escaped callback and provider rejection | No authenticated Setup dispatch yet | 10–25s |
| A11 | Native runtime provider. MachineUpdateRetainedSetupRuntimeNative.swift (190) | 210–300; 370 | Close each machine connection, borrowed input lifetime, verifyCurrent at every stage, partial runtime recovery | Actual native account context remains attended | 5–15s |

### Schema25 policy producer

| Slice | Complete responsibility and measured donor source | Production estimate; cap | Required tests | What remains unproven | Core addition budget |
| --- | --- | --- | --- | --- | --- |
| P01 | Policy-v2 source and phase proposals. MachineUpdateRetainedSetupPolicyIntentRecord.swift: donor requireSource/preparingWrite/recording/reconciling/transition; current v2 source factory | 100–190; 260 | Real second paired commit, exact receipt/no-op, role/global revisions/checkpoint; unchanged writing grants no retry | Preserve v2 scope and current observe/codec; no donor-v1 restoration | 10–20s |
| P02 | Schema25 policy SQL and single-use acknowledgement. PreparationIntentStore.swift:5031–5267 (237) | 270–350; 390 | 24→25 migration, private gate, all other rows, id/revision predicates, fresh changed acknowledgement, rollback | No journal commit can occur before acknowledged writing and machine close | 20–45s |
| P03 | Policy journal permit and owner. AuthorityJournal.swift: retained startup hook within735–783; MachineUpdateRetainedSetupPolicyOwner.swift (221) | 260–340; 390 | Permit one-use/process/thread/closed-store checks; full phase order; exact recovered receipt; escaped/reentrant body | Unresolved writing remains owner intervention; no automatic replay | 15–40s |
| P04 | Native policy custody and writable pair. MachineUpdateRetainedSetupPolicyNative.swift (285; reuse G3 path/read-only parts) | 250–330; 390 | Explicit mutable-pair authority, protected identity/material/activity, close on every path, current owner checks | Real native policy commit remains attended; no generic readOnly bypass Boolean | 5–15s |

### Real typed plan and enrollment

| Slice | Complete responsibility and measured donor source | Production estimate; cap | Required tests | What remains unproven | Core addition budget |
| --- | --- | --- | --- | --- | --- |
| E01 | Checked retained enrollment inventory projection. PreparationIntentStore.swift: donor5513–5551; MachineUpdateStableReleaseSnapshot.swift (87 donor); typed retained plan inventory binding | 180–300; 380 | Sealed inventory unchanged; only exact authenticated retained account/service additions; all foreign additions/removals/code and seal changes rejected | New explicit reader contract; never delete inventory==installed-epoch guard | 15–35s |
| E02 | Typed v6 retention and enrollment SQL. PreparationIntentStore.swift:3373–3530 plus3594–3603; protected digest support near3800–3836 | 230–330; 390 | Retain exact v6 bytes; enroll exact derived account/jobs; private actual-frame adoption; all other rows pinned | No registration flag or proof until R02; typed state only | 20–45s |
| E03 | Activation native read-only scope. MachineUpdateRetainedSetupActivationNative.swift (221) | 240–330; 390 | Current typed metadata/code/custody/material; account and service identity; pair scope expiry | Keep separate activation and promotion stage invariants; no widening of G4 | 3–10s |
| E04 | Typed activation file publication. MachineUpdateStableRuntimeActivationPublication.swift (226 donor; adapt retained-only portion) | 210–320; 380 | Exact typed plan/host/job files, actual read-back and unknown exchange result; no ordinary decoder fallback | No live registration or ordinary runtime enablement | 10–25s |
| E05 | Retained activation enrollment owner. MachineUpdateRetainedSetupActivationOwner.swift (215) | 230–320; 380 | Source proposal, durable plan, checked file publication then enrollment, closed machine and exact actual frames | Native registration still absent until H/R blocks | 10–30s |

### Authenticated native health closure

| Slice | Complete responsibility and measured donor source | Production estimate; cap | Required tests | What remains unproven | Core addition budget |
| --- | --- | --- | --- | --- | --- |
| H01 | Registration/completion health plans. MachineUpdateRetainedSetupHealth.swift: plan portion7–269 (exclude promotion-only construction) | 170–260; 340 | Exact role, purpose, retained binding, policy/checkpoint and typed plan; reject crossed stages | No authenticated reply or channel yet | 2–5s |
| H02 | Health challenge and reply validation. MachineUpdateRetainedSetupHealth.swift:270–441 (172); MachineUpdateRetainedSetupJointHealth.swift (102) | 290–350; 390 | Nonce/deadline/signature/role/purpose binding; one consumption; joint root/transport transcript | Owned signatures are not native peer proof | 5–15s |
| H03 | Root startup metadata and read-only pair. MachineUpdateRetainedSetupRootStartup.swift (242); CompletionStartup.swift (57); selected checked store getter5682–5694 | 320–370; 399 | Exact command host/job files, actual pair/completion phase, native identity first; checked getter precedes generic CLI selection | No command admission or startup readiness claim | 3–8s |
| H04 | Health hello and XPC protocol. MachineUpdateRetainedSetupHealthXPCEndpoint.swift:5–64 (60) | 70–130; 200 | Explicit wire versions, role/purpose substitution, malformed payload and bounds | No endpoint executes requests yet | 1–3s |
| H05 | Native health peer and claimed request. MachineUpdateRetainedSetupHealthPeer.swift (315; omit promotion-only factories) | 270–340; 390 | Code/UID/connection identity, hello schema, immutable request, native vs owned claim, replay and close | Owned requests cannot pass native-only claims | 3–8s |
| H06 | Native authority/transport health keys. MachineUpdateRetainedSetupAuthorityHealthKey.swift (188); MachineUpdateRetainedSetupTransportHealthKey.swift (172); exclude promotion-only native paths | 270–340; 390 | Exact requested key/provenance, purpose, custody and peer fence; ordinary UID before key paths | Actual installed key access is attended; no secrets in artifacts | 5–15s |
| H07 | Transport driver, scope and channel. MachineUpdateRetainedSetupTransportHealthChannel.swift (354); omit native promotion factory | 320–365; 399 | Typed host3, exact root transcript and transport signature, connection failure/timeout/cancellation, scope lifetime | Native transport operation remains untested by owned driver | 5–15s |
| H08 | Authority channel core and peer fence (owned path only). MachineUpdateRetainedSetupAuthorityHealthChannel.swift:5–169 +170–185 +254–365 (293 selected) | 310–360; 399 | Owned channel state, one open, peer fence lifetime, close/late replies, purpose ownership | No reference to future concrete native contexts or raw native-proof constructor | 5–15s |
| H09 | Native authority health owner. MachineUpdateRetainedSetupAuthorityHealthOwner.swift (250); exclude promotion-only owner/context | 180–280; 360 | Claimed native request, typed startup scope, transport proof, current material/pair fences and resource release | No standalone native success claim | 3–8s |
| H10 | Native registration context/factory. MachineUpdateRetainedSetupAuthorityHealthChannel.swift:186–202 +366–445 (97 selected) | 120–210; 290 | Actual registered jobs observed before marking metadata; native-purpose proof, no owned-fence substitution | No registered database bit yet | 3–8s |
| H11 | Native completion/recovery context/factories. MachineUpdateRetainedSetupAuthorityHealthChannel.swift:203–236 +446–569 (158 selected) | 180–280; 360 | Fresh completion-purpose proof, exact before/after pair classification and recovery source; scope expiry | Cannot substitute registration or future promotion proof | 3–8s |
| H12 | Endpoint and retained listeners. MachineUpdateRetainedSetupHealthXPCEndpoint.swift:66–187 (122); MachineUpdateRetainedSetupHealthListeners.swift (134) | 280–350; 390 | Bounded XPC work, request claim, no reply after close, asynchronous settlement and activity release | Starting actual services is attended; fixtures check lifecycle only | 3–10s |
| H13 | Authenticated startup selection and CLI routing. HealthStartupSelection.swift (25); RuntimeStartup (10); selected bool/CLI getters5650–5681,5696–5706; startup call sites; generator/Python health-v1/v2 matrix | 130–240; 330 | Actual v6/stage selection, fixed path, no ordinary/gateway fallback; declare health1/2 only with reachable listeners | No installed running job proof until native test | 3–10s |

### Actual native registration

| Slice | Complete responsibility and measured donor source | Production estimate; cap | Required tests | What remains unproven | Core addition budget |
| --- | --- | --- | --- | --- | --- |
| R01 | Native registration observation. MachineUpdateRetainedSetupRegistrationObservation.swift (129) | 150–240; 320 | Native PeerFence bound to challenge/source/lease, process/thread/one-use expiry; owned proof rejection | No SQL registration marker yet | 5–15s |
| R02 | Actual job registration and metadata marker. MachineUpdateRetainedSetupRegistrationNative.swift (139); PreparationIntentStore.swift:3531–3593; private activation gate extensions | 230–330; 390 | Ensure actual fixed jobs, obtain live health then compare exact v6 row and registered=0; no proof-free marker; rollback/close | Actual Root execution and jobs still require attended verification | 15–35s |

### Schema26 completion and authenticated dispatch

| Slice | Complete responsibility and measured donor source | Production estimate; cap | Required tests | What remains unproven | Core addition budget |
| --- | --- | --- | --- | --- | --- |
| C00 | Read-only native completion observation. MachineUpdateRetainedSetupCompletionObservation.swift (176) | 190–280; 360 | Native completion PeerFence, sequence/use scope, exact source and native-only rejection | Must exist before C01 authorization references its proof | 5–15s |
| C01 | Schema26 completion writer and journal permit. PreparationIntentStore.swift:4802–5028 (227); AuthorityJournal.swift retained completion hook in735–783 | 270–350; 390 | 25→26 exact receipt, other rows, single-use changed write acknowledgement, closed-machine journal commit, pre-BEGIN formats | No completion owner or native floor update yet | 20–45s |
| C02 | Completion policy owner. MachineUpdateRetainedSetupCompletionOwner.swift (222) | 240–330; 390 | Prepared→writing→actual floor commit→recorded; exact recovered receipt; sourceUnchanged refuses replay; frame and callback expiry | No synthetic receipt can authorize a native floor write | 15–40s |
| C03 | Native completion entry. MachineUpdateRetainedSetupCompletionNative.swift (161); read-only startup helper already in H03 | 180–270; 350 | Native completion fence and sequence-use scope; current pair/material/custody, fresh health and closed stores | Keep all native proof checks; real floor commit is attended | 3–10s |
| C04 | Registration/completion sequence and providers. MachineUpdateRetainedSetupActivationNativeSequence.swift (86); selected MachineUpdateStableSetupAccountOperations.swift (113) | 190–290; 370 | Distinct registration then completion proofs, activity retained through callbacks, cancellation/cleanup; exact final recorded snapshot | No automatic ordinary promotion or admission reopening | 10–25s |
| C05 | Authenticated stable account/service dispatch. SetupAccountOwner.swift: stable selection355–397, enrollment398–466, service progress467–521; injection/verification fields | 220–330; 390 | Caller UID, disclosure, target UIDs, revisions, existing consent and progress semantics; foreign caller rejection | No synthetic selection or direct private store escape | 5–15s |
| C06 | Authenticated runtime/activation dispatch and truthful declarations. SetupAccountOwner.swift: runtime522–664 and retained activation branches2312–2449; generator and test declarations | 300–365; 399 | Existing custody acceptance, exact requested progress, native sequence and real recorded completion; declare only reachable25/26/file producers | Keep retained completion internal; no new visible state or ordinary-ready claim; no provider/hardware success claim | 10–25s |

## Dependency details that must not disappear

1. Policy25 is a real v2 producer, not the donor's old v1 codec.
P01 adds checked phase proposals beside the current private validation and v2 source digest.
P02 keeps the complete single-use acknowledgement. P03 changes the paired journal only through that acknowledgement after the machine closes.
A writing marker with an unchanged source remains unavailable for replay. A recovered receipt is recorded only after an exact fresh pair read.

2. Enrollment requires a new explicit reader contract in E01.
Before E01 code, write a short design note listing accepted and rejected images and the invariants that remain.
Chiacchiersaturn reviews the note. Toni approves it before implementation.
If the design weakens an existing security invariant, Toni takes that decision to Seb. The note cannot approve that change.
The current frame requires inventory==installed epoch. The donor accepts later inventory rows; that condition cannot be copied without proof.
Keep the strict sealed-base reader and the installed epoch unchanged.
A separate checked retained-enrollment projection must reconstruct only the exact additions authorized by typed v6 plans and their actual policy/preparation rows.
Bind account/owner, service labels, execution IDs, bundle/release, seal, original inventory and every other protected row.
Reject missing original rows, arbitrary new accounts/services, changed reservations, crossed plans or unsupported schema changes.
Only the retained path may use that projection. Ordinary unsupported reads must refuse without treating a known valid retained state as corruption.
E02 authorizes one exact before/after image under closed admission. It cannot grant arbitrary inventory mutation.
This is additional source work, not permission to delete an equality check to obtain a passing fixture.

3. Real registration needs the whole native health path.
The donor registration/completion observations require AuthorityHealthScope.PeerFence with a native purpose and fresh authenticated reply.
The source flags jobsRegistered and inInventory are results, not substitutes for that proof.
H10 and H11 mint distinct registration/completion scopes. Owned requests and owned signatures must fail native-only consumption.
H13 launches/selects only the retained health path. It never falls through to ordinary commands or the gateway runtime.
H13 includes the exact native registration/completion health format declarations and Python tests for health-v1/v2 roles.
No native-promotion factory or health-v3 writer is enabled by this prerequisite block.
Actual service execution, key custody, signing identity and native transport remain attended checks; no such execution occurs during planning.

4. Completion26 changes the actual paired policy floor.
C01 must retain the receipt namespace and changed/one-use checks. Its floor commit uses the current journal permit contract.
C02/C03 retain the material, identity, closed admission, exact pair and native completion proof through the commit and final recorded marker.
P03 and C02 preserve unresolved-writing intervention. They do not replay a policy write merely because a method is named resume.

5. Authenticated dispatch is part of the distance to usability.
The donor entry is MachineUpdateStableSetupAccountOperations.native, injected into SetupAccountOwner.
C05 covers account/service selection and consent. C06 covers runtime custody acceptance and the retained activation/completion branch.
Bind caller UID, actual request revision and existing host authorization. Keep the normal Setup UX and refusal paths.
Keep retained completion as an internal result. Do not show a new Setup state or change the existing visible completion behavior.
Do not report ordinary-ready before promotion and the separate final gates.
If these constraints require a visible UX change, Toni must obtain Seb's product decision before that change.
No automatic activation, shared-update owner change, admission reopening or service restart is added by a planning shortcut.

6. Writer declarations follow actual reachability.
G2 adds readers only. C05/C06 and G9 add the corresponding writer declarations with their complete reachable producers.
C06 can declare initial host3, retained-release v1, activation6 and actual policy25/completion26 emitters once their native route exists.
G9 declares completed-host4 and binding/archive/configuration/publication writers with the completed publication route.
Do not declare a policy-v1 emitter or future schema28 writer. Check the complete current role/version union before BEGIN.
When actual producers become reachable, update the current empty-writer assertions in G0 and the manifest tests to the exact new role matrix.
Keep their codec reader comparisons intact. A deliberate new producer contract must not leave an obsolete read-only assertion behind.

7. More code than one cap is not an excuse to cut a guard.
The611-line authority channel is staged in H08/H10/H11 within its original file, keeping private constructors private.
H08 adds only the core and owned path. H10 adds native registration; H11 adds completion and recovery.
H04 introduces the hello/protocol before H05 peer code uses it. H02 includes the joint-health transcript/proof/session.
H08 has no field whose concrete native context is defined only in H10/H11. Native constructors stay private in the same file.
H03 includes its checked store getter and the completion startup helper; it does not call the later H13 generic selector.
C00 introduces the read-only completion observation before C01 references it in a private writer authorization.
The donor stable compatibility wrapper is not a wholesale dependency; its current callers use the G1 checked stable entry.
C04 omits the donor ordinary-stable activation owner and post-promotion finalization provider. Neither can be a temporary stub.
The native-promotion context and factories are outside this prerequisite block; they are not silently enabled.
Source code already present in public models is reused. A missing donor filename is not proof that its type or responsibility is missing.

## Core and CI capacity

The budget baseline is Toni's full F Core stage:2123s of2700s, leaving577s, as reported in1456.
Bepi's1776.876s F pre-gate is a separate measurement and does not set Toni's gate headroom.
After #690 merges, Toni owns splitting his local Core stage with scripts/run-xctest-shards.py --concurrent.
Preserve the exactly-once outcome check. This plan does not claim the change is already applied or qualified.
G0 adds two full-fixture methods; a20–40s test budget is provisional, using the observed focused F cost only as a rough guide.
Other slices should use owned lightweight fixtures and grouped independent assertions instead of repeating the entire replacement setup for every edge.
Each negative case still starts from a valid control. Stores must be fresh or re-resolved after reopen. No mutable global fixture sharing is proposed.

| Original slice | Provisional incremental Core budget |
| --- | --- |
| G0 | 20–40s |
| G1 | 15–45s |
| G2 | 0–0s |
| G3 | 3–10s |
| G4 | 5–15s |
| G5 | 10–30s |
| G6 | 25–60s |
| G7 | 5–15s |
| G8 | 20–60s |
| G9 | 5–15s |

The42 prerequisite budgets sum to323–838s. G0–G9 add108–290s.
The crude serial range on Toni's2123s baseline is2554–3251s. It is not measured qualification evidence.
The serial upper estimate exceeds2700s. Toni owns the local stage split and its validation after #690.
Do not claim that future sources fit a gate until their actual gate completes.
Keep actual per-case timings and lightweight fixtures for each slice. Toni owns full Core capacity and stage scheduling.
Qualify measured fixture improvements separately when needed.
Preserve all assertions, isolation and actual case outcomes. Do not skip tests, increase the budget, fake transfer evidence or rerun passed stages for bookkeeping.
This performance follow-up is conditional on actual timings; the52-slice source plan can require additional measured fixture work.
CI method/class weights are owned by chiacchiersaturn, from actual CI logs, in small PRs between feature slices per1446.
A new heavy class must not receive a misleading median weight. CI balancing and Toni's local stage split have separate validation.

## Source-only status

The source inspection records40 named donor files and10 selected SQL/journal excerpts in producer-closure-inventory.json.
They are a directed dependency inventory, not a feature count or a private-snapshot publication plan.
The existing G0 commit d8972ae1 is separate. This appendix applies no product source and runs no parse/build/test.
The original donor-decision table is now explicit about direct G dependencies versus prerequisites in P/E/H/R/C.
All producer and native-success claims above remain future obligations. No installed credentials, devices, services or signing identities were accessed.
