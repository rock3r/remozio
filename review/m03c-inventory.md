# M03c retained writer inventory, Toni 2870

Source `54d95b8a362aed95c28fe47a76d79a0be7d1ec22`, tree `b9639e879ea8162c17bfbc7d7d2e0f47aadd3fa9`.
Paths below are under `macos/core/Sources/RemozioCore`. This is source review only. No schema 29 writer execution is claimed.
M03b1 changes startup reads only. M03b2 is not implemented. M03c must close before M15 permits the first native body.

Toni 2870 narrows M03c to policy, material, publication and promotion. Policy/material/publication are mandatory before M15. Promotion must be ready before a migrated machine reaches promotion. Completion and readiness SQL producers are separate issue #760 work. They do not block the window itself.

## Policy, material and publication

Existing policy and associated material/publication writers have private owners. Their admission and transition guards exclude schema 29.
Keep the native scope, paired journal, candidate formats, exact metadata, admission and transaction checks. A larger version set alone is insufficient.

- `MachineUpdateRetainedSetupPolicyStorage.swift:9`: `static let stableSchemaVersions = Set(24...MachineUpdateRetainedSetupPromotionReadyStorage.schemaVersion)`
- `MachineUpdateRetainedSetupPolicyStorage.swift:10`: `static let policySchemaVersions: Set<Int64> = [25, 26, 27, 28]`
- `MachineUpdateRetainedSetupPolicyStorage.swift:41`: `guard stableSchemaVersions.contains(version) else { throw PreparationStoreError.incompatibleStore }`
- `MachineUpdateRetainedSetupPolicyNativeContext.swift:187`: `guard MachineUpdateRetainedSetupPolicyStorage.stableSchemaVersions.contains(runtime.setup.source.actual.schemaVersion),`
- `MachineUpdateRetainedSetupPolicySnapshot.swift:25`: `MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(activation.runtime.setup.source.actual.schemaVersion) else {`
- `MachineUpdateRetainedSetupPolicySnapshot.swift:32`: `MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(activation.runtime.setup.source.actual.schemaVersion) else {`
- `MachineUpdateRetainedSetupPolicySnapshot.swift:48`: `MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(previous.schemaVersion),`
- `MachineUpdateRetainedSetupPolicySnapshot.swift:71`: `MachineUpdateRetainedSetupPolicyStorage.stableSchemaVersions.contains(prior.schemaVersion),`
- `PreparationIntentStore.swift:4016`: `MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(expected.activation.runtime.setup.source.actual.schemaVersion) else {`
- `PreparationIntentStore.swift:4144`: `MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(expected.setup.source.actual.schemaVersion) else {`
- `PreparationIntentStore.swift:6869`: `MachineUpdateRetainedSetupPolicyStorage.policySchemaVersions.contains(try scalar("PRAGMA user_version")) else {`
- `PreparationIntentStore.swift:6877`: `MachineUpdateRetainedSetupPolicyStorage.stableSchemaVersions.contains(try scalar("PRAGMA user_version")) else {`
- `PreparationIntentStore.swift:6885`: `(24...28).contains(try scalar("PRAGMA user_version")) else { throw PreparationStoreError.invalidTransition }`
- `PreparationIntentStore.swift:6891`: `(24...28).contains(try scalar("PRAGMA user_version")) else { throw PreparationStoreError.invalidTransition }`
- `PreparationIntentStore.swift:6896`: `(24...28).contains(try scalar("PRAGMA user_version")) else { throw PreparationStoreError.invalidTransition }`
- `PreparationIntentStore.swift:6901`: `(24...28).contains(try scalar("PRAGMA user_version")) else { throw PreparationStoreError.invalidTransition }`
- `PreparationIntentStore.swift:6906`: `(24...28).contains(try scalar("PRAGMA user_version")) else {`

Required evidence: actual schema 29 retention and phase CAS, exact other rows/catalog, native scope rejection, uncertainty retirement, and admitted material/publication transitions.

## Issue #760: completion producer

The completion read constructor accepts schema 29 after M03a. Its mutation comparison contracts still exclude 29.
On this source, searches for the table literal and every CompletionStorage reference found declarations/readers and digest admission, but no executable SQL producer.
This is a missing implementation as well as a version contract. Do not treat the proposal methods or owned SQL fixtures as a production writer.

- `MachineUpdateRetainedSetupCompletionSnapshot.swift:34`: `[Int64(26), 27, 28].contains(activation.runtime.setup.source.actual.schemaVersion) else { throw PreparationStoreError.staleRevision }`
- `MachineUpdateRetainedSetupCompletionSnapshot.swift:39`: `[Int64(26), 27, 28].contains(activation.runtime.setup.source.actual.schemaVersion) else { throw PreparationStoreError.staleRevision }`
- `MachineUpdateRetainedSetupCompletionSnapshot.swift:46`: `[Int64(26), 27, 28].contains(before.activation.runtime.setup.source.actual.schemaVersion),`
- `MachineUpdateRetainedSetupCompletionSnapshot.swift:47`: `[Int64(27), 28].contains(activation.runtime.setup.source.actual.schemaVersion) else {`
- `MachineUpdateRetainedSetupCompletionSnapshot.swift:55`: `[Int64(27), 28].contains(before.activation.runtime.setup.source.actual.schemaVersion),`
- `MachineUpdateRetainedSetupCompletionSnapshot.swift:56`: `activation.runtime.setup.source.actual.schemaVersion == 28 else {`
- `MachineUpdateRetainedSetupCompletionSnapshot.swift:68`: `|| allowReadinessMigration && prior.schemaVersion == 27 && frame.schemaVersion == 28,`

Required evidence: an actual owner-bound SQL writer on schema 29, exact initial/adjacent CAS, paired completion receipt checks, unchanged unrelated rows/catalog and failed-commit recovery.

## Promotion

The metadata read constructor accepts 29. The producer declarations, catalog, native context, row primitive and transaction owner still reject it.

- `MachineUpdateRetainedSetupPromotionStorage.swift:56`: `case (27, _), (28, _): break`
- `MachineUpdateRetainedSetupPromotionCatalog.swift:56`: `guard [Int64(26), 27, 28].contains(value), try step(row) == SQLITE_DONE else {`
- `MachineUpdateRetainedSetupPromotionNativeContext.swift:258`: `guard expected.intent?.phase == .recorded, [Int64(26), 27, 28].contains(runtime.setup.source.actual.schemaVersion),`
- `MachineUpdateRetainedSetupPromotionSnapshot.swift:28`: `[Int64(27), 28].contains(completion.activation.runtime.setup.source.actual.schemaVersion) else {`
- `MachineUpdateRetainedSetupPromotionSnapshot.swift:35`: `[Int64(27), 28].contains(completion.activation.runtime.setup.source.actual.schemaVersion) else {`
- `MachineUpdateRetainedSetupPromotionSnapshot.swift:38`: `guard [Int64(27), 28].contains(before.completion.activation.runtime.setup.source.actual.schemaVersion) else {`
- `PreparationIntentStore.swift:5345`: `guard previous == nil && [Int64(26), 27, 28].contains(schema) || previous != nil && [Int64(27), 28].contains(schema) else {`
- `PreparationIntentStore.swift:6912`: `[Int64(26), 27, 28].contains(try scalar("PRAGMA user_version")) else {`

Required evidence: real schema 29 retain and phase change through the existing typed native owner, exact catalog/other rows, full reader/producer cohort, wrong-source rejection and uncertain commit retirement.

## Issue #760: readiness producer

The source declares canonical readiness records, DDL and readers. I found no executable SQL readiness producer on this source.
CompletionSnapshot.requireReadinessMetadataChange only permits the existing 27→28 or 28 comparison. It is not a persisted readiness writer.
Implement the actual owner before advertising schema 29 readiness writes. Registration and synthetic packets cannot substitute for joint native health.

- `MachineUpdateRetainedSetupCompletionSnapshot.swift:53`: `func requireReadinessMetadataChange(from before: Self) throws {`
- `MachineUpdateRetainedSetupCompletionSnapshot.swift:55`: `[Int64(27), 28].contains(before.activation.runtime.setup.source.actual.schemaVersion),`
- `MachineUpdateRetainedSetupCompletionSnapshot.swift:56`: `activation.runtime.setup.source.actual.schemaVersion == 28 else {`

Required evidence: actual schema 29 readiness CAS, exact published promotion, authenticated joint health, unchanged unrelated rows/catalog and interruption recovery.

## Reachability and tests

M03b2 may expose only an internal window metadata writer. It must have no production caller until M03c and the native lifecycle gates are complete.
The schema 28→29 migration and first window must share one transaction. Any pre-commit failure must leave schema 28 unchanged.
Each M03c writer needs its own real schema 29 regression. A remaining blocked writer needs a named cause and keeps M15 closed.
Ordinary account/service writers remain guarded separately. This inventory does not authorize widening their contracts.
The current M03a tests that prove writer refusal remain truthful until their specific M03c successor replaces that expectation.
