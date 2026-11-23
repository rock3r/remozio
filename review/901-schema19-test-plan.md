# Schema 19 migration test plan

This proposal covers the journal migration and the Root stage transitions in #901. It follows the [accepted migration design](https://github.com/rock3r/remozio/blob/7f362fdd4ccf2f83f15ec0cbec9c2c04593abf16/review/901-journal-migration-plan.md). The selector inventory uses PR #912 at `a3f25403`. Verify the merged base before creating fixtures or selecting tests. The schema 19 tests below are proposed names.

## Fixtures and evidence

- Use the real journal lease and checkpoint writer with temporary files and test keys. Use existing installers to construct valid tier catalogs and preserve their rows. Use SQLite fixture mutations only to inject faults or invalid inputs.
- Exercise the real Root setup owner with a valid version 2 re-pair. Observe when it reserves the stage, commits the journal, finalizes continuity, and releases the transcript. Reopen both stores and inspect admission before and after startup recovery.
- At each migration boundary record the physical version, feature tier, exact catalog, authority and ledger digests, committed and pending checkpoints, stage identity and row count, admission state, and whether the reply escaped. Use distinct test recordings for old-format and migrated states.
- Run the legacy binary witness as an ordinary user. Use temporary fixture copies with valid old-tier and migrated journal/continuity pairs. Use the actual old open path with implicit migration disabled. Prove the old-tier control opens, the migrated pair returns the expected format rejection, and both files and the sidecar inventory remain unchanged. Build the old source in the existing authorized checkout under the native lock. Keep the baseline commit, build terminal, binary hash, invocation, exit status, and before/after hashes. Use only test credentials and fixture files.
- Exercise the Root stage transitions through the owner that holds the existing writer lease. Use controlled Root clock values and deterministic barriers on either side of the durable commit. Check the pending and terminal stage rows after reopening the stores. The signed reply lookup and Android retirement follow in separate changes.

## Proposed focused selection

Use one new class, `AuthorityJournalSchema19MigrationTests`. Follow the existing production entry points and fault hooks. Keep one XCT outcome per named method and record the subcase outcomes.

| Proposed method | Required assertions |
| --- | --- |
| `testOrdinaryPairingAndStartupKeepTheExistingFormat` | Ordinary pairing completes on an old journal. Startup and the pairing path keep the version, catalog, and digest format. The pairing commit changes its expected rows and checkpoint only. |
| `testFirstAuthorizedRePairStageCommitsMigrationAndStageOnce` | An eligible, authorized first stage migrates and writes the stage in the same transaction. The reply leaves Root after both commits. Reopen reconstructs the same stage. Retry cannot duplicate it or refresh its deadline. |
| `testRejectedRePairDoesNotMigrateOrReserve` | A refused authorization, stale revision, invalid predecessor, or busy admission leaves the original catalog, checkpoint, reply count and stage capacity intact. |
| `testMigrationPreservesTheCatalogAndContinuityAtEachLegacyTier` | Use catalog-valid fixtures for every tier 12–18. Exercise real eligible stage migration at tiers 13, 15, 17 and 18. Assert the old table and row set plus exactly the two new tables, one singleton, the same feature tier, and the intended authority format transition. Low tiers keep optional gateway features absent. A stage-only mutation must keep the ledger digest and chain head. |
| `testSchemaNineteenRejectsInvalidTierAndCatalogWithoutOpeningAdmission` | Reject missing or malformed singleton, out-of-range tier, missing stage table, extra table, and tier/catalog mismatch. Reject an incorrect checkpoint or a checkpoint that describes schema 19 without the matching stage. Failed opens do not repair or recreate files. |
| `testSchemaNineteenInstallersPromoteTheTierWithoutChangingTheFormat` | Exercise installers at their supported boundaries for tiers 13 through 18. The singleton and each table change commit together. A rollback preserves the old tier and catalog. Physical version stays 19 and repeated installation follows the existing idempotence contract. |
| `testTierSeventeenAbandonmentPromotesToEighteenAndSurvivesReopen` | Preserve the grant history and terminal identity. A real abandonment changes tier 17 to 18 with outer 19 unchanged. Publisher and candidate readers recognize the durable tombstone after reopen. Include an already-abandoned grant from an old tier 18 as a migration fixture. |
| `testStageAndCheckpointPreparationFailuresKeepTheExactOldBoundary` | Inject a fault before the first stage insert and a failure preparing continuity. Roll back both schema/table changes and stage. The old boundary and old reader remain valid, and Root returns no transcript. |
| `testStartupDiscardsNewCheckpointAfterJournalRollback` | Fail after continuity prepares the new boundary and before the journal commits. Startup discards the pending checkpoint when the exact old journal is present, then reopens admission. No stage or new reply survives. |
| `testStartupFinalizesTheMigratedCheckpointWithoutRestaging` | Fail finalization after the journal commits the migration and stage. Admission stays closed until startup verifies the exact candidate. Finalization is idempotent and cannot create a new stage or release a new transcript. An incomplete or mismatched candidate remains closed. |
| `testAuditChainSpansTheAuthorityFormatTransition` | Append one real audit event on each side. The pre-migration event hash is the post-migration predecessor. Verify the chain and unchanged retained records after reopen. |
| `testCutoverChecksPhysicalFormatTierAndCheckpoint` | Snapshot and compare both version values and the checkpoint. Reject changes in each independently. A rejected inspection makes no checkpoint or stage write. |

## Root stage transition selection

Add these seven methods to the same focused class. Count the durable recovery slots independently of transient setup admission.

| Proposed method | Required assertions |
| --- | --- |
| `testCommitAndExpirySerializeAndPreserveTheDurableCommit` | Release commit and expiry contenders against the same writer in both orders. If the commit is durable before expiry obtains the writer, the committed stage and original receipt remain. If expiry wins first, the later commit cannot enroll or change that terminal state. No observation reports expiry while a durable commit is eligible for recovery through checkpoint finalization. |
| `testExpiryUsesOnlyTheRootClockUnderTheCurrentWriterLease` | Sample the controlled Root clock within the leased writer. Check immediately before, at, and after the approved deadline boundary. A stale timer callback, a client clock value, or a lost lease cannot expire a stage. Apply a valid expiry once and preserve its reason across reopen. |
| `testStartupClosesOnlyPendingStagesFromRetiredIncarnations` | Seed pending stages for a retired incarnation and for the current incarnation, plus terminal stages from both. Reconcile the checkpoints first. Close the retired pending stages before setup or recovery admits work. Record `retired incarnation` only on those rows, keep current pending and all terminal records intact, and verify idempotence across a second restart. |
| `testVersionTwoStageSlotIsUniqueForAnIdentity` | Race two valid stage reservations for the same identity on different connections. Keep at most one nonterminal row. A replay of the same request must preserve its binding and deadline. Keep version 1 pairing out of the recovery slot accounting. |
| `testVersionTwoStageLimitIsThirtyTwoPerAccount` | Reserve 32 nonterminal version 2 stages for distinct identities in one account. Refuse the 33rd with the original 32 unchanged. Verify the limit across reopen and show another account has independent capacity. |
| `testStageSlotsReleaseOnlyOnAuthorizedTransitions` | Check commit, a new reservation through the valid replacement transition, revocation or removal, and an explicit authorized action. Each release affects only the intended slot and retains the correct terminal evidence. A failed or wrong-scope action cannot release another slot. Retry a completed release and verify it does not release a second slot. |
| `testThirtyThreeFailedOrdinaryPairingsDoNotConsumeRecoverySlots` | Fail 33 ordinary pairing attempts at a point that acquires transient setup admission. An ordinary pairing then succeeds. Verify that recovery-slot counts and the old journal format remain unchanged by the sequence. |

## Existing baseline selectors

Toni approved these 13 tests on the merged predecessor. Run them after reconciling #912 with main and keep their evidence separate from the new tests.

- `AuthorityPairingSetupTests/testConfirmedProofCommitsAndSignsThroughTheExistingOwner`
- `AuthorityPairingSetupTests/testRePairStagesAndCommitsOnlyAfterRevocation`
- `AuthorityPairingSetupTests/testHandshakePeerAndAdministratorFailuresCannotStage`
- `AuthorityPairingSetupTests/testMaintenanceStageReservationSurvivesCommitUntilTheReceiptReplyReturns`
- `CheckpointedJournalTests/testPreparationFailureRollsBackJournalAndRetiresCoordinator`
- `CheckpointedJournalTests/testRecoveryDiscardsPreparationWhenJournalRolledBack`
- `CheckpointedJournalTests/testRecoveryFinalizesCommittedCandidateAndIsIdempotent`
- `CheckpointedJournalTests/testStartupWithholdsWriterUntilCheckpointedRecoveryCompletes`
- `JournalDatabaseTests/testContinuityDigestsSeparateHistoryAndSurviveReopen`
- `GatewayAuthorityJournalTests/testTombstoneHeadMustMatchTheExactRetainedGrant`
- `UpdateSchedulingJournalTests/testSchedulingStorageOpensFromCommandSchemaWithoutEnablingOptionalGateway`
- `UpdateSchedulingJournalTests/testSchemaSeventeenSupportsGatewayRotationRenewalAndRevocationAfterReopen`
- `AuthorityJournalCutoverInspectionTests/testMismatchedCheckpointIsRefusedWithoutMarkingRepairOrRewritingFiles`

## Proposed regression gate

Start from the 18 approved PR #912 classes. Add `AuthorityPairingSetupTests` (58), `AuthorityMaintenancePairingAdmissionTests` (25), `AuthorityPairingReceiptTests` (7), `MacPairingSessionTests` (14), `PairingSetupNetworkSessionTests` (5), and `TransportPairingControlTests` (15). The current source projects 1,011 existing Swift methods after the same single Secure Enclave exclusion. The 19 proposed focused methods bring the projected gate to 1,030 Swift methods in 25 classes. Run the three existing Python guard cases after adding migration-specific assertions to them. Run the legacy binary witness separately. Refresh the exact method counts and each selection after the implementation and compiled discovery.

Use the existing ATC native gate and lock. The last gate took 4 min 43 s for discovery and 887 tests. Updated estimates are 5–10 minutes for the focused candidate, 7–14 minutes for the regression gate, and 4–8 minutes for the old-binary witness. Proposed caps are 720, 1,200, and 600 seconds, respectively. Re-estimate after source and fixture review.

This is a review proposal. Implement it after #912 merges. No migration code, test overlay, build, or test run accompanies it.
