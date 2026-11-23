# Pairing recovery journal migration

Review proposal for [#901](https://github.com/rock3r/remozio/issues/901). This storage change follows the signed wire format.

## Activation boundary

Migrate at the first authorized version 2 re-pair stage that can reserve a recovery slot. Run the migration and the initial stage write in the same authority transaction. A failure before commit leaves the existing format and admission state in place. Root releases the new transcript only after the journal and continuity checkpoint agree.

Ordinary pairing and startup of an account without a recovery journal keep the current schema. A client that never starts re-pair stays on its existing schema. After the migration commits, an older Mac binary cannot open that account's journal. Document this downgrade boundary and require a release that understands schema 19 before activation.

## Schema and compatibility

Use outer `PRAGMA user_version=19`. A singleton records the installed feature tier from 12 through 18. Add the recovery stage table. Preserve the previous table catalog and feature tier. For example, migrations from 13 and 15 leave gateway scheduling and submission storage absent where they were absent before.

Use one authority journal resolver, `featureTier`. It reads `user_version` for schemas 12–18. For schema 19 it reads the validated singleton and checks the exact catalog for that tier plus the two recovery tables. All authority journal capability checks and installers use the resolver. On 19, installers advance the singleton inside the same transaction as their table changes. They leave `user_version=19`.

| Current use | Required migration coverage |
| --- | --- |
| `GatewayAuthorityJournal.abandonmentHistoryInstalled` at line 570 | Compare the feature tier to 18. Preserve abandoned-grant visibility for publisher and candidate reads. An outer version of 19 cannot hide a durable abandonment. |
| `GatewayAuthorityJournal` submission checks at lines 557, 703, 1178, 1217, 1263, 1287, 1304, and 1313 | Use the tier for presence checks, counts, and queries. On a migrated tier 13, submission history stays absent. |
| `JournalDatabase` at lines 213, 234, 587, and 1168, and `ApprovalRequestCoordinator` at lines 1442 and 1463 | Use the tier for abandonment queries, initialization expectations, replay installation, retained scheduling reads, and scheduling admission. |
| `AuthorityJournalCutoverInspection` at lines 133 and 156 | Snapshot and compare the validated outer format and tier. Matching those fields does not substitute for matching the checkpoint. |
| `CodePolicyJournal`, `HistoryRecoveryJournal`, `CommandSubmissionReplayJournal`, `GatewayAuthorityJournal`, and `UpdateSchedulingJournal` | Route version reads and installer writes through the resolver. This includes the 13, 14, 15, 16, 17, and 18 promotions, including the grant abandonment installer. |

Add a source check to the migration gate. In the authority journal and its feature installers, reject assignments to `user_version` and direct feature comparisons on `storageSchemaVersion` or `submissionSchemaVersion` outside the resolver and explicit authority journal migrations. Include multiline SQL writes and direct comparison variants in the check tests. The independent `ContinuityStore`, `GatewayDatabase`, and `PreparationIntentStore` use their own schemas and remain outside this check.

`JournalContinuityDigest` uses the current catalog and byte format unchanged on schemas 12–18. Schema 19 has a distinct authority digest format. It covers the tier singleton, recovery table, and old authority tables selected by the tier. The audit ledger digest format stays the same. Treat the first migration as an explicit authority format transition under the current lease and checkpoint writer. Update the compatibility declarations and checkpoint transition together. At startup, the checkpoint writer's committed and pending state decides whether recovery accepts the exact old format or the exact schema 19 format with its stage. The outer version alone cannot decide. Startup completes that recovery before reopening admission.

An older binary rejects 19 in the existing identity and schema check before journal writes. It must leave the database and continuity store intact. Do not introduce an automatic downgrade or a fallback that creates a new journal.

## Required evidence

- On an unchanged old-tier journal, ordinary pairing completes and leaves the schema, catalog, and continuity format unchanged. Start re-pair afterwards and verify that its first stage upgrades the format in the same transaction.
- Exercise 13 and 15 without gateway data, and 17 and 18 with their existing features. Verify the exact catalogs and digests before and after. On schema 19 with tier 17, durably abandon a grant. Verify that the tier becomes 18, the outer version remains 19, and the publisher and candidate reads still see the grant as abandoned after reopen.
- Force failure before commit and across the journal/checkpoint boundary. On reopen, verify either the exact old format or the exact schema 19 format with its staged attempt. Check that a mismatched or incomplete catalog stays closed.
- Append an audit event before migration and another afterwards. Verify that the last pre-migration hash is the predecessor of the first post-migration event and that chain verification succeeds.
- Attempt to open a migrated journal with the old binary. Verify rejection and compare the journal and continuity bytes before and after.

This proposal changes only the design. It leaves the choice of test selectors and the migration gate to the implementation review.
