# Pairing recovery journal migration

Review proposal for [#901](https://github.com/rock3r/remozio/issues/901). This storage change follows the signed wire format.

## Activation boundary

Migrate at the first authorized version 2 re-pair stage that can reserve a recovery slot. Run the migration and the initial stage write in the same authority transaction. A failure before commit leaves the existing format and admission state in place. Root releases the new transcript only after the journal and continuity checkpoint agree.

Ordinary pairing and startup of an account without a recovery journal keep the current schema. A client that never starts re-pair stays on its existing schema. After the migration commits, an older Mac binary cannot open that account's journal. Document this downgrade boundary and require a release that understands schema 19 before activation.

## Schema and compatibility

Use outer `PRAGMA user_version=19`. A singleton records the installed feature tier from 12 through 18. Add the recovery stage table. Preserve the previous table catalog and feature tier. For example, migrations from 13 and 15 leave gateway scheduling and submission storage absent where they were absent before.

On schema 19, recover the feature tier from the validated singleton and check the exact catalog for that tier plus the two recovery tables. Later feature installation advances the tier inside the same authority transaction. It keeps `user_version=19`. Any existing code that checks or installs a feature by schema version must use this tier or the common resolver. Older schemas continue through the existing paths.

`JournalContinuityDigest` uses the current catalog and byte format unchanged on schemas 12–18. Schema 19 has a distinct authority digest format. It covers the tier singleton, recovery table, and old authority tables selected by the tier. The audit ledger digest format stays the same. Treat the first migration as an explicit authority format transition under the current lease and checkpoint writer. Update the compatibility declarations and checkpoint transition together. Startup must recover an interrupted transition before reopening admission.

An older binary rejects 19 in the existing identity and schema check before journal writes. It must leave the database and continuity store intact. Do not introduce an automatic downgrade or a fallback that creates a new journal.

## Required evidence

- On an unchanged old-tier journal, ordinary pairing completes and leaves the schema, catalog, and continuity format unchanged. Start re-pair afterwards and verify that its first stage upgrades the format in the same transaction.
- Exercise 13 and 15 without gateway data, and 17 and 18 with their existing features. Verify the exact catalogs and digests before and after. Verify a later feature-tier promotion while the outer schema remains 19.
- Force failure before commit and across the journal/checkpoint boundary. On reopen, verify either the exact old format or the exact schema 19 format with its staged attempt. Check that a mismatched or incomplete catalog stays closed.
- Attempt to open a migrated journal with the old binary. Verify rejection and compare the journal and continuity bytes before and after.

This proposal changes only the design. It leaves the choice of test selectors and the migration gate to the implementation review.
