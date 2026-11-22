# Issue #851 — Reserve journal capacity for phone revocation

Plan reviewed against main `2d2b1fb6839801b0ad47dd43eb87a2be228acc57`. This is the first pairing lifecycle PR. It changes the Mac Authority journal capacity contract. It keeps the existing Android, Mac UI and gateway wire contracts.

## Failure and invariant

`GatewayAuthorityJournal.capacity()` currently counts phone trust restrictions, recovered revocations and signed revocation controls in the same budget as push delivery. `JournalDatabase.revokeApprovalEnrollment` writes the enrollment change, signed gateway control and audit event together. A refusal to insert the control rolls back the enrollment change.

Every retained enrollment has capacity for its first signed revocation and its first verified recovered revocation. Traffic cannot consume those slots. The guarantee applies to the exact retained phone and enrollment epoch. Other scopes and exhausted storage still fail closed. Gateway publication and local trust remain distinct.

## Schema and accounting

Keep authority journal schemas 12 through 17, their current tables, signed payloads and continuity digest formats. Use a logical migration on upgrade. Derive usage from durable rows inside the enclosing write transaction. This needs no counter row, migration file or new `user_version`. It also keeps the optional submission and scheduling schemas independent. Use the existing version guard for the submission outbox when it is absent.

| Capacity | Accounted rows | Proposed limit |
| --- | --- | --- |
| Delivery history | `gateway_outbox_v1`, candidate and activation history in `gateway_reconciled_controls_v1`, and optional `gateway_submission_outbox_v1`. Keep submission accounting and behavior in this budget for this PR. | The configured `maximumControls`, default 4,096. |
| First signed revocation | One `gateway_revocations_v1` row per exact pair in `approval_enrollments_v1` with any signed revocation. Count an existing row or a reconciled row against this slot. | 1,024. This is one slot per retained enrollment, matching the ledger's total retained row limit. |
| First recovered revocation | One `gateway_recovered_revocations_v1` row per exact retained pair. The primary key makes this one row per pair. | Separate 1,024 slots. |
| Other signed revocation history | Further signed rows for already covered epochs, including refreshed delivery envelopes, plus canonical revocation rows for epochs outside the retained ledger. | 4,096 separate slots. |
| Recovered revocations outside the retained ledger | Verified `gateway_recovered_revocations_v1` rows without an exact retained pair. | 1,024 separate slots. |
| Unknown trust restrictions | `gateway_trust_restrictions_v1` rows keyed by phone. | The existing separate 1,024-row limit. |

At the default delivery setting, the total new steady-state limits account for 12,288 control and evidence rows. This excludes auxiliary rows and any retained legacy excess. The two per-enrollment classes each use a distinct pair count. A second row for the same pair cannot take a first-row slot from another enrollment.

Use the existing unique keys and the index over signed revocation epochs. Project how many rows a verified batch puts in each class. A reconciliation batch can include deliveries and signed revocations, so check every projected class before inserting a row. Count the first new canonical row for a retained epoch once within a batch. Check revision and scope as today. Duplicate/import operations that insert no row use no slot.

Keep the existing outer transaction around enrollment state, signed control, audit and checkpoint. Keep old rows, authority heads, acknowledgment heads and replay checks. A gateway delivery that runs out of refresh history budget must surface that condition and preserve the durable restriction. It must not present gateway acknowledgment as complete. Existing already-issued envelopes retain their current validity and retry conditions. This PR does not compact signed history.

## Upgrade from a full database

1. Open the existing journal through the authorized owner and validate its lease, identity, stored version and continuity checkpoint.
2. Read the existing tables under the new accounting. Opening the journal changes no rows, revisions, schema catalog or digest. A crash before the first write repeats the same classification.
3. Keep all stored rows, including legacy rows above a new non-reserved limit. Refuse only additional growth of that class. For example, 4,096 existing delivery rows keep delivery full, while first revocation of an admitted epoch can still commit in its reserved class.
4. Classify signed and recovered evidence already present for retained inactive enrollments in its respective first-row slot. Such evidence remains binding. Old excess history cannot use the reserve of a different pair.
5. On the first new write, enforce the class budgets and existing authentication in the same transaction. A failed insert, signing step or checkpoint leaves the existing rollback or recovery behavior intact. Preserve the configured budget across restart. Older runtimes retain their old admission rules, so only the upgraded runtime supplies the new capacity guarantee.

Reject unsupported schema versions and corrupt scope or evidence through the existing validation. This plan covers logical capacity. An actual disk-full or I/O error remains a storage failure.

## Regression and validation

- Start from the existing two-slot enrollment and gateway fixtures. At a full delivery budget, verify that an authorized first revocation commits the inactive epoch, signed control and audit entry. The same test should fail on main at the capacity check. Preserve the unmodified source baseline and report its actual rollback.
- Test verified recovered revocation for a retained epoch and unknown trust restrictions while the delivery class is full. Test that untrusted or wrong-scope evidence consumes no quota.
- Seed prior signed and recovered evidence for one retained epoch, then prove another epoch still has both slots. Run boundary cases for every class and a mixed reconciliation batch. Check that refresh, unknown evidence and non-revocation writes cannot spend another epoch's reserve.
- Reopen old-format full stores. Cover a schema without submission history and one with it. Check that the SQLite catalog, user version, existing signed rows and pre-write checkpoint digest match. Cover grandfathered excess, rollback, interrupted commit recovery and restart. Verify expired controls and old delivery cannot reactivate a revoked epoch.
- Verify the normal publisher can load and send an existing signed revocation after full-queue recovery and treats gateway acknowledgment as separate. No device, protocol or gateway-service source changes are planned for this PR.

Use the eight Core smoke classes, plus `GatewayAuthorityJournalTests`, `EnrollmentJournalTests`, `JournalDatabaseTests`, `CheckpointedJournalTests`, `AuthorityPhonePushRecoveryTests` and `AuthorityPhonePushRegistrationTests`. The last compiled inventory contained 509 Core and 18 built-app methods in the selected classes. With eight new Core tests the provisional selection is 517 Core and 18 built-app methods. Reconcile class weights, method count and any required integration coverage at compiled discovery.

| Forecast item | Seconds |
| --- | ---: |
| Existing class weights at 1.3 times the recorded total | 76.183 |
| New cases and migration fixture time | 120 |
| Optimized Core discovery and build | 420 |
| Debug and Release builds and 18 arm64 inspections | 660 |
| Runner and evidence | 180 |
| 94 Python manifest and selector checks | 180 |
| One predecessor comparison on the new regression | 480 |
| **Total** | **2,116.183** |

Proposed cap 3,000 seconds. Send the exact diff and compiled selection for the source-bound gate. This plan does not execute or qualify a migration.
