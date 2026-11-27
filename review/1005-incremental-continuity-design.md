# Authenticated incremental journal continuity

Design review for #1005, based on main `53c69c99b7f70cf369f3dff87cfaf116a682ff9f`. The scope is the Mac authority and its independently protected continuity store.

## Decision

Use ordered Merkle trees for the authority and ledger. Update the affected ranges to compute the tentative checkpoint. Keep complete verification of raw data before the write body and after the durable commit. Protected reads and recovery also keep complete verification.

A stored root can remain valid after someone edits an unrelated raw SQLite row. A proof for one key gives no evidence about that edit. Reducing the two complete checks would require a trusted mechanism that observes every mutation or a change to the integrity guarantee. The current protected lease remains necessary and supplies owner exclusion. It does not prove that the raw contents still match the checkpoint.

## What the checkpoint binds

- The independent checkpoint commits to the format, storage identity, schema, scope, both roots, checkpoint generation, authority generation, and audit epoch and head. The pending checkpoint names its exact predecessor. Only a change to authority evidence advances the authority generation. A format conversion with identical authority content preserves that generation.
- Commit to the supported schema tier, table domains, and the relevant schema objects. Bind column order, types, primary keys, constraints, and indexes used for decisions. Verify the catalog from the same SQLite snapshot as the data. Restrict triggers, migrations, and other writers to a reviewed inventory.
- Each tree commits to ordered ranges over a table's full primary key, including Mac and account. Each leaf covers a bounded number of rows and bytes. Its hash commits to range boundaries, row count, keys, and typed canonical row contents. Branches commit to child order and ranges. Validate bounds, continuity between ranges, counts, and endpoint coverage before using a tree. Use an explicit encoding for empty tables and for every field and node type.
- Store the tree nodes and a generation marker with the journal data in the same SQLite transaction. The independent checkpoint supplies the trusted root. A stored node is a proof input. Its own presence in the journal gives it no authority.
- Reads that authorize work check the actual database values. For a key or range, check membership, non-membership or completeness, as applicable. The replay nonce check needs coverage of its secondary key too. Bind an exact nonce-to-submission map and verify it against the raw rows. SQL index results alone cannot establish absence for replay.

The initial leaf format should reuse the current typed SQLite value encoding. Stream each leaf into SHA-256 and bound its memory use. A maximum-size legal row can occupy its own leaf. A full sweep verifies ordered raw rows against the anchored ranges, then rebuilds the observed table roots. Two full sweeps per successful write remain linear in the protected data size.

## Checks at the trust boundary

| Operation | What it authenticates | Before it returns or advances |
| --- | --- | --- |
| Protected point read, including trust and decision lookup | The complete raw snapshot and schema match the committed anchor. Check the requested key and exact value, or prove absence. | Bind the answer to the same transaction and scope. Keep the existing policy, signature, time, and admission checks. |
| Protected range read, including audit and outcome recovery pages | The complete raw snapshot plus the ordered interval. Check its boundaries and completeness, including an empty page. | Use the verified cursor and head. Recheck on a new snapshot when signing or delivery requires it. |
| Begin a checkpointed write | The committed anchor and the full raw pre-state, including schema, exact key order, roots, epoch and head. Confirm the generation and absence of unresolved preparation. | Use the existing exclusive journal owner and transaction boundary. Any mismatch stops before the body. |
| Build and prepare the candidate | Old proofs and actual new rows for every changed range, including deleted keys, inserts, changed primary keys, and affected nonce entries. Recompute the candidate roots and advance the generation once. | Re-read affected ranges in the write transaction. Commit data and nodes together. Compare-and-set pending in the independent store against the exact committed predecessor before the journal commit. No result leaves the owner here. |
| Verify the durable commit and finalize | A fresh read transaction over the durable journal independently verifies all raw rows, roots, catalog, generation, and epoch/head against pending. | Compare-and-set finalize in the independent store. Release the result only after finalization. Discard all verification state tied to the tentative transaction. |
| Recovery before reopening admission | Verify the protected stores, schema and format, actual raw rows, tree and roots, generation, audit boundary, and exact committed/pending relationship. Check the reader floor. | Finalize only a matching durable pending state. Discard pending only if the durable journal matches committed. Keep admission closed for ambiguity, integrity failure, and storage errors. |

The write-body optimization needs complete change coverage. Inventory the mutations in the existing journal APIs, including savepoints, indirect changes, and migrations. Every incremental path declares and checks affected keys and ranges. An unproven statement, migration, trigger, or cascade takes the full candidate verification path. The durable check still verifies the raw rows after every successful commit. If anything escapes the inventory, it must fail before finalization.

### Raw edits, stale data, and recovery

The sweep compares raw row encodings with the range commitments. A modified value fails the leaf comparison even if every stored node is intact. An inserted or removed row, moved key, or reordered proof fails the key, bound, count, or hash check. An edit and recomputed tree in SQLite still fail against the independent anchor. The same rules apply to data that the current command would never read. A read uses one SQLite snapshot. It cannot reuse a verdict or borrowed value from an earlier transaction or accept a replayed generation.

Each full check needs a snapshot that observes persistent changes even if an edit bypassed SQLite's change counter. Verify this with a fresh pager under the same protected lease. For durable verification, open a fresh read-only observer after the commit. In the fault test, change a row on an otherwise untouched page between transactions without updating the database header. A warm pager and an unchanged stored tree must never make that snapshot acceptable.

- Before prepare or after rollback, the raw pre-state must still match committed. If prepare was durable and the journal rolled back, verify committed before discarding pending.
- If the journal committed and finalization was interrupted, verify pending from the durable journal before finalizing. If storage cannot prove either state, fail closed. Preserve errors and retained evidence.
- Keep the existing distinction between authority damage and a loss of ledger history. A separate, explicit recovery path may record a history gap only after it proves authority and follows the required unresolved-outcome policy. It cannot treat missing replay evidence as a fresh namespace.
- The trust anchor is the separately protected continuity store. The proof verifies the observed snapshot under the existing storage ownership boundary. Rollback of both stores remains outside this local proof. Extending that guarantee would require an independent monotonic anchor.

### Migration and old readers

Require the supported owner, installed reader floor, and exclusive leases before migration. Close admission and verify the legacy checkpoint against all raw data. Build the new trees from exactly that verified snapshot. Prepare one migration candidate that binds the legacy predecessor and new roots. Verify all raw rows and the new catalog after the journal commit, then finalize.

Give both stores an explicit version boundary. A reader that cannot interpret the new pending or committed format must fail closed throughout the transition. The new reader supports recovery of the exact legacy predecessor and the new pending candidate. A supported rollback before the journal commit still requires a complete legacy match. A partially installed version or contradictory stores require recovery. Preserve the reader floor across restart and retain legacy checkpoint evidence for recovery and audit.

## Retiring consumption details

`consumptions_v1` uses an exact scoped request ID and rejects a duplicate before checking the one-million-row capacity. Outcomes reference that receipt. Startup scans the outcomes and settles authorized or executing commands. Command submissions separately reserve both the submission ID and nonce. These identities give no order from which to derive a safe deletion floor.

An authenticated tree can support compaction with a permanent exact replay set. Before retirement, keep a checkpointed membership record for every consumed request ID. Keep both submission IDs and nonces for command replay. Bind each key to its scope and purpose. Require proved absence across the live and retired evidence before any attempt to admit or consume. A missing, corrupt or unavailable proof fails closed. A digital signature or valid time window alone gives no absence proof.

Retire only detail whose outcome is final and whose request, execution, retry, recovery, and delivery owners have settled. Keep unresolved and uncertain outcomes in the live ledger initially. Preserve historical receipt and outcome behavior through a verified archive with read-through lookup. Retain the archive and its authenticated index before committing the deletion, and commit the replay record and live removal at the same boundary. Recovery must prove the old complete state or the new complete state, including archive availability and replay membership. Deletion of unneeded archive data awaits a separate retention decision.

The million-row limit can become a limit on live details after that path is proven and approved. The exact replay set still grows. Its own size limit and the command-submission cap need an explicit policy. A bounded replay set would need a new protocol namespace with authenticated retirement of old admissions, or another independently proved acceptance floor. Keep the current caps until those transitions are separately qualified.

## Delivery and evidence

Use the same warm benchmark fixture as #1057 on the same host. After pruning, keep 100,000 audit rows with matched consumption, outcome, and replay counts of 100,000 or one million. Compare the real write and its verification passes, protected reads, startup recovery, and peak storage and memory. The prior post-prune median write was 0.484 s and 3.768 s at those two sizes. The figures below are targets for review.

| PR | Scope | Required tests | Expected measurement |
| --- | --- | --- | --- |
| 1. Proof format and reference verifier | Add the ordered range format and a read-only fixture harness. Compare an incremental update to an independent rebuild. | Key ordering, empty leaves, splits/merges, malformed counts, membership/absence, missing rows, forged ranges and modified raw rows with unchanged roots. | At 100,000 and one million rows, measure full sweep, proof bytes, and touched-range update separately. Target bounded touched-row reads at both sizes. |
| 2. Explicit transaction coverage | Run the candidate root calculation in shadow mode against the existing journal on disposable fixtures. Keep the current authority boundary live. | Cover inserts, deletes, key changes, nonce uniqueness, cascades, schema change fallback, savepoint rollback, lost or extra mutations and rejected writes. | Show near-flat time for a fixed touched range as total row count grows. Report shadow overhead and full-fallback frequency. |
| 3. Checkpoint adoption and migration | Adopt the proven candidate calculation between the two full raw checks. Pair the new journal and continuity formats. | Raw tamper on an untouched key, stale snapshots, replayed roots, all prepare/commit/finalize cuts, format mismatch, old reader refusal, migration and restart recovery. | Target at least 10% lower median writes at both scales, under 0.436 s and 3.39 s on the prior fixture. Report read and restart cost separately. Approve activation only after parity and a repeatable gain. |
| 4. Replay-preserving detail compaction | Add exact retained identity evidence, the verified detail archive, and bounded idle retirement. Keep cap changes behind the final review. | Retry old requests and submissions on both sides of migration and immediately after each crash cut. Test missing archive, lost replay proof, ongoing work, old outcomes, both submission keys, and crossing the old cap. | At both scales, measure live rows reclaimed, replay and archive bytes, worst lock hold, and next valid admission. Confirm duplicate refusal after retirement and quantify the permanent storage growth. |

Production activation requires its own source-bound local gates and exact-current-head review.
