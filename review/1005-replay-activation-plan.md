# Permanent replay activation plan

PR 3 for [#1005](https://github.com/rock3r/remozio/issues/1005). Builds on [#1058](https://github.com/rock3r/remozio/pull/1058) and [#1060](https://github.com/rock3r/remozio/pull/1060).

| Slice | Production change after qualification | Required evidence |
| --- | --- | --- |
| 3a | Install format 20 at protected startup with the final reader floor and exact counters. Keep the cap at one million per set and leave retirement scheduling disabled. | Verify migration, counters, legacy gap handling, and startup recovery. Measure both steady-state shapes, the digest cost, and startup counter verification at one and two million keys per set. |
| 3b | Enable one qualified idle batch and raise the supported cap to two million per set. | Use the 3a digest measurements as an entry check. Pass the lock, queued approval, and capacity gates in sections 3–5 on the final source. |

## 1. Install format 20 before opening admission

The protected installed Authority startup owns migration. It calls `AuthorityJournal.installPermanentReplay` on the exclusive journal after reconciliation and self-validation, before `AuthorityService` calls `prepareRequests`. The installed startup supplies the release authorization. The generic service, health-only, completion-only, and retained Setup paths do not acquire that authorization. The wake service starts its listeners and command receiver only after migration and request recovery finish.

Require the durable signed release record and generation floors for both Authority and Setup. Use the first installed release qualified against the **final** format 20 catalog, including the retirement and counter definitions. Earlier manifests can advertise format 20 without reading that catalog. The format 20 installer has no production caller on the base from #1060. The counter definitions can therefore enter format 20 before its first installed writer. Qualify both the floor and rollback with the final 3a catalog, including its counters. Verify the signed roles, their reader and writer capabilities, and the rollback floor under the existing update admission barrier. The supported rollback release must read the final catalog too. Keep admission closed through seed, the independently verified journal commit, checkpoint finalization, and startup health. Use the committed release and floors after a restart. [Journal startup](../macos/core/Sources/RemozioCore/AuthorityJournal.swift), [request service](../macos/core/Sources/RemozioCore/AuthorityService.swift), [installed wake service](../macos/core/Sources/RemozioCore/AuthorityWakeService.swift), [release compatibility](../macos/core/Sources/RemozioCore/ReleaseCompatibilityPreflight.swift)

| Startup result | Action |
| --- | --- |
| `.installed` | Verify and finalize the candidate, then run normal request recovery before admitting work. |
| `.alreadyInstalled` | Validate the exact catalog and counters before request recovery. The installed format and floor still apply. |
| `.legacyHistoryGap` | Leave the journal on its existing legacy format, normally 19. Continue legacy startup with the current one-million limits. Keep retirement disabled for that account. |
| Unresolved gap, invalid floor, counter mismatch, or ambiguous boundary | Keep admission closed and let existing reconciliation or repair resolve the evidence. Never use a partial seed. |

Preserve the legacy history distinction in [#1059](https://github.com/rock3r/remozio/issues/1059). A finalized gap leaves the account on legacy rules. An unresolved history recovery still blocks ordinary startup. If qualification fails, leave the writer disabled on legacy installations. Once format 20 commits, recovery must recognize the exact predecessor or candidate. A scheduler switch can stop retirement while preserving format 20 and its permanent keys. An older writer cannot take over.

## 2. Count permanent keys in the checkpointed transaction

Use one authenticated counter row per Mac and account, with separate counts for consumed request IDs and command reservations. Count a submission and its nonce once. Keep the counter definition in the exact format 20 catalog, under the authority digest with the permanent keys. Include the definitions in the format 20 seed while the format is dormant. Check their exact DDL and reject secondary indexes and triggers under the catalog guard. Test schema changes and incorrect counts.

| Operation | Counter rule |
| --- | --- |
| Seed | Derive both counts from the verified predecessor and compare them with the inserted keys. Validate scope and the exact submission-to-nonce mapping. Commit the counts in the same checkpointed write. |
| Admission or signed consumption | Check scoped primary-key membership first, then use the exact count for the appropriate cap. Insert the new key and increment its count once in the same transaction. A command inserts both keys and increments one count. |
| Rejection, retry or interruption | An existing key still rejects as replay, even at capacity. A rollback leaves the count and keys at their prior boundary. Recovery verifies the exact candidate or predecessor against the durable checkpoint before enabling admission. |
| Startup and history recovery | Independently compare both retained counts with their actual key sets and verify the bidirectional command mapping. A mismatch requires repair. History recovery cannot lower a permanent count from a partial ledger. |
| Detail retirement | Keep both permanent counts unchanged. Enforce the separate live-receipt guard with exact ledger accounting. Deletion changes the live count in the same transaction. |

Keep the current cap paths for legacy journals. The normal format 20 path must use a primary-key read and a bounded counter update where the permanent set currently uses `COUNT(*)`. Keep the existing full checkpoint verification. Counts and triggers for maintenance may be evaluated under the idle owner. Test threshold crossings, scope isolation, duplicate ID and nonce, every checkpoint interruption, corruption, and concurrent admission. Compare live count with retained receipts during verified startup. A missing counter must fail closed and must never be treated as zero.

## 3. Schedule one idle turn at a time

Use the existing Authority idle maintenance lane on a **60-second cadence**. Start at **800,000 live receipts** and continue toward **100,000**. Keep the existing one-million live receipt guard. A blocked or busy turn ends without work. When both audit and detail maintenance are eligible, alternate so neither starves. Do not run concurrent maintenance or a catch-up burst. Yield to queued approvals and recheck the request, exchange, native execution, update drain, and release activity guards under the existing nonblocking owner lock. Keep the lock through the full checkpointed batch. The time interval schedules work; it never proves that a row can be deleted.

Gate 7946 ran on `4adf5790` with one million live receipts, outcomes, and reservations, 50,000 linked submissions, and 100,000 audit rows. Each figure is the median of three samples unless marked max. Details in [PR #1060](https://github.com/rock3r/remozio/pull/1060).

| Batch | Observe lock | Retire lock | Retire max | Approx. rows per lock-second for an observe/retire pair |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 8.02 s | 8.06 s | 8.24 s | 62 |
| 10,000 | 8.33 s | 8.30 s | 8.31 s | 601 |
| 50,000 | 9.87 s | 10.36 s | 10.57 s | 2,471 |

Test **50,000** as the preferred batch. It retires five times as many rows as 10,000 for about two extra seconds per turn. This amortizes the roughly 8-second fixed cost, which includes about 0.12 seconds for the receipt count. At one eligible turn per minute, 700,000 rows take about 28 turns if all are eligible. Alternating with audit, protected rows, load, and restart can extend that time. Preserve the checkpointed mark and let a later turn prove the same revision and epoch before deleting. Use the current cursor semantics and retain legacy reservations without a durable submission link.

The observed fixed cost reached 8.19 seconds. The earlier 8-second lock estimate helped set the provisional policy. The activation gate now requires a maximum lock hold of **12 seconds for any single observation or deletion turn**, and a maximum of **30 seconds for every approval**, including one queued behind a batch. Both limits apply at one and two million permanent keys per set. Qualify 50,000 first. If either limit fails, measure 10,000 against both limits. If 10,000 fails, keep scheduling disabled. The 1,000-row measurement explains the fixed cost and throughput tradeoff. In 3a, time one digest pass at one and two million permanent keys per set, with the live detail and audit counts held fixed. Use the observed fixed work to estimate the two-million lock floor. If the fixed work alone exceeds 12 seconds, 3b cannot start. Reduce digest cost first. Review the #1005 variant that removes the sweep before the write body only with evidence that it preserves the retained integrity guarantees. Changing the batch cannot remove fixed work. Log repeated skipped turns and protected excess. They can cause the live receipt guard to fill even when there is room for permanent keys.

## 4. Measure the approval waiting behind maintenance

Use the real installed Authority journal path and its current authenticated admission and signed approval exchange. Prepare a valid synthetic request and create a deterministic latch after maintenance holds the owner lock and passes its idle check. Start the caller immediately after that latch, before the batch releases the lock. Use the production admission and decision paths. Do not simulate the lock with a sleep or subtract pending time from the approval result.

For both one and two million permanent keys per set, test the maximum supported live receipt backlog, a partially retired ledger, and the 100,000-detail steady state. For the full backlog, start close enough to the one-million live guard to exercise the cost while leaving room for the measured admission. Keep audit rows fixed. Include both observation and deletion turns with the preferred batch, and a no-maintenance control on each fixture. Bind the report to the actual signed build, source tree, fixture shape, and selected batch. Run at least three repeats per cell, include a cold startup/recovery run, and report the maximum as well as the median. Exercise both fresh command admission and a prior retained request when the idle contract permits it. When retained work keeps maintenance from starting, verify that it skips the turn.

Measure time from arrival at the Authority endpoint, before lock acquisition, through the verified durable response. Record the lock wait, admission write, signed decision and checkpoint completion, and any timeout or refusal. Include the longest supported approval path. The harness sends the decision promptly after admission so the run measures system latency. Require **every measured approval to finish within 30 seconds**, including the maximum approval that waits behind a batch at one and two million. Also require that every batch releases the lock within 12 seconds. Keep the existing 60-second service budget. Verify a queued caller gets service before the next maintenance turn. A batch that meets the average and misses either maximum fails qualification. Recalculate the approval budget with the write time measured at two million. Use that time with the measured lock wait and other approval costs.

## 5. Qualify the two-million supported cap

Set the proposed supported cap to **2,000,000 per permanent set**, independently. Keep the existing one-million caps until the two-million gate and reader-floor exercise pass. Ten million is a future format ceiling from the design. This plan neither enables it nor claims it is supported.

- At **80% (1,600,000)**, emit a bounded capacity warning for the affected set. Include which set is approaching capacity and its remaining capacity, with no request identifiers. Keep accepting valid new work while both relevant guards have room.
- At **100% (2,000,000)**, reject a new key in the full set without partial reservation or admission. Keep refusing replays and serving permitted historical reads. The other set keeps its own limit. Retirement cannot free permanent slots. Recovery for an account that exhausts its permanent capacity is outside scope. [#1061](https://github.com/rock3r/remozio/issues/1061)
- Qualify below, at and above the old one-million limit, then at the warning threshold and at the boundary of the new cap. Include a real first successful admission past one million, exact fills, one extra key, a nonce-only replay and an ID-only replay after restart. Use small deterministic capacity tests and a separate large-fixture exercise.
- Measure closed-admission migration, reopen and recovery, disk growth and free-space headroom, rollback journals or WAL, and peak RAM. Report the startup comparison of the counters and retained keys separately at one and two million per set. Verify old-reader refusal, current reader and Setup compatibility, rollback behavior, crash boundaries, and archive-free history. The benchmark must pass the 30-second approval gate and the separate retirement lock gate before enabling retirement. If two-million qualification fails, leave the expanded cap disabled.

## 6. Forecast the steady-state write

Use **3.768 seconds** as the existing full-detail median from #1057. It had one million live receipts, outcomes, and reservations plus 100,000 audit rows. Compare the same real checkpointed write on the same host with one million permanent request keys and one million permanent command reservations, including both permanent command tables, and 100,000 live receipts and outcomes.

Gate 7946 measured roughly 7.70–8.19 seconds of fixed maintenance cost including the receipt count. One verified planning read plus the three write verification passes make about four digest passes under that lock. As a rough proxy, take the fixed cost minus the roughly 0.12-second count, divided by four, which gives about 1.90–2.02 seconds per pass including other fixed work. The prior profile attributed 0.517 and 0.389 seconds per pass to a million receipts and outcomes, and 0.398 seconds to a million full command rows. A reduction to 100,000 rows saves about 0.82 seconds for receipts and outcomes, plus up to 0.36 seconds if the linked command details also shrink. The counter removes the admission count scan. It does not replace full digests.

| One-million permanent shape with 100,000 receipts and outcomes | Proposed median write forecast | Compared with 3.77 s |
| --- | ---: | --- |
| About 100,000 remaining command details | 2.3–2.9 s | About 0.9–1.5 s faster |
| About one million command details because many legacy reservations have no link | 3.4–4.0 s | Similar, with a possible regression |

These are forecasts. Gate 7946 measured maintenance on a synthetic full backlog. In 3a, measure both shapes on the real service while test fixtures prepare the two retained-detail counts. Also measure the digest pass and startup comparison at one and two million permanent keys per set. The two-million fixture is qualification input while the supported cap stays at one million in 3a. Time each verified digest pass, counter lookup, SQLite mutation, commit and finalization separately. Record exact live command detail counts. Retain the actual terminal, raw timings, source identity and receipts before using the measured forecast for 3b.
