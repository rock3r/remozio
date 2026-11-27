# Permanent replay protection and detail retirement

Plan for the replay retirement slice of #1005. Base `53c69c99b7f70cf369f3dff87cfaf116a682ff9f`. Scope is the macOS authority journal and its continuity checkpoint. This plan keeps the flat digest and every existing verification pass.

## Replay protection

- Add two exact, scoped SQLite sets. Key the first by Mac, account, and consumed request ID. Key the second by Mac, account, and command submission ID, with a unique scoped nonce. Include both tables and their schema in the existing authority digest. The independently protected checkpoint already binds that digest.
- Under the exclusive owner with admission closed, verify the complete predecessor and seed both sets from that snapshot. Validate field sizes, membership, nonce uniqueness, and counts. Pair the new schema and checkpoint tier with the installed reader floor. Verify the durable candidate before finalization. At restart, only the exact predecessor or the exact candidate can finish migration. A damaged legacy ledger cannot seed a complete set. Older owners must refuse the new tier. Seed promises lifetime coverage for the existing account only when the verified legacy journal has continuous consumption history. The shipping recovery path in `JournalHistoryRecovery.resume` writes a recovery epoch and a durable `history_recoveries_v1` record. Refuse migration if recovery is pending, reconciliation reports a discontinuity, or the verified predecessor has a recorded history gap. Test both unresolved and finalized gaps. Once seeded, later ledger-only recovery preserves the lifetime set because it must match the authority digest.
- Store the consumed ID in the same transaction as its receipt. Have both `ApprovalRequestCoordinator.admit` and `ConsumptionJournalTables.consume` check the consumed ID set. Reserve the command submission ID and nonce atomically with command admission. Both predicates read the exact set. A valid fresh request or submission follows the existing signature, scope, and policy checks.
- Cover permanent keys in the authority digest because `JournalCheckpointRecoveryPolicy` can permit a ledger history gap when authority evidence still matches. That path must retain the verified keys. Missing or changed keys require repair with admission closed. A newly consumed ID now advances the authority generation. The generation audit below names its consumers and the required isolation tests. Once active, removal of ledger details alone leaves that generation unchanged.
- Move any live command reservation details still needed by callers into a separate ledger table. Keep all six existing fields accessible during the transition. The permanent set carries only the four identity fields. Retire old details only after the caller audit and the eligibility checks below. Implement shared schema additions without changing the behavior of the Linux fixture or enabling Linux activation.

## Authority generation

| Source at the base | Generation or revision used |
| --- | --- |
| `AuthorityJournal.prepareRequests` and `JournalStartupRecovery.start` | The new restart epoch descriptor binds the committed authority generation during startup. Existing live request entries use their retained request identity and clock epoch. |
| `AuthorityJournal.requireDispatchRevision` and execution outcome writes | Dispatch compares the target request's exact receipt, phase, and outcome revision. It does not compare the authority generation. |
| `JournalTransaction.approvalTrustSnapshot`, command execution trust, and gateway recovery checks | Trust compares its own enrollment and policy revision and scope. Preserve those explicit comparisons as the checkpoint advances. |
| `ContinuityCheckpoint.successor` and `ContinuityState` | Succession advances the checkpoint generation on every commit. It advances the authority generation only when the authority digest changes. Preserve pending-candidate validation. |
| `HistoryRecoveryIntent`, `JournalHistoryRecovery`, and `ContinuityStore` | Recovery binds the generation from the verified predecessor or pending authority evidence. A missing permanent key cannot select ledger-only recovery. |
| `MachineUpdatePolicyIntentRecord` and the retained Setup policy and completion intent records | Update intents bind their exact predecessor and require the prescribed successor checkpoint and authority generations. Keep their startup isolation and stale-intent behavior. |

Use a paired, checkpointed fixture with a pending request and a separate authorized command. Consume an unrelated request after command preparation and before dispatch. Verify the authority generation advances and the other pending request remains usable. Verify that the prepared command still passes trust and receipt revision checks and can dispatch. Repeat while a real account update drain blocks new admissions but permits previously admitted work. If the generation change invalidates either operation, stop and review a separate replay generation before altering any consumer.

## Requirements and tests

| Requirement | Required test |
| --- | --- |
| The checkpoint covers both replay sets. | Seed from a real legacy fixture. Reopen at each prepare, SQLite commit, and finalize interruption. Verify exact legacy or exact migrated membership and no admission on ambiguity. Use the actual predecessor reader built from the pinned release source and a journal produced by that tier. Prove it first accepts the predecessor, then refuses the migrated fixture before mutation. A feature flag in the new reader cannot substitute for that check. Remove or change one permanent key in disposable test data and prove that recovery requires repair. With a ledger-only history gap and matching authority, prove that replay remains refused. |
| Replay refusal depends only on set membership. Archive loss affects only historical detail reads. | Retire a request with a settled outcome and retry with valid current admission inputs. Verify refusal through both draft admission and signed consumption. Run with a history provider that returns unavailable if queried. A fresh request succeeds and both replay checks make zero history calls. Verify that an archive-backed historical read with its archive missing returns unavailable, while the archive-free lookup returns retired. |
| The existing exclusive owner retires details. It checks idle under the same lock used for the write, as in #1057. | Hold request, exchange, native execution, deferred preparation, and drain guards in turn and verify that retirement makes no changes. Race admission against the idle check and show serialization across the entire write. Interrupt the write at each checkpoint boundary and verify membership and coherent receipt/outcome pairs after reopen. |
| The nonce is kept permanently. | Retire command details, close and reopen the journal, then submit a fresh submission ID, request ID, and capture with only the old nonce reused. Assert replay refusal and no new reservation or request. Also test the inverse with an old submission ID and a fresh nonce, and a control with both keys fresh. |

For the archive-loss row, exercise the historical lookup contract with a test provider. The archive-free macOS release does not need a production archive or a second storage backend.

## Archive-free decision

Prefer deleting eligible final details. The source audit at the base found no macOS production path that needs their contents after the final outcome and the release of all owners. Preserve explicit status for historical consumers and retain unsettled or uncertain outcomes.

| Reader at the base | What must survive retirement |
| --- | --- |
| `ApprovalRequestCoordinator.admit`, `ConsumptionJournalTables.consume`, and `CommandSubmissionReplayTables.reserve` | These are admission and replay checks. Use exact membership. Keep submission ID and nonce checks independent. |
| `AuthorityCommandAuthorizationNotice.withValidatedCommandExchange`, `ApprovalRequestCoordinator.authorizedCommandApproval`, `takeAuthorizedCommandExecution`, and `AuthorityJournal.requireDispatchRevision` | These authorize live execution. Keep authorized and executing rows, and every row still used by an owner. Startup `JournalDatabase.reconcileInterruptedConsumptions` must continue to see unresolved rows. Retain unknown outcomes under the initial policy. |
| `ApprovalRequestCoordinator.exchangeRequest` | The signed exchange uses current in-memory request state. Keep details while any retained request can answer. Preserve the existing response for an absent request. Exposing retired to a remote client would require a separately reviewed authenticated protocol change. |
| `ApprovalRequestCoordinator.historicalOutcome` and `JournalTransaction.commandSubmissionReservation` | The command authorization notice reads the immediate live outcome. The other observed consumers are tests or experiment fixtures such as `LiveCommandFixture` and `ApprovalFlowPeer`. Give local receipt, outcome, and submission lookups explicit present, retired, and absent results. Update callers deliberately and keep the existing scope checks. A retired ID must never look eligible for admission. |
| `AuthorityJournalCutoverInspection` | Preserve the validated scan for live outcomes and keep unknown counts and startup recovery decisions intact. Report live count and a separate checkpointed retired count if the summary needs the lifetime total. Validate the split in the cutover tests before enabling deletion. |

Use canonical outcome decoding, including an initial decline without a separate outcome row. Start with verified final success, failure with a verified result, and decline. Include cancellation only when durable evidence proves no dispatch. Keep ambiguous rows and rows with any active request, retry, result, release, or recovery owner. Use one checkpointed retirement watermark. Under the idle lock, record the first verified settlement with the scoped key, canonical terminal outcome revision, and independently verified committed `ContinuityCheckpoint.generation` of that snapshot. Before deleting, verify that the marker survived finalization, the current committed generation is strictly newer, the terminal revision is unchanged, and all live-owner checks still pass. Selection and marker insertion cannot retire the same row in one transaction. Missing, stale, or uncertain marks restart observation. Wall time only schedules scans.

Delete outcome then receipt in one checkpointed write and leave the permanent keys in place. Report retired when the verified history proves that detail could only have gone through retirement. After a history gap, return unavailable for a known ID whose missing detail could be due to that gap. Test this distinction and keep admission tied to permanent membership. Keep audit records under #1057's separate retention policy. If a supported reader needs durable final details, defer deletion for that reader until its contract is resolved. Any later archive would serve historical detail only. Failure to open it would return unavailable for those reads and would have no effect on admissions, checkpoint recovery, or replay checks.

## Capacity and idle policy

Use separate exact counters for consumed request IDs and command reservations per Mac and account. Derive and verify the counters during backfill and recovery and update them with the corresponding set in each checkpointed transaction. A command reservation counts once and retains both keys. A cap check must not scan a million rows on each admission.

| One row in each set | Row field bytes | Nonce index key bytes | Combined bytes before SQLite overhead |
| --- | ---: | ---: | ---: |
| One consumed ID and one command reservation | 48 + 80 | about 80 | about 208 |
| 1 million of each | 128 MB | about 80 MB | about 208 MB (198 MiB) |
| 10 million of each | 1.28 GB | about 800 MB | about 2.08 GB (1.94 GiB) |

The consumed key contains two 16-byte scope values and one 16-byte request ID. The command key adds a 16-byte submission ID and a 32-byte nonce to that scope. The estimate assumes primary-key storage in `WITHOUT ROWID` tables and a secondary nonce key carrying the submission ID. Measure real table and index pages. Record headers, page slack, WAL, migration overlap, and live details are extra. The sets grow independently.

Propose a format limit of 10 million entries in each set and an initial supported cap of 2 million each, subject to the 2-million gate below. Keep the existing 1-million caps until the new tier qualifies. Warn at 80% and fail closed for new entries at the supported cap. Keep denying known replays and keep existing settled reads available. Run a capacity test with small injected limits and a production-shaped fixture that crosses the old cap. No age, retirement, or disk-pressure path removes identities. If the 2-million gate fails, leave the new tier disabled. Advancing further requires a new benchmark and a reviewed cap change.

In the existing maintenance lane, try one bounded batch at a time. Start retirement near 800,000 live consumption rows and work toward 100,000 eligible details remaining. Keep the current 1-million live-detail guard until capacity behavior is proven. Reuse #1057's nonblocking lock and idle predicate under that lock, including update drain, suspended or stopped modes, the worker and native execution owners. Hold ownership through selection, revalidation, deletion, and finalization. Skipped ticks do no work. Compare 1,000, 10,000, and 50,000 eligible rows per batch before selecting a limit and cadence. Report protected excess and repeated skips. For scale, removing 700,000 rows at 10,000 per eligible minute would take at least 70 minutes. An account that stays busy or retains many protected rows can still hit its live guard.

## #1057 benchmark forecast

Use the retained #1057 results as the baseline. The fixture has 100,000 audit rows after pruning and equal counts of consumed requests, outcomes, and command submissions. The figures below are estimates for the specified data shape. They are not test results for this plan.

| Shape after maintenance | #1057 digest pass | #1057 median write | Forecast digest pass | Forecast median write |
| --- | ---: | ---: | ---: | ---: |
| 100,000 used IDs and submissions, 100,000 live receipts and outcomes | 0.159–0.165 s | 0.484 s | 0.16–0.21 s | 0.49–0.65 s |
| 1 million used IDs and submissions, 100,000 live receipts and outcomes | 1.246–1.259 s at 1 million live | 3.768 s at 1 million live | 0.50–0.85 s | 1.6–2.7 s |

The 1-million #1057 instrumented profile spent 517 ms on receipt rows, 389 ms on outcomes, 398 ms on full command submission rows, and 46 ms on audit records. Estimate 140–280 ms for the compact consumed set and 220–360 ms for the compact command set at that scale. Add the retained detail and audit costs and allow for decoding and locality. Three digest passes per write remain. Until retirement catches up, test the higher-cost state with a million live details and the permanent sets also present. Retained command detail can raise that cost further.

The observed #1057 audit batch took 0.668 s at 100,000 and 5.068 s at 1 million. Plan for 5–7 s for the first 10,000-row retirement batch near the trigger. Measure total lock hold and separate planning, row deletions, and the fixed digest and checkpoint work at 1,000, 10,000, and 50,000 rows. Choose the batch and cadence from these measurements. If the fixed cost alone exceeds the provisional 8 s lock-hold budget at the supported cap, keep retirement disabled there. Protected reads and full sweeps still scale with rows. A linear extrapolation of the compact membership cost alone at 10 million is 3.6–6.4 s per pass. Three writes can therefore consume most of the existing 60 s budget before reads or other work. Do not activate 10 million based on that estimate.

At 100,000, 1 million, and 2 million per set, measure three warm repeats on the #1057 host with a fixed audit count. Capture each digest pass, protected reads, write and maximum retirement lock time, startup/recovery, growth on disk and peak WAL and RAM. At scale, cover a full live backlog, partially retired data, and 100,000 live details. Report the first valid admission past the old cap and refusal of nonce-only replay after restart. At the legacy 1-million limit, measure the migration separately. Report seed and durable verification times, the full time with admission closed, and peak WAL including overlap and crash recovery. Report peak rollback journal bytes too when the store uses rollback mode. For the 2-million cap require the longest supported approval path, including time queued behind a retirement batch, to finish within 30 s in those fixtures. A separate 10-million fixture measures the slope without enabling the cap.

## Delivery order

1. Add the checkpoint tier, seed and validate the permanent sets, and switch replay reads and writes together. Keep legacy caps and retain details. Qualify migration, reader refusal, recovery, and generation behavior before merging.
2. Add typed historical results and archive-free retirement under the existing idle owner. Keep retirement disabled until the reader audit, crash tests, and #1057 measurements pass. Verify both unretired and retired paths.
3. Enable the qualified bounded policy and cap. Require a source-bound benchmark, the approved test selection and time cap, and current-head review before activation. Keep the 10-million ceiling as a format limit.
