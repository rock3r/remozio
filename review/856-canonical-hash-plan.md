# Canonical journal hashing after audit retention

Source review of `53c69c99b7f70cf369f3dff87cfaf116a682ff9f`. The timings below come from the prior local benchmark for #1057. This review adds a proposal.

## Issue boundaries

**#856** covers the cost of the existing canonical hash. #1055 reduced encoding overhead, and #1057 limits audit growth. One digest still reads all rows. Each checkpointed write still verifies the old state, hashes the tentative state, and verifies the durable state independently. The next change should reduce work per row while preserving every byte and all three passes. The three large tables already had zero SQLite sorts in the benchmark.

**#1005** covers authenticated incremental verification and the work to address the existing consumption cap. It needs a design that detects raw row changes even when a stored root stays the same. It also needs to preserve replay refusal and outcome evidence across recovery, mixed-version startup, and migration. That work determines whether the authority can retire consumption records safely.

## Next PR

**Start with `command_submissions_v1`.** It is the largest table with a fixed-width row. Its six BLOBs have lengths 16, 16, 16, 32, 16, and 32 bytes. In `JournalContinuityDigest.swift`, keep the current catalog, column metadata, explicit order, and SHA-256 inputs. For that exact column order, add a path that checks each BLOB's storage class and length, then reserves scratch space once for the entire 183-byte encoded row. Copy SQLite's borrowed bytes before stepping the statement. Route other layouts and rows through the existing encoder. Preserve its storage errors and unsupported-type rejection. Keep the generic path for both consumption tables.

**Tests.** Extend `CheckpointedJournalTests.swift` to compare the specialized and previous digests over the same journal. Cover empty tables, multiple rows spanning the scratch boundary, key order, altered column order, and rows with a different type or length. Confirm that an unsupported SQLite value still fails. Run `CheckpointedJournalTests`, `JournalDatabaseTests`, and `ConsumptionJournalTests` for existing checkpoint, rollback, and recovery coverage. These are the only two files planned for changes.

**Measurement.** Repeat the same warm synthetic benchmark on the same Mac. Retain 100,000 audit records and match the consumption, outcome, and replay counts at each size. Alternate baseline and candidate runs. Record per-table costs and wall time for the real checkpointed write alongside the three digest passes.

| Consumptions | Prior digest pass | Prior replay table profile | Estimated saving per pass |
| --- | ---: | ---: | ---: |
| 100,000 | 159–165 ms | 39.5 ms | 3–8 ms |
| 1,000,000 | 1.246–1.259 s | 397.7 ms | 30–80 ms |

The estimate assumes the specialized path saves roughly 8–20% of replay-table time. SQLite still reads the same rows, and SHA-256 still receives the same bytes. Require equal digests and a repeatable reduction in checkpointed write time before shipping. Use the result to decide whether another canonical optimization is worthwhile for #856.
