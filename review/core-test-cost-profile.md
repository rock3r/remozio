# macOS Core test costs

This is a measurement plan for [#812](https://github.com/rock3r/remozio/issues/812), based on main at `8930647a`. Both retained local runs used optimized arm64 macOS Core and three concurrent shards. The records give per-case elapsed time. They contain no Core XML or fixture phase timings.

| Gate | Source | Passed | Skipped | Sum of passing cases | Longest shard |
| --- | --- | ---: | ---: | ---: | ---: |
| 7999 | `fd6eed41` | 8,103 | 3 | 4,310.431 s | 1,472.027 s |
| 8022 | `a87998f5` | 8,105 | 3 | 4,333.564 s | 1,498.462 s |

Case times overlap across shards. They include fixture setup, test code and teardown. They measure neither CPU time nor the critical path. Shares use the sum of passing cases. The three intentional skips are excluded.

| Class | Passed methods in 8022 | 7999 seconds | 7999 share | 8022 seconds | 8022 share |
| --- | ---: | ---: | ---: | ---: | ---: |
| `RuntimeMaintenanceStartupRecoveryTests` | 145 | 427.239 | 9.91% | 425.424 | 9.82% |
| `MachineUpdateReplacementTests` | 238 | 382.189 | 8.87% | 391.398 | 9.03% |
| `RuntimeMaintenanceExplicitRestorationTests` | 66 | 173.982 | 4.04% | 175.349 | 4.05% |
| `SetupOrphanRecoveryOperationsTests` | 39 | 131.812 | 3.06% | 133.646 | 3.08% |
| `RuntimeMaintenanceRestartRestorationTests` | 51 | 126.928 | 2.94% | 128.048 | 2.95% |
| `MachCommandCallerReceiverTests` | 347 | 127.697 | 2.96% | 127.500 | 2.94% |
| `RetainedSetupRuntimeSequenceTests` | 22 | 102.652 | 2.38% | 102.083 | 2.36% |
| `SetupRetainedOrphanClaimTests` | 42 | 87.969 | 2.04% | 88.822 | 2.05% |
| `SetupExecutorAdmissionOwnerTests` | 23 | 66.230 | 1.54% | 66.657 | 1.54% |
| `SetupMaintenanceRecoveryScopeTests` | 24 | 60.843 | 1.41% | 61.732 | 1.42% |
| **Top ten** | **997** | **1687.541** | **39.15%** | **1700.659** | **39.24%** |

## Compare six and eight shards first

The gate Mac has 10 cores (8 performance and 2 efficiency) and 64 GiB of RAM. Use gates 7999 and 8022 as the historical three-shard baseline. Their source revisions differ from `8930647a`. Gate 8022 has eight fewer Core cases than the source inventory for `8930647a`.

Run the full Core suite at `8930647a` with six shards and then with eight. Run one configuration at a time under the native validation lock. Use the same optimized binary, weights and intentional skips. The standard runner must verify every expected test exactly once. Record the test bundle digest and compare complete case outcomes between configurations.

| Concurrent shards | Longest shard from reassigned 8022 case times | Proposed runner elapsed | Cap |
| --- | ---: | ---: | ---: |
| 6 | 754 s | 750–1,250 s | 2,400 s |
| 8 | 559 s | 560–1,100 s | 2,400 s |

The reassignment uses the repository splitter and the measured durations from gate 8022. It does not model contention, changes in CPU frequency or the eight new cases. Record build and per-shard wall time, overall elapsed time, failures and timeouts. Sample the concurrent sum of XCTest RSS every two seconds and retain the peak sample. The sum can count shared pages more than once and can miss a peak between samples.

If the higher count materially reduces wall time and retains the expected outcomes, propose a local gate change for that count. One run per configuration can uncover failures and timeouts. It cannot establish a flake rate. GitHub CI concurrency is a separate decision.

### Measured result

Both runs used the same binary at `8930647a`. Each run recorded 8,113 passes and three expected skips. The exactly-once guard passed. No test timed out, and no outcome differed. These were sequential runs on the same host.

| Shards | Runner elapsed | Fastest shard | Slowest shard | Peak sampled XCTest RSS |
| --- | ---: | ---: | ---: | ---: |
| 6 | 821.750 s | 2/6 at 762.216 s | 4/6 at 808.237 s | 1,417.9 MiB |
| 8 | 650.173 s | 5/8 at 587.432 s | 3/8 at 638.377 s | 1,575.7 MiB |

Eight shards reduced elapsed time by 20.88% compared with six. The historical three-shard maxima were 1472.027 s and 1498.462 s. Those values are shard elapsed times from earlier source revisions.

The comparison below includes the slowest cases that passed in both configurations and had a historical result.

| Test | 7999 | 8022 | 6 shards | 8 shards |
| --- | ---: | ---: | ---: | ---: |
| `MachineUpdateReplacementTests/testCompletionPublicationStorageRetainsOnlyTheExactRecordedPlan` | 47.479 s | 48.557 s | 49.505 s | 51.663 s |

## Separate fixture and test costs

Measure the median-duration case from each class and three slow cases with distinct behavior. Each selector below uses the `RemozioCoreTests.` prefix. These timings are from gate 8022 and forecast the sample size only.

| Selector suffix | 8022 case seconds | Path to measure |
| --- | ---: | --- |
| `RuntimeMaintenanceStartupRecoveryTests/testSupervisorCloseDuringBeforeRPCVerifyReopenFailsClosed` | 2.659 | Supervisor reentry |
| `MachineUpdateReplacementTests/testCompletionPermitRejectsAnotherThreadAndConsumesAFailedAttempt` | 1.114 | Completion fixture |
| `RuntimeMaintenanceExplicitRestorationTests/testActorReentryBeforePendingSecondReconnect` | 2.614 | Explicit restart fixture |
| `SetupOrphanRecoveryOperationsTests/testNoCompletionIsNotApplicableToAdoptionAfterSuccessfulClaim` | 2.345 | Stopped orphan and maintenance writer |
| `RuntimeMaintenanceRestartRestorationTests/testBusyAccountDrainClosesTheRefusedAttemptWithoutRpcOrAWriter` | 2.469 | Restart fixture and drain |
| `MachCommandCallerReceiverTests/testRegistryReentryClosesOnlyASeparateIncomingTransferAndCloseCancelsAssembly` | 0.052 | Registry and cancellation |
| `RetainedSetupRuntimeSequenceTests/testAssemblyRejectsAnotherActualInventoryBetweenLoansAndPoisonsTheContext` | 4.205 | Two nested retained fixtures |
| `SetupRetainedOrphanClaimTests/testDeinitRightsReturnIsRequiredAfterStatusAlreadyShowsOrphan` | 2.071 | Orphan frame and rights return |
| `SetupExecutorAdmissionOwnerTests/testCloseWhenIdleWaitsForTheActualAuditBody` | 0.365 | Admission owner and audit body |
| `SetupMaintenanceRecoveryScopeTests/testPersistentOwnerCleanupUsesBackoffCappedAtThirtySeconds` | 2.040 | Recovery scope and injected clock |
| `RuntimeMaintenanceStartupRecoveryTests/testAJobWithoutALivePidDoesNotRegisterAReplacement` | 17.441 | Startup fixture and real deadline |
| `MachineUpdateReplacementTests/testCompletionPublicationStorageRetainsOnlyTheExactRecordedPlan` | 48.557 | Installed-readiness fixture and publication |
| `MachCommandCallerReceiverTests/testMappedNativeDispatchUsesEveryAuthenticatedCallerRoutingMask` | 8.478 | Repeated fixture and native dispatch |

The 13 selectors sum to 94.410 seconds in 8022. Three serial repeats are about 283 seconds of case time at those rates, before process startup and host variation. Budget 3–6 minutes for tests with a 10-minute test cap. Allow up to 15 minutes for the separate optimized build. These are proposed bounds for the profiling run.

Add test-only monotonic phase timing to the actual fixture paths and run each selector three times on the same host. Record the first pass separately from warmed passes. Measure construction, teardown and the work between those boundaries. Record fixture counts and inclusive and exclusive time. Merge overlapping fixture intervals within each case so nested setup and teardown count once. Attribute process setup in the caller receiver case separately from Mach dispatch. Keep assertions and real deadlines in place. Flag and investigate any testcase wall time missing from the phase records. Report the split for each sample and avoid extrapolation to unmeasured paths. For the startup deadline and slow completion publication tests, also record XCTest process CPU by phase in isolation. CPU time excludes child processes and does not explain every gap in elapsed time. Check the explicit startup deadline separately before proposing a clock substitution.

## Choose the first change from the result

- If measured incremental fixture cost is larger, start with the fixed profile in `withMaintenanceWriterFixture`. Check whether its closed seed data can be reused without carrying live runtime state across tests. Keep per-test admission, task ownership, handles and deadlines. Retain nested proof revalidation. Fixture records bind paths and filesystem identities. Blindly copying a populated tree can invalidate those bindings.
- If seed reuse is feasible, compare a fresh fixture with a reset fixture. Compare canonical state and file identity. Run mutation and exceptional-exit cases before a second borrower in both orders. Use fresh fixtures for identity changes, migration and fault injection.
- If measured test work dominates, start with scheduling. Gate 8022's slowest shard finished 86.692 seconds after its fastest shard. Check whether placement of heavy selectors explains that gap. Preserve the same three-process cap, checks and native timeouts. Use a separate scheduling experiment if changing the weights or splitter.
- For either PR, repeat the full optimized Core run before and after on the same host. For fixture reuse, pin the same weights file and use `scripts/run-xctest-shards.py` with the same options and exactly-once guard. Confirm the same selectors and expected skips. Report per-shard elapsed time, overall test wall time and build time separately. Compare repeat measurements before claiming a gain.

## Measured fixture and test phases

The slow completion publication case used a median of 46.036 s elapsed and 45.562 s of XCTest process CPU. Its fixture used 0.449 s elapsed. The remainder took 45.531 s. The observed cost is CPU work in the measured body. Fixture reuse or a test clock would save little on this case.

In the no-live-PID startup case, the measured deadline interval lasted 15.058–15.072 s across the three passes. It consumed 0.911–1.136 s of process CPU. This is the case where an injected clock could reduce elapsed time. Preserve a test of the real deadline behavior.

Seven of the ten median-duration cases spent more than 80% of elapsed time in measured fixture work. Retained setup sequence, restoration and orphan tests supply candidates for fixture-only improvements. The sample measures these selectors. It does not estimate the effect of fixture reuse on the full suite.

The table shows medians of the three serial passes on `e0b10957`. Fixture time includes measured setup and cleanup, with overlapping intervals counted once. The remainder includes work outside the measured fixture intervals. CPU is the time for the entire XCTest process and excludes child processes.

| Case | Elapsed | Setup | Cleanup | Fixture elapsed | Remainder elapsed | Process CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `MachineUpdateReplacementTests/testCompletionPublicationStorageRetainsOnlyTheExactRecordedPlan` | 46.036 s | 0.446 s | 0.003 s | 0.449 s | 45.531 s | 45.562 s |
| `RuntimeMaintenanceStartupRecoveryTests/testAJobWithoutALivePidDoesNotRegisterAReplacement` | 17.412 s | 2.336 s | 0.004 s | 2.340 s | 15.061 s | 3.258 s |
| `RuntimeMaintenanceStartupRecoveryTests/testSupervisorCloseDuringBeforeRPCVerifyReopenFailsClosed` | 2.686 s | 2.321 s | 0.000 s | 2.321 s | 0.364 s | 2.470 s |
| `MachineUpdateReplacementTests/testCompletionPermitRejectsAnotherThreadAndConsumesAFailedAttempt` | 1.069 s | 0.448 s | 0.002 s | 0.450 s | 0.600 s | 0.935 s |
| `RuntimeMaintenanceExplicitRestorationTests/testActorReentryBeforePendingSecondReconnect` | 2.382 s | 2.122 s | 0.005 s | 2.126 s | 0.256 s | 2.182 s |
| `SetupOrphanRecoveryOperationsTests/testNoCompletionIsNotApplicableToAdoptionAfterSuccessfulClaim` | 2.289 s | 2.284 s | 0.004 s | 2.288 s | 0.001 s | 2.094 s |
| `RuntimeMaintenanceRestartRestorationTests/testBusyAccountDrainClosesTheRefusedAttemptWithoutRpcOrAWriter` | 2.309 s | 2.105 s | 0.004 s | 2.110 s | 0.202 s | 2.112 s |
| `MachCommandCallerReceiverTests/testRegistryReentryClosesOnlyASeparateIncomingTransferAndCloseCancelsAssembly` | 0.057 s | 0.004 s | 0.000 s | 0.004 s | 0.053 s | 0.056 s |
| `RetainedSetupRuntimeSequenceTests/testAssemblyRejectsAnotherActualInventoryBetweenLoansAndPoisonsTheContext` | 4.101 s | 4.075 s | 0.000 s | 4.075 s | 0.026 s | 3.712 s |
| `SetupRetainedOrphanClaimTests/testDeinitRightsReturnIsRequiredAfterStatusAlreadyShowsOrphan` | 1.940 s | 1.936 s | 0.005 s | 1.940 s | 0.001 s | 1.797 s |
| `SetupExecutorAdmissionOwnerTests/testCloseWhenIdleWaitsForTheActualAuditBody` | 0.367 s | 0.143 s | 0.000 s | 0.143 s | 0.225 s | 0.093 s |
| `SetupMaintenanceRecoveryScopeTests/testPersistentOwnerCleanupUsesBackoffCappedAtThirtySeconds` | 1.946 s | 1.942 s | 0.004 s | 1.945 s | 0.001 s | 1.799 s |
| `MachCommandCallerReceiverTests/testMappedNativeDispatchUsesEveryAuthenticatedCallerRoutingMask` | 9.637 s | 2.367 s | 0.000 s | 2.367 s | 7.270 s | 0.528 s |

All 39 selected test executions passed. The first wrapper exited with a parser error after two timing records interleaved with XCTest output. The original log stays intact. Both records were reconstructed from their original byte fragments, and the 13 first-pass outcomes were verified separately. The two remaining passes used the same instrumented binary with separate output streams. The temporary patch was removed after the run.

## Evidence

The parser checked the SHA-256 of each shard log against both `core-cases.json` and `outcome.json`. It matched the terminal cases and their results exactly to `core-cases.json` and checked the final shard counts. The original local evidence roots end in `retry-fd6eed41/candidate-7999` and `retry-a87998f5/candidate-8022`.

| Gate | Shard | Elapsed seconds | SHA-256 |
| --- | --- | ---: | --- |
| 7999 | `shard-1-of-3.log` | 1472.027 | `b318acc1096d66b4c74f585debffbc916619decebebccca2067db189eaa077da` |
| 7999 | `shard-2-of-3.log` | 1415.129 | `03cd15bf3652e9db42171bbf3da6045c8519764cd43d38b03eeaeb882d50a5e1` |
| 7999 | `shard-3-of-3.log` | 1427.022 | `33e2478de6036be27cc3bcc6c05ce0d8aa292790be1111169157f0e604574ead` |
| 8022 | `shard-1-of-3.log` | 1498.462 | `b9f3bb05a1f60b7415cdd341231a12ecfc5285c920fb29c8b597031adf955775` |
| 8022 | `shard-2-of-3.log` | 1411.770 | `a1adedfac4c1ce5ec632b59c764fb277ee4bd4e4cfa4b0d0ed4c6eb643659fa4` |
| 8022 | `shard-3-of-3.log` | 1426.679 | `db42787dc037b0af696bcb14d5b542595b784410308f41c490482f0f77954760` |
