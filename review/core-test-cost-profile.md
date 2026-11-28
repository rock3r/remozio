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

Add test-only monotonic phase timing to the actual fixture paths and run each selector three times on the same host. Record the first pass separately from warmed passes. Measure construction, teardown and the work between those boundaries. Record fixture counts and inclusive and exclusive time. Merge overlapping fixture intervals within each case so nested setup and teardown count once. Attribute process setup in the caller receiver case separately from Mach dispatch. Keep assertions and real deadlines in place. Flag and investigate any testcase wall time missing from the phase records. Report the split for each sample and avoid extrapolation to unmeasured paths.

## Choose the first change from the result

- If measured incremental fixture cost is larger, start with the fixed profile in `withMaintenanceWriterFixture`. Check whether its closed seed data can be reused without carrying live runtime state across tests. Keep per-test admission, task ownership, handles and deadlines. Retain nested proof revalidation. Fixture records bind paths and filesystem identities. Blindly copying a populated tree can invalidate those bindings.
- If seed reuse is feasible, compare a fresh fixture with a reset fixture. Compare canonical state and file identity. Run mutation and exceptional-exit cases before a second borrower in both orders. Use fresh fixtures for identity changes, migration and fault injection.
- If measured test work dominates, start with scheduling. Gate 8022's slowest shard finished 86.692 seconds after its fastest shard. Check whether placement of heavy selectors explains that gap. Preserve the same three-process cap, checks and native timeouts. Use a separate scheduling experiment if changing the weights or splitter.
- For either PR, repeat the full optimized Core run before and after on the same host. For fixture reuse, pin the same weights file and use `scripts/run-xctest-shards.py` with the same options and exactly-once guard. Confirm the same selectors and expected skips. Report per-shard elapsed time, overall test wall time and build time separately. Compare repeat measurements before claiming a gain.

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
