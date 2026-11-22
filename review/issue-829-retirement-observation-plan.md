# Issue #829 — Cancel recovery attempts before closing admission

Main observed at `8b85517464f60b7d6470afba5be99ace8461d04c`. PR #879 changes the same supervisor. Apply the implementation to the actual green main after #879 lands and verify the shutdown path on that source. This branch contains the plan.

## Cause and fix

`SetupMaintenanceRecoverySupervisor.startClosing()` stops accepting requests and closes recovery admission. It then calls `join`, which marks each entry task cancelled. Between these operations, an attempt can pass the process lease check and reach `SetupAccountOwner.acquireMaintenanceRecoveryScope` after the owner is marked closing. The scope call throws `unavailable`. The lease can still be valid, so the runner can report `failed(serviceUnavailable)` before task cancellation arrives.

Keep the existing admission error and real failure classification. On the supervisor actor, stop accepting requests, take the existing entry task snapshot, and mark those tasks cancelled immediately before closing admission. The cancellation call does not await work or release custody. Keep the waiters, task joins, session joins and final close in their existing order. Keep the disposal path's cancellation independent. Keep #879's retained-owner cleanup and retry behavior.

Review all cancellation handlers in this path. The native owner's handler marks cancellation and cancels its actual task. It does not wait for the executor or release admission. A handler that waits for actual work would make this ordering unsafe. The change adds no work, no rights and no persistent field.

## Deterministic ordinary-owner regression

Use `SetupMaintenanceRecoveryScopeTests` and its actual owner, shutdown and process lease. Wrap ordinary-owner custody at `closeAdmission` to control the schedule. Block the driver before scope acquisition. Start retirement, call the real admission close, release the driver, and wait inside the fixture's close callback until the driver has captured the rejection and its current task cancellation flag. Do not let the close callback return before the driver has made that observation. The driver calls the real `acquireMaintenanceRecoveryScope` and rethrows its error. Check that the lease is valid and the error is `AdministrativeSetupError.unavailable`. Stop on an explicit, bounded timeout for each handoff.

Require the cancellation flag to be set at that exact rejection. This assertion fails deterministically on main because its `join` has not run. Also require the supervisor's final observation to be `cancelled` on the candidate. Report the status actually observed on main. The main status can still depend on when the runner classifies the error after the fixture releases the close callback. No sleep determines when the assertion runs.

Assert that no executor body runs and that the final join releases the actual process lease once. Keep the existing live-custody `serviceUnavailable` tests in the gate. Run the new test once on reconciled main with only fixture code applied, then run it in the candidate gate.

## Provisional gate

Select the eight CI smoke classes, the maintenance scope, supervisor, phase and recovery-session classes, the Setup lifecycle, and both built-app classes. The current inventory contains 407 Core methods and 18 built-app methods in this selection. Reserve four #879 methods and one #829 method for 412 Core methods. Reconcile these numbers against compiled discovery after the merges.

Use three optimized arm64 Core shards, both app builds, the built-app tests, 18 arm64 inspections, and 94 Python manifest and selector checks. Estimated budget is 2,200 seconds including the baseline. Proposed cap is 3,000 seconds. Send the exact diff, compiled selection and refreshed forecast before test execution.
