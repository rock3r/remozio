# Issue #827 — Retry failed native owner cleanup at retirement

Review proposal based on main `8b85517464f60b7d6470afba5be99ace8461d04c`, the merge of #876. Recheck main before implementation. The panel PR #877 can continue through its own review.

## Cause

`SetupMaintenanceRecoverySupervisor.Runner` joins each acquired owner once. If `NativeOwner.join()` cannot finish `phases.closeActual`, it marks that owner failed in `Custody`. The retained owner and its scope keep their admissions and leases. The supervisor joins its scheduling tasks and reports `.failed`. Later `retire()` and `close()` calls retry final close, but `Custody.closeAfterJoiningResult()` sees `cleanupFailed` and returns before reaching the owner. The lifecycle’s 250 ms retirement loop therefore cannot clear the failure. The existing 300 s watchdog can terminate it with exit 75. This diagnosis is from source.

## Proposed fix

- Give a retained native owner a typed cleanup retry operation for the same scope and executor. Keep the first close result as `.failed`. On a later explicit `retire()` or `close()`, let the existing supervisor retry path ask native custody to run one attempt for each failed owner. Keep the ordinary test custody’s existing final-close retry behavior.
- Reuse the original worker’s return and the existing `closeActual` cleanup path. The retry cannot acquire another owner, replay the worker or invoke a recovery effect. Keep all admissions and the process and placement leases while the actual cleanup is outstanding. Only a successful cleanup can close the scope and remove the matching owner from custody.
- Retain and identify the actual retry task before awaiting it. Reuse the native final-close wait and keep its five-second bound. A cancelled or timed-out caller leaves the same task in custody. A later caller joins it. Clear or replace a task only if its identity still matches. Never start a second cleanup for an owner while the first attempt is in flight.
- Once all pending owners have really joined, use the existing final close. A repeated failure returns `.failed` and retains ownership. A released admission error remains a failure unless the owner can prove that cleanup already finished. Preserve final-close retries, the retirement cadence, and the original watchdog. Keep #821 diagnostics, #826, normal worker scheduling and the Setup recovery UI outside this slice.

## Deterministic regression

Use `SetupMaintenanceRecoveryScopeTests` with a real native `Custody`, an Owned supervisor, and a real recovery scope and leases. Supply an ordinary-user fixture owner whose first cleanup marks the same native custody entry failed and whose next cleanup succeeds. Drive `retire()` through the real supervisor and native final-close path. The first retirement must report `.failed`, keep `shouldExit` false and reject competing lease acquisition. On main, the second call leaves the attempt count at one and still cannot exit. With the fix, it runs exactly one additional cleanup, closes the original scope and both leases, and reports `.closed` with `shouldExit` true. Keep the regression’s fixture plumbing identical in the baseline and fixed runs. If the new typed registration needs fixture scaffolding to compile on main, apply only that plumbing with the test to the baseline and retain the exact patch. The baseline must retain the old final-close behavior.

Add two guard cases. Hold a retry open while close and retirement overlap, cancel or expire one waiter, and verify there is only one actual cleanup and that neither lease opens early. Then make cleanup fail repeatedly and verify one attempt per later call, no replay, no handoff, and a typed failure. Retain the existing lifecycle watchdog tests. Use fixture barriers and the existing Owned shortened close wait. No test needs to wait 300 seconds or activate an installed helper.

## Gate forecast

Propose the eight CI smoke classes, the full native scope, supervisor, phase, recovery-session shutdown and lifecycle classes, and the two built-app test classes. The current compiled inventory has 407 Core and 18 built-app methods in that selection. Reserve three new Core cases for a provisional 410 Core plus 18 built-app. Discover the exact selectors on the real diff. Run the new regression once against the baseline before the fixed gate. For the fix, use the three optimized arm64 shards, Debug and Release builds, 18 artifact inspections, and 94 Python manifest and selector checks. The built-app cases run after the builds.

Existing test weights sum to 99.780 seconds. Apply the 1.3 multiplier for 129.714 seconds. Reserve 90 seconds for the three new fixtures, 420 for compile and discovery, 660 for both app builds and artifact inspection, 180 for the runner, 180 for Python and evidence, and 480 for the baseline comparison. The provisional forecast is **2,139.714 seconds** with a **3,000-second cap proposed**. Recalculate with actual fixture weights and seek gate admission before executing tests. Installed retirement and the watchdog remain separately attended checks.
