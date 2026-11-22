# Issue #828 — Join the close retry already in progress

Read against the local #829 commit `4b05f9e94c83af77882422f0a02b8dfc96f781ce`, which includes #879's retained cleanup and retry backoff. Apply the code on that local branch after review. Validate it only after #829 merges into green main.

## Change

The supervisor's first close or retirement caller sets `retryingClosure` and awaits the final close retry. A concurrent caller sees that flag and returns without waiting. The direct shutdown path then sees that recovery still holds its binding and throws `unavailable`, even if the active retry succeeds.

Replace the flag with an actor-owned task for the current retry. Publish the task before suspending. A concurrent close or retirement call joins that task. The task publishes the result and clears its slot on the supervisor actor before any joined caller returns. A call that only waited for the initial shutdown still follows the existing initial-close behavior. A later explicit caller can start another retry if the previous retry did not close. No call starts a second retry after waiting for one.

Keep #829's cancellation order, #879's retry backoff, the native bounded close, the actual custody task and the lease release conditions. Cancelling a waiter cannot cancel the shared retry. A timed-out or failed retry still leaves custody held and permits a later explicit attempt. The change does not add a new native caller.

## Regression

Extend the existing ordinary-owner scope fixture. Use its real direct `shutdown.close()`, supervisor and process lease. Make the initial close retain the owner after failed cleanup. Advance the existing test clock to the retry deadline. Start retirement and hold the second cleanup at a bounded gate. Start direct close while that retry is held. Check for early completion while the gate is held, then release the gate and require both callers to finish and direct close to succeed. Check one retry, one resource release and no replay. On the predecessor, direct close is expected to return `unavailable` while the retry is held. Record the actual result from one run with only the fixture changes applied.

Use the supervisor fixture to cover a shared unsuccessful retry from `.pending`. Check that concurrent callers see that attempt's result and that only a later explicit call can retry. Keep the existing first-close, cancellation, timeout and backoff tests in the selection. Use bounded waits with explicit failure messages and always release the fixture gate on teardown.

## Provisional gate

Select the eight Core smoke classes, maintenance scope, supervisor and phase classes, recovery-session shutdown, Setup lifecycle, and the two built-app classes. The #829 plan projects 412 Core and 18 built-app methods. Reserve two new Core tests for a provisional 414 Core and 18 built-app methods. Use three optimized arm64 shards, both app builds, 18 arm64 checks and 94 Python checks. Forecast 2,260 seconds including the predecessor comparison. Proposed cap 3,000 seconds. Recompute from the exact rebased diff and compiled inventory before starting the gate.
