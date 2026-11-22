# Issue #830 — Assert what the restore shutdown join waited for

Main observed at `2d2b1fb6839801b0ad47dd43eb87a2be228acc57`. This is a test-only change to `SetupOrphanInProcessRestoreEffectTests.testShutdownCancelsTheConcreteUnboundTaskWithAnIntentAndAPendingRPC`.

The current test waits for `joinRecoverySessions()` and then independently waits for `actual.value`. Its assertions run after both waits. The second wait can hide an early return from the shutdown join.

Move the `returned` and `driverClosed` assertions to immediately after the shutdown join and before `await actual.value`. Give each assertion a distinct failure message. Keep the concrete restore effect, confirmed intent, pending RPC, lease checks and later startup assertions. Keep the individual task wait for cleanup if an assertion fails. The post-join assertions run even when the task has yet to return.

To show the assertion can detect an omitted join, run one temporary test-only control. Take the same assertions while the real RPC is still pending, before either wait. Then run the original shutdown join and task wait so the fixture tears down normally. Require the expected incomplete-work assertion failures. This control does not change production or claim a runtime defect on main. Run the positive test through the normal shutdown path in the candidate gate.

## Provisional gate

Use the eight CI smoke classes, the concrete restore, recovery-session shutdown, orphan operations and retained claim classes, and both built-app classes. The compiled #880 inventory has 406 Core and 18 built-app methods in that selection. Main without #880 has 404 Core. The change adds no test method.

Run three optimized arm64 Core shards, Debug and Release builds, the built-app tests, 18 arm64 inspections and 94 Python checks. Allow 2,510 seconds including the negative control. Proposed cap is 3,200 seconds. Refresh the forecast on actual main and send the exact diff and discovery before the gate.
