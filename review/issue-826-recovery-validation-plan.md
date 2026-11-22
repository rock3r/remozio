# Issue #826 — Remove repeated signed-release checks within a recovery call

Review proposal based on main `8b85517464f60b7d6470afba5be99ace8461d04c`. Recheck main and the independent PRs before implementation. The counts below come from reading the current source.

## Cause

`NativeRecoveryContext` invokes `Host.checkedStartup()` through `validate`, `currentOwner` and `registerSession`. The check reloads the protected configuration, inspects the installed bundle and its signed components, checks the running Setup identity, and revalidates placement. Recovery also repeats it through `SetupOrphanRecoveryOperations.requireContext()` when checking the same invocation, recording the reply, capturing the target and claiming it. A successful new hello runs four full checks, a successful start runs six synchronous checks, and each successful progress read runs two. Work after the claim performs separate checks on its own executor. An already opened hello follows the existing idempotent path.

## Proposed fix

- Separate the expensive release scan from live checks of the invocation, process lease, protected placement and configuration, caller, current owner, admission, and endpoint lifetime. Keep live checks at their existing boundaries. Do not cache a successful signature check on a connection or copy the status lane’s five-second interval.
- For a new `recoveryHello`, do one full release check during native endpoint construction. Keep native format validation, peer verification, the owner check during registration, the simultaneous admission and endpoint installation checks, and disposal when admission closes during construction. Recheck live placement and the owner before exposing the endpoint. Do not reopen or revalidate an existing hello beyond its current checks.
- For `startRecovery`, keep full checks before recording a new request, after the recorded reply and before importing rights, and after import at the last point before claiming the exact target. The reply and rights import are separate boundaries. The remaining checks in each synchronous segment reuse that segment’s validation while rechecking the live guards. Do not carry an invocation check into a retained task. Keep current authorization, exact reservation and incarnation, request deduplication, and the existing checked work before any recovery effect.
- For `recoveryProgress`, keep one fresh full check per successful read. Keep peer and connection checks both before reading and immediately before returning bytes. Recheck live guards at the reply boundary. A failure still closes or refuses as it does today. Do not share the check across peers, requests, or overlapping invocations.

Keep existing asynchronous restore and adopt checks, selector routing, admission boundaries and readiness. Do not add signing policy, a rate limit, a new persistent state, or changes to the status or restart-only protocols. If the existing guard at a boundary requires a fresh full check to preserve its safety property, retain it and revise the forecasted count.

## Deterministic regression and cost measurement

Use the actual facade and orphan recovery endpoint flow with an ordinary-user fixture. Inject a test-only counter at the full-check boundary and separate it from the live guards. Root must keep its fixed Host construction. Drive a new hello, a valid start and 100 progress reads on the same endpoint. Hold the worker before its executor phase so the count isolates caller-side checks. Expected counts are four for hello and 206 for start and reads on main, versus one and 103 after the change. Run the count regression against main once with only shared instrumentation and the test applied. The instrumentation must count the old call sites without changing validation outcomes or timing rules.

Use fixture barriers and explicit failure injection to verify that a configuration or peer change before the reply or claim fails closed, that concurrent calls cannot share a check, and that opening admission still closes a late endpoint. Keep the existing duplicate, caller-drift, retirement, and request-recorded tests in the selection.

Time `SignedReleaseInspection.inspect` in the existing signed Debug and Release bundle test. Record the bundle, verification mode and individual elapsed values. The ordinary local fixture can measure ad-hoc bundle inspection. Record production identity, installed placement and full `checkedStartup()` cost separately when the signed installed path is available. Do not install or elevate to get this measurement.

## Gate forecast

The provisional selection includes the eight CI smoke classes, Setup facade, XPC endpoint, lifecycle, orphan and restart recovery endpoint and operation classes, recovery-session shutdown, retained orphan claim and in-process restore, and both built-app classes. The current inventory has 520 Core and 18 built-app cases in this closure. Reserve four new Core cases. Run three optimized arm64 shards, then Debug and Release builds, built-app tests, 18 arm64 inspections, and 94 manifest and selector checks.

Existing weights total 726.191 seconds, or 944.048 at 1.3. Reserve 120 seconds for new cases, 420 for optimized discovery, 660 for the two builds and inspections, 180 for runner overhead, 180 for Python and evidence, and 480 for the baseline run. The forecast is **2,984.048 seconds** with a **3,900-second cap proposed**. Recalculate from the actual diff and compiled inventory before seeking gate approval.
