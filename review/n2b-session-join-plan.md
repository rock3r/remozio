# N2b: join actual Setup recovery work

Status: source audit and plan approved by Toni4930 and Saturn4934, with the required additions confirmed by Toni4935.
Implementation may start. Send the actual diff, test closure and forecast before the native gate.
No N2b build, test, or runtime qualification exists. This document contains no product implementation.

The audit uses main `9353b1e7f26dfac888414fd1e52375eba1df604c`, tree `b08a0df49616ae1124eb8436cb27decb1317dcf0`.
Its 2,871-input manifest is `1f56c9e9a575f89f7f9b3c4b76ef0b047034f7c6046529412b9f7e6da085acab`.
PR #820 is actually merged. The earlier N2a qualification remains bound to its original code tree.

This plan applies the join design approved in Toni4868 and decisions4907,4910,4912,4915,4917,4920,4922,4926,4928,4930,4934,4935.
The [await census](n2b-session-join-awaits.json) lists 277 lexical await sites in 16 files within the audited call closure.
Each entry records its exact source line, file hash, cancellation family, and final dependency.
The census includes shared native/Owned helpers. It does not claim that every listed Owned branch is reachable in production.

## Result and limits

The endpoint owns a wrapper Task, but current shutdown does not join that Task.
The real restoration runs in a separate private `RestorationWork` Task.
Cancelling a waiter does not cancel that Task and must not shorten its actual join.

Add explicit `RestorationWork.requestCancellation()`. Only the shutdown finalizer calls it.
Keep `value()` and `joinRecovery` as real joins. Set `returned` and `completed` only from the real result.
Ordinary `claim.abandon()`, Setup invalidation, and an Authority transport failure must not request this cancellation.
They retain their existing authorization and cleanup behavior. Decision4917 supersedes the ambiguous use of “abandon” in4907.

The normal close path releases leases and reports closed only after actual joins and successful account closure.
The existing 300-second watchdog remains unchanged. Its exit75 is a crash, not a successful join or cleanup receipt.
This amends the absolute exit statement in the earlier design. See decision4920 and the crash matrix below.

A started native command does not cooperate with Task cancellation.
Its normal polling deadline is ten seconds; its SIGKILL/reap cleanup has no explicit deadline.
A kernel wait can outlast that polling deadline. Do not detach the child or add a lease-releasing timeout.
Keep `BoundedNativeCommand` and `SetupAuditUpgradeWorkExecutor` unchanged, as directed in4910.

Persistent cleanup failure can keep the normal shutdown path pending indefinitely.
The existing retry cannot guarantee progress if that error persists. External repair may be necessary.
Decision4915 accepts this existing limit. Diagnostics belong to [#821](https://github.com/rock3r/remozio/issues/821), outside N2b.

## Wait matrix

All paths below refer to `macos/core/Sources/RemozioCore/` at the audited commit.
“Cooperative” describes the actual Task or observer. It does not prove interruption of a running synchronous body.

| Path and exact sites | Cancellation behavior | What must finish |
| --- | --- | --- |
| `SetupOrphanRecoveryEndpoint.run`:102 | `claim.join()` does not stop for a cancelled waiter. | Original ledger join and any prior restoration result. |
| Endpoint `run`:107,118 | `RestorationPhases.run` checks cancellation before phase admission. | The actual executor body and release observation. |
| Endpoint `run`:124,130 | Delegates to adopt/restore. The async signature alone proves no cancellation behavior. | The fixed native engine and its actual cleanup. |
| Endpoint `waitForWork`:149-151 | Snapshot `Task.value` has no waiter cancellation shortcut. | The wrapper Task. A nil snapshot does not prove raced publication completed. |
| `SetupRetainedOrphanClaim.Joined.startRestoration`:181-182 | Checks through phase admission before creating the work slot. | Admission body, then the actual published work. |
| Claim `finishRestorationNative`:191,193 and Owned:205,207 | The result wait is noncancellable by the waiter. The settlement phase cooperates before admission. | Actual restoration result, durable/readback proof, then settlement. |
| Claim `join`:234-236 | A cancelled waiter still waits. | `joinRecovery`, not a substitute endpoint wrapper join. |
| Reservation `RestorationWork.init`:491; `RestorationStart.wait`:523-535 | The publication continuation has no cancellation handler. | `start.open()` after the real handle is retained. It runs before custody or RPC work starts. |
| Reservation `RestorationWork.value`:500-507 | Waits for `task.result`; currently has no producer cancellation API. | The real body plus its real cleanup. |
| Reservation `joinRecovery`:558-572 | Awaits original.value and any existing restoration.value without early release. | Original ledger cleanup and actual previous restoration result. |
| Reservation `RestorationPhases.once`:408-422 | `Task.checkCancellation` at410; executor token check before the synchronous body. | Actual worker Thread return. |
| Phases `admitted`:424-432 | Busy retries check Task cancellation and sleep25ms. A normal attempt also checks its deadline. | Executor availability, or cancellation/deadline before a new body. |
| Phases `cleanup`:446-452, `cleanupUnlessReleased`:455-461, `closeActual`:475-477 | Separate uncancelled cleanup Tasks use no attempt deadline. | Real cleanup body. Busy retries end when the current executor body returns. |
| Phases `afterRelease`:463-473; owner `waitForReleaseAfterRecord`:408-424 | Cancelling this observer resumes it. It never ends the real hold. | Real hold release, observer cancellation, or its optional deadline. |
| `SetupAuditUpgradeWorkExecutor.execute`:49-71 | onCancel marks the token. The continuation resumes only after the real body and afterReturn. | Thread body, including synchronous OS calls. No thread interruption is claimed. |
| `SetupRetainedRecoveryLedger.waitForInvocationCleanup`:82-88 | No cancellation or time shortcut. | Invocation deinit reports after rights cleanup; Reservation:198-201 forwards that notification. |
| Ledger `joinWorkers`:100-107; `launchJoin`:136-151 | Cancels registered workers, then awaits actual return and synchronous cleanup. | Registered actual tasks and cleanup. There are no production callers of `retainWorker`/`retainCleanup` beyond their definitions at this commit. Owned tests must supply controlled release. |
| `RuntimeMaintenanceUnboundRestoreRunner`:40-48,59-89 | Phase checks and bounded client RPCs cooperate after cancellation reaches the real Task. | Intent write, verified RPC/readback and completion write. A transport cancellation does not prove that a remote effect stopped. |
| Unbound runner:95,100,109; startup `finishExplicit`:1213-1226 and `closeActual`:888 | Cleanup deliberately ignores caller cancellation and the attempt deadline. | Last confirmed durable outcome and real custody closure. |
| `AuthorityMaintenanceXPCClient.invokeUnbound`:330-358; `invoke`:1168-1205 | Pre/post checks, cancellation handler, driver close, pending continuation finish, and five-second RPC timer. | Authenticated reply, transport failure, cancellation, or RPC timeout. Actor close is a scheduling hop, not an actual restoration join. |
| Startup `decisionProbe`:1432-1451; `restoreHealthy`:1453-1497; `requireRestoringProcess`:1529-1553 | Check Task cancellation around phases. Their250ms clock sleeps cooperate and use the attempt deadline. | Current peer/process evidence, bounded phase body/RPC, or attempt termination. |
| Startup inspection:829-830; `RuntimeJobRegistration.ensureStartupRestoration`:135 | `launchctl print` is read-only; `launchctl bootstrap` mutates registration. Neither running command observes the Task token. | Command's own ten-second polling deadline plus actual reap. |
| `BoundedNativeCommand.run`:46,53-55,63-90 | No Task cancellation check. Polling is bounded; final blocking waitpid is not. | Exact spawned child reaped. Parent crash can leave the child alive. |
| `RuntimeJobStopSession.poll`:82-99 | Synchronous sampling, not an async waiter. The restore-startup path creates no new stop owner. | Original stop/worker cleanup remains in the prior claim join; process observations sample rather than await exit. |
| Supervisor scheduling:126-198 | Streams/sleeps observe cancellation; availability has a scheduling deadline. Task.value remains an actual join. | Slot release/closed admission, native timer, or real entry task. Owned timing hooks need controlled completion. |
| Supervisor `runOwner`:342-367 | onCancel invokes the actual NativeOwner.cancel; cleanup Task awaits owner.join. | Actual owner work, cleanup and retained scope closure. |
| Native adapter `NativeOwner.run/cancel/join`:234-263 | Existing bridge marks its token and cancels the real Task. Join still awaits actual.result. | Engine body and phases.closeActual before scope.close/didJoin. Reuse this ownership rule. |
| Supervisor `startClosing/join`:261-291 | Cancels and joins its own entries. Current snapshot does not include orphan endpoint wrappers. | Every supervisor entry, then the proposed shared session join, then final close/release. |
| Native adapter `Custody.boundedClose`:62-98 | Five-second/cancellable observer may report timedOut. Its retained actual close Task continues. | Actual closeBody owns any release; timeout never proves release. |
| `AdministrativeSetupShutdown.close`:66-72; owner `closeWhenIdle`:168-182; `SetupOwnerAsyncWork.waitUntilIdle`:47-61 | Current direct close rejects recoveryBound. Cleanup retries and idle continuations have no cancellation shortcut. | Successful account cleanup and actual admission-token release. Persistent failure is the accepted #821 limit. |
| Lifecycle `requestRetirement`:384-409; `waitUntilStopped`:424-428 | Retirement joins are retained. The stopped continuation resumes only at didClose. | Shared finalizer reaches closed, or independent watchdog exit75 terminates the process as a crash. |

Synchronous filesystem, SQLite, Security and kernel operations do not gain preemption from an async wrapper.
This audit proves their call paths and cancellation boundaries, not a hard upper bound for every OS operation.
The native factory must not accept arbitrary worker, cleanup or engine callbacks from Root callers.

## Crash and orphan-command matrix

The journal records restoration progress; wrapper Tasks and `RestorationWork` handles are process-local.
`finishRecordedRestorationNative` reads the current in-memory work slot; it cannot adopt a Task from a dead process.
Source: `SetupRetainedOrphanClaim`:185-195 and Reservation:595-600.

| Exit point | Durable state and restart behavior | Source |
| --- | --- | --- |
| Endpoint admitted or original join pending, before a new write | No new completion exists. Startup uses the last confirmed row; a missing window stays missing. A needsOwnerRecovery row is not promoted to success. | StartupRecovery:714-731,1230-1255; StartupPolicy:10-22. |
| Bound restore before registration | The restoring transition precedes registration. Stopped/workSettled/restoring with a saved binding select startup restoration. | StartupRecovery:1514-1526; StartupPolicy:16-17. |
| Bound restore with orphan bootstrap still running | Readback must handle all registration race positions described below. Parent exit does not stop launchctl or prove absence. | BoundedNativeCommand:43-55; JobRegistration:118-138,172-189. |
| Unbound intent written; RPC reply or completion missing | Unbound descriptor/reopenPending is not a success receipt. Startup records owner recovery, discards the unusable descriptor to repairRequired, and keeps the window closed. | StartupRecovery:1164-1199; WindowRecord:215-221. |
| Bound reopenPending, before verified restored write | Startup refuses automatic success with admissionUnconfirmed. A fresh authorized path is required. | StartupPolicy:20; current source does not invent a readback receipt. |
| Restored durable row exists, but in-process adopt/settlement is unfinished | The durable restored row survives; process-local task handles do not. Startup treats restored as terminal; it does not replay the old effect. | WindowRecord:206-211; StartupPolicy:21; StartupRecovery:714-731. |
| Cleanup pending or persistently failing | No successful cleanup or lease-close receipt exists. Startup reads the actual durable state. Pending repair remains explicit; #821 diagnostics stay separate. | Shutdown:40-50; CleanupOwner:12-33; Lifecycle:175-194,384-428. |
| Watchdog fires in any state above | Keep the300s watchdog and exit75. Record no completion and call no lease.close merely because the watchdog fired. | Lifecycle:178,194; Service.start:254-263. |

`launchctl print` is read-only. The bootstrap command is not read-only.
A surviving bootstrap can complete after the new daemon starts. Never infer child termination from the parent's exit.

Registration race positions:

1. The orphan completes before StartupRecovery.restoring's outer inspect at1522. A matching job skips new registration.
2. The outer inspect sees absent; the orphan completes before JobRegistration's inner absence guard at133. That guard currently throws conflictingPlan.
3. The inner absence guard passes; the orphan completes before reconcile's inspect at175. Matching returns after validation.
4. Reconcile sees absent; the orphan completes before the new bootstrap returns an error. Reconcile performs a new inspect at184-187 and accepts only matching.

The durable `.restoring` row is the existing pre-registration recovery marker. It is not a separate bootstrap-start bit.
The narrow race in position2 is tracked in [#822](https://github.com/rock3r/remozio/issues/822).
Toni4926 and4928 keep it outside N2b.
When its inner guard throws, StartupRecovery.restoring:1523-1524 wraps the error as serviceUnavailable.
The uncancelled run catches it at1412-1425 and attempts a needsOwnerRecovery write through persistRecovery:391-397.
A confirmed write at368-375 makes that row terminal for automatic startup: StartupPolicy:21 returns nothing.
It needs authorized recovery. Another automatic boot does not resume that confirmed failure row.
An uncertain failure write instead invalidates custody at376; inspect actual storage before naming the durable outcome.
This is an existing startup registration race. N2b adds no bootstrap implementation, blind retry, or automatic replay.
Its fixed native factory reuses the same engine. Any proposal that increases bootstrap retries must return to the lead.
Keep this limitation in the eventual PR body. Do not misdescribe in-process recorded/adopt as crash recovery.

## Proposed ownership and implementation order

1. Keep `AdministrativeSetupShutdown` as the single finalization owner. Add session registrations and the admission/publication barrier there.
2. Register each native session's actual work slot before creating the endpoint wrapper Task. Publish the actual Task or an explicit never-created outcome.
3. Keep the registered handle after the endpoint clears its local property. Connection disposal must not erase a join obligation.
4. Close admission and copy the session snapshot under the owner lock. Close endpoints and cancel/join work outside all owner, record and endpoint locks.
5. Retain a shutdown-only cancellation capability for the exact real restoration work. It grants no forward effect or new claim.
6. Handle shutdown before restoration-work publication with a retained cancellation request. Any later real work must see it before its publication barrier opens.
7. Ordinary claim abandonment must not set that request. A cancelled waiter must not set it either.
8. Join original claim work and the actual endpoint wrapper separately. Neither join is evidence for the other.
9. Extend the existing final-close capability with an actual async session join. Both supervisor shutdown and ordinary disposal must use it.
10. Route direct shutdown.close through the same finalization owner. A second caller awaits that owner outside every lock; it cannot start a second drain.
11. Only after actual joins, run existing audit cleanup and account closure. Pending/failed results retain both leases and use existing retry behavior.
12. Bind a native operations factory from the accepted invocation and verified Host. Use only fixed restoreNative and finishRecordedRestorationNative engines.
13. Read Host.configuration.maximumConnections. Do not accept caller-supplied peer identity, Host custody, routing state or connection limits.
14. Add the recovery lane and selectors atomically with Setup IPC13 and signed app/Setup manifest declarations. Keep C02 preparation12 unexported.
15. Serving permits the agreed operations. Retiring permits adopt/window-free release while cleanup admission remains open; it refuses restore.
16. Final cleanup closure refuses every recovery hello with version0. A foreign selector refuses that call without discarding existing lane work.

Production closure: Shutdown; Endpoint; Operations; Claim/Reservation; NativeAdapter/FinalClose protocol; Lifecycle/Service; ConnectionFacade; Listener/Slots; exported Setup contract and version declarations; signed manifest generator.
The existing engine, RPC transport, command helper and work executor retain their policies.
The exact file diff and test inventory require source review before any gate.

Excluded: C02 producer, restart-only selector publication, M13, Root privilege changes, routing/enrollment changes, #821 diagnostics, and new cleanup owners.
No new timeout may convert pending work into successful cleanup. No new restart record or replay engine belongs in this slice.

## Required tests and validation plan

These are required scenarios, not discovered test counts or completed results.

- Pause between slot admission and Task publication. Shutdown must wait for publication and the real join.
- Exercise the never-created branch: no real work is created. Resolve the publication barrier and finish the join within the existing fixture bound.
- Pause the wrapper after claim.join returns. Supervisor completion must not close the account or release either lease first.
- Request shutdown before real RestorationWork publication. The late real Task must observe the saved shutdown request.
- Use the concrete recovery engine with the existing retained claim. Pause at a controlled phase boundary, then request shutdown.
- Prove that the actual restoration Task observes cancellation and joins within the existing fixture bound.
- Keep the separate original-join fixture blocked. Hold both leases until the fixture releases the actual worker.
- Cancel a waiter or call claim.abandon without shutdown. The real restoration Task must not observe an injected cancellation.
- Gather the actual result before custody release in the abandonment case.
- Race session construction with cleanup admission closure. No registration may escape the final snapshot.
- Exercise supervisor shutdown, ordinary disposal and direct shutdown.close. Each must join the same actual work.
- Call direct close while recoveryBound is true. It must await the finalizer instead of throwing unavailable; state this contract change in the PR body.
- Race two direct close callers. Pause the first finalizer, prove owner-lock checks remain possible, then let both observe the same result.
- Make account cleanup return pending/failed after joins. Keep both leases; do not add repair logic or false closed status.
- Exercise retiring hello, final closed hello, adoption, window-free release and refused restore separately.
- Exercise both foreign-selector directions and native factory ownership/Host connection-limit checks.
- Inject the existing watchdog timer and terminate callback while a real N2b join remains pending. Expect exit75 notification, no lease.close/completion, and the correct durable startup input.
- Test the existing successful orphan registration races with the real reconciliation helper and controlled observations, not real launchctl calls.
- Record the existing inner-guard race and its terminal failure route. A fix for that shared startup path is outside N2b, per Toni4926.
- Test crash readback for pre-write join, partial bound restore, partial unbound intent, verified completion before adopt, and pending cleanup.
- Beside the partial-unbound crash case, request shutdown with the durable intent written and its RPC pending.
- Expect the same durable reopenPending input and repairRequired startup result, never successful completion.
- Check Setup IPC13 support and the built Debug/Release declarations. Explicitly prove that12 remains unexported.
- Audit literal IPC-version lists and acceptance/rejection loops in Swift tests, Python manifest scripts and their tests.
- Check complete expected reader/writer sets and fixture declarations. Do not update only scalar version assertions.
- Keep unrelated channel and codec versions unchanged. Record each affected literal and its intended channel.

Use existing endpoint, orphan-claim, phase, native-adapter, supervisor, lifecycle and concrete restore-effect fixtures.
Preserve their original bounds and actual joins. A controlled release is not a production cancellation proof.

After source approval, derive the affected closure and a fresh forecast from the actual diff and same-Mac CI weights.
Confirm every selected method against fresh compiled discovery. State the case count, groups, guards and cap before execution.
Run through ATC with the shared native lock and existing cache. Retain failures and actual terminal records.
No native gate, qualification, commit of product code, or PR is authorized by this plan document alone.
Toni owns integration, current-head watcher readiness, CI and merge.
