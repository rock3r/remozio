# M05: work observation and clean shutdown

Current decisions: Toni2996,2998 and3002, following Saturn2994/2997.
This revision supersedes the full live-idle design in689ee08e. That commit retains the detailed hosted-owner audit as history.
The inspected implementation source remains7698e3ef1761a145aea841a866336ed1b440e4de.
This report is source-only. It qualifies no installed control channel, marker, shutdown or service stop.

## Decision

A maintenance window must not cut a command, pending decision or staged pairing attempt.
It uses A's real account drain, bounded observation of actual user work, existing ordered shutdown, a durable close marker and the original exit witness.
There is no new full-runtime live-idle proof. Background services settle through their existing shutdown owners.
Cancellation before bootout reopens A without a stop. Cancellation after bootout requires restoration through M09.
The operation body cannot start until the exact close marker, exit witness and required journal/continuity custody all pass.

## Source answers

1. AuthorityRuntimeRunner.close:108-120 joins its startup/monitor task and calls the retained instance.close.
InstalledAuthorityCommandRegistration:497-500 joins the extension monitor, consumer recovery and settings listener before closing AuthorityWakeService and registration.
AuthorityWakeService.close:481-506 joins receiver, scheduling offers, authorization producer callbacks, execution start turns, publisher, settings/recovery drains and observers.
The synchronous request close then waits for the journal lock before closing storage.

This is ordered shutdown, but it is not a proof that user work had already finished.
ApprovalRequestCoordinator.close:279-289 retires live entries with unknown outcomes and closes their resources.
AuthorityJournal.close:818-829 does not join commandExecutions. It cancels only execution that has not been released.
CommandExecution.cancelBeforeRelease:145-150 returns immediately after release.
The existing test testNativeDispatchCleanupSurvivesJournalClosureWithoutKillingReleasedWork calls close and separately waits for actual native cleanup.
Therefore the pre-stop observation remains mandatory. A successful close alone cannot protect a running command or pending decision.

A staged pairing attempt is also user work. AuthorityPairingXPCEndpoint:67-80 retains it between calls with activity and an expiry timer.
Its close:50-55 clears that attempt. Per Toni3002, staged pairing therefore stays inside the bounded pre-stop wait.
Natural expiry keeps its existing meaning. Maintenance cannot clear, cancel or accelerate the attempt to obtain zero work.

2. Neither the generated per-account manifest nor the bundled Authority plist declares ExitTimeOut.
The installed local manual, /usr/share/man/man5/launchd.plist.5:414-420, defines the default as system-defined.
It specifies SIGTERM followed by SIGKILL after that timeout. It does not establish a fixed20-second contract on this host.
Some existing joins are unbounded. No source result proves that the effective allowance always suffices.
An explicit ExitTimeOut would change installed job declarations and needs Toni's separate scoped decision.
This plan leaves the plist unchanged and fails closed when shutdown does not produce the required marker.

3. RuntimeJobExitWitness exposes only hasExited. RuntimeJobProcessObservation:61-74 maps the native observer to a Boolean.
CommandCallerObservation.c:28 requests NOTE_EXEC and NOTE_EXIT, then discards exit event data.
The local kqueue manual states that NOTE_EXITSTATUS is valid only for child processes.
Setup is not the parent of the system-domain Authority daemon. It must not infer status0 from the current witness or registration absence.
The new marker proves completed close, followed by exit of that same incarnation. It does not prove the numeric exit status.
A SIGKILL after durable marker publication occurs after close has finished. The witness cannot distinguish that case from ordinary exit.
Toni3002 accepts this precise contract. Do not claim the marker supplies an exit status.

## Ordered sequence

1. Persist the exact window intent and draining phase. Hold ordinary shared machine admission and A's exact registered account drain.
2. Use the authenticated Setup-to-A channel to observe actual request, decision, execution, handoff and staged-pairing work.
3. Preserve those lifetimes while waiting within the configured bound. If busy persists, cancel before bootout and explicitly reopen A.
4. Block new pairing stages under the authenticated maintenance binding, preserving existing attempts. Then revalidate zero staged pairing, account, gate, attempt/revision, Setup identity and the same incarnation before arming removal.
5. Boot out only the derived Authority A job. This invokes the existing ordered shutdown. Other roles and accounts stay outside the stop cohort.
6. A publishes the exact durable close marker only after runner.close succeeds under its retained authenticated shutdown binding.
7. Setup requires the original process exit witness and exact marker readback. Missing, stale, foreign or mismatching evidence means needsOwnerRecovery.
8. Acquire and validate A's actual journal/continuity pair. Only then may the purpose-bound body loan begin.

No request Boolean, empty queue, timer, durable terminal row or successful bootout reply can replace these checks.
A timeout never grants lock takeover, forced expiry, body replay or invented completion.

## One authenticated channel and one record-read mechanism

M05b supplies the native Setup-to-A channel. M09 reuses it for explicit admission reopen/readback.
Authenticate the fixed Setup peer on the exported invocation stack before async handoff.
Setup supplies account, exact attempt and window revision. Include machine/installation, gate identity and a fresh connection/incarnation binding.
A checks them through the one protected command boundary and retains the resulting binding in memory for that connection.
The first operation asks for the M05a observation. Returned owner state is data, not a stop permit.

A reads the window record only at protected startup and on authenticated maintenance commands.
No per-request reread, background poll or second event-driven reconciliation is added.
In particular, A does not reopen the machine store or reread the window inside close to discover the marker's attempt.

A restart creates a different incarnation and loses the old binding.
A disconnect or cancellation before bootout retires the binding and cannot later create a marker for that attempt.
The transition from a live authenticated binding to an armed, signal-triggered shutdown must be explicit and tested.
Normal listener teardown during the already-armed shutdown must not erase its retained marker binding prematurely.
Conversely, an unrelated retirement, deinit, startup failure or lost connection must not mint a window-close marker.
An ordinary shutdown without that exact binding creates no such marker.

## Durable marker contract

Bind the marker to account, machine/installation, attempt, expected revision, Authority incarnation and the current installed code/release scope.
Setup compares against the exact expected binding it retained before bootout, not merely a filename or PID.
Use fixed protected storage and bounded canonical bytes. Refuse symlinks, replacement identities, unsafe ownership and malformed or stale records.
Commit durability before reporting publication. Test crash windows and both file and directory durability boundaries.
Never overwrite or adopt an old marker to make a new attempt pass. Preserve unrelated attempts and recovery evidence.
If close or marker persistence fails, leave the body unstarted and expose needsOwnerRecovery.
The readback and native permit must still enforce their current code, protected scope and same-process witness contracts.

## Focused cuts

| Cut | Complete responsibility | Planning estimate | Required tests and boundary |
| --- | --- | --- | --- |
| M05a | Actual work observation through pairing reply/activity release; shared budget releases at work return | 152 measured | Sourcec86366af, published by Toni as #764/ab540f5e. Gate18129 passed Core/Debug,31 pairing and10 Debug checks fresh;42 focused methods and54 Python outcomes transferred. |
| M05b1 | Canonical binding and shared pairing stage admission owner | 115 measured | Source303fcc08. Gate26372 passed Core/Debug,10 admission and10 Debug checks fresh;73 focused methods and54 Python outcomes transferred. No endpoint integration. |
| M05b2t | Process-owned armed pairing block, independent of the connection | 49 measured | Source970f30df; gate46648 passed Core/Debug,20 admission and10 Debug checks fresh;73 focused methods/54 Python transferred. Exact cancel/reopen only; closed admission stays unavailable. |
| M05b2a | Canonical channel codec with applied/stagesPending/refused outcomes | 119 measured | Source7c293c7d; gate66084 passed Core/Debug,15 codec and10 Debug checks fresh;93 focused methods/54 Python transferred. Pending only for arm with work; refused has no work. Applied arm reports actual transfer. |
| M05b2b | Original-stack authenticated endpoint with explicit outcomes and joined per-operation lifetime | 183 measured | Source796f2517. Gate61351 passed Core/Debug,17 endpoint +24 admission +15 codec +10 Debug checks fresh;73 focused methods/54 Python transferred. Actual anonymous XPC teardown uses owned peer controls. Root positive admission and the protected access producer remain unqualified. |
| M05b2c | Fixed-address native listener and retained disconnected work | Under200 per complete cut | Root self/release/Setup peer checks, registry and joined retired endpoints. Test listener teardown after arming preserves the block. No product registration. |
| M05b3 | Native authenticated client with bounded cancellation and exact reply correlation | 120–195 planned | Fixed installed self and Authority identity; account/attempt/revision/incarnation/connection matching; no automatic retry after an ambiguous reply. |
| M05b4 | Protected record read and actual M05a/pairing owner composition | 100–180 planned | At one authenticated read boundary, verify installation and gate identity against the request, plus exact phase/attempt/revision/account/incarnation. Retain real stage ownership, block before zero revalidation and release only the exact armed target. No close-time read. |
| M05c | Exact protected marker publication after successful ordered close, plus Setup readback | 110-195 per complete cut | No marker after failed/unbound close; crash/durability failures; wrong/stale/incarnation mismatch; armed shutdown preserves its binding through listener teardown. No claim about exit status. |
| M05d | Purpose-bound permit and separate native stop factory, introduced together | 120-195 if prior support is complete | Actual bounded observation, pre-stop cancellation without interruption, exact bootout, clean-marker plus witness readback, then real pair custody. Audit EX unchanged. |

Every PR remains capped at200 changed production lines. Measure before tests. No partial implementation may enable the body.
There is no approved large receiver/app/background fence matrix under this sequence.
The historic audit explains what existing shutdown joins; it is not a list of new lifecycle services to implement.

The archived M05a draft is uncommitted and uncompiled. Its tests also remain unexecuted.
Toni2998 asks Bepi to send this plan revision, then resume that draft and add the required staged-pairing observation if it fits.
Use the M04 base7698e3ef until its actual merge permits main reconciliation. Do not invent merge readiness.
M03b2/M03c writers do not block these supporting observations. M15 still owns final reachability, full qualification and the attended boundary.

### M05b supporting cut order (Toni3020)

Toni3018 required the M05a pairing correction first. Its source6a591d02 passed the focused gate72151.
M05b1 follows that correction; M05b2, M05b3 and M05b4 follow in order. Toni owns publication and merges.
The four supporting cuts keep each production diff below200 lines. Measure again before each cut's tests.
M05b1 source303fcc08 contains the internal owner and passed gate26372. Original5fa698f2 remains preserved after the requested rebase.
Its stage reservations are not yet attached to real pairing endpoints. M05b4 must prove that integration.
An observation or decoded binding grants no native authority, idle proof, clean-close marker or stop permit.
M09 reuses this channel. The existing gateway settings channel and its contracts remain unchanged.

### Native channel order after Toni3042/3044

The latest order is M05b2t, M05b2a, M05b2b and M05b2c. It supersedes the placement in3040.
M05b3 and M05b4 retain their client and protected composition responsibilities.
M05b2t transfers the blocked admission from Connection to a shutdown target bound to the exact five identifiers.
An armed block survives connection close, deinit and expected listener teardown during bootout.
Only explicit cancel/reopen for that exact target, or Authority process termination, ends the armed restriction.
Pre-arm disconnect still releases the connection's restriction. A stale close cannot release a newer target.
A later authenticated command may reattach only to the existing armed target after native and protected scope checks.
Decoding its identifiers neither creates an armed block nor grants shutdown authority.
M05b2b proves XPC teardown behavior. M05b2c proves listener teardown behavior.
M05b4 verifies installation and gate identity against the request. The five-value binding alone omits those identities.

Current M05a isc86366af with the shared budget fix, published by Toni as #764/ab540f5e.
Current M05b1 is303fcc08 with the completed gate26372. The existing plan's earlier states remain historical.
The original saved codec20f1f655 remains source-only. Its preparation started no build or test before the order changed.
The codec rebased only after the completed b2t gate. Its source482407e5 then received its own gate87265.

### Endpoint retry distinction (Toni3049)

Transfer currently reports the same unavailable error for live stages and an invalid blocker.
M05b2b must distinguish these cases with a dedicated error or explicit count.
If stages still exist, preserve them and wait/retry only within the configured pre-stop bound.
If the block is lost, closed or held by another owner, cancel the attempt and do not retry that transfer.
Test live stages, lost block, closed admission and wrong blocker separately. No generic unavailable retry is allowed.
This endpoint behavior is still unimplemented. The b2t library gate does not prove native connection handling.
The completed codec preserves all M05a fields as non-atomic data. It grants no idle proof or shutdown authority.

### Explicit channel outcomes (Toni3058/3060)

The codec has a closed outcome set: applied, stagesPending and refused. Unknown values fail decode.
Applied retains the action-specific work shape. Applied arm means the native owner actually transferred the block.
StagesPending is valid only for arm and requires work observations. Setup may wait and retry only within the original bound.
Refused carries no work. It covers a lost, closed or foreign block; Setup cancels without retry.
A missing or failed observation never becomes a zero-work snapshot. A transport error never becomes stagesPending.
The native endpoint must map the two distinct transfer errors to these outcomes and test each path separately.
That endpoint remains unimplemented. The historical draft in /private/tmp predates this decision and must not be applied wholesale.
The correction gate includes all15 codec methods. The failed2f5cdfc5 gate stopped during test compilation and ran no test.
Its actual terminal67584/1/10ab59 and logs remain immutable; its time stays in the codec budget.
The test-only missing-try fix produced current7c293c7d. No failed receipt was relabeled.

### Endpoint result and ownership contract (Toni3063/3065)

Every response constructor requires an explicit outcome. There is no default applied result.
A refused open echoes account/attempt/revision through unowned metadata. It creates no connection reservation or pairing restriction.
The endpoint completes open validation and work capture before reserving its connection. Tests then perform a fresh successful open.
Live stage reservations produce stagesPending. Invalid, closed or foreign block ownership produces refused without work.
Applied arm is emitted only after actual transfer. Setup/b3 owns bounded waiting; the endpoint performs no generic transport-error retry.
Unarmed cancellation checks ownership and the absence of another armed target in one lock step.
Wrong-binding reopen cannot acknowledge releasing another restriction. Stale close cannot release an armed target.
Per-operation task and budget ownership remains distinct through replies. An immediate next call cannot lose its budget to older cleanup.
Disconnect cancels and joins actual work, retaining activity and budget until it settles. Reply cleanup remains joinable.
An actual anonymous XPC disconnect after arm preserves the block. This test uses owned peer controls, not installed Root authentication.

The native constructor enforces Root identity and the original XPC invocation guard. The owned seams refuse Root.
The process-bound access type has no native Root producer yet. Its protected construction belongs to b4.
The fixed listener, Authority self/release validation and listener teardown proof remain b2c. No product listener is registered.
The first two b2b gates stopped during compilation and ran no test. Their original terminals88020/1/34cdee and67002/1/08609e remain preserved.
The later gate61351 uses distinct source, adapter and outputs. Its budget includes both failed runs.
No marker, stop permit, native stop factory, writer declaration or production entry was added.
