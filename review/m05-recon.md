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
4. Revalidate account, protected gate, attempt/revision, Setup identity and the same live Authority incarnation before arming removal.
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
| M05a | Internal observation of real request/capture/activity, exchange callbacks, queued/rejected starts, native execution custody and staged pairing | 71-line archived command draft plus a measured pairing addition; total under200 or split pairing immediately afterward | Authorization-to-enqueue gap, rejected-start/report reservation, terminal row with live cleanup, staged attempt and active pairing work. No endpoint, idle proof or permit. |
| M05b | Authenticated Setup-to-A observation channel and connection-bound in-memory marker context, reused by M09 | 120-195 per complete cut | Exact Setup peer, account/attempt/revision/gate/incarnation; disconnect/restart invalidation; no close-time record read. Split supporting validation first if necessary. No native stop factory. |
| M05c | Exact protected marker publication after successful ordered close, plus Setup readback | 110-195 per complete cut | No marker after failed/unbound close; crash/durability failures; wrong/stale/incarnation mismatch; armed shutdown preserves its binding through listener teardown. No claim about exit status. |
| M05d | Purpose-bound permit and separate native stop factory, introduced together | 120-195 if prior support is complete | Actual bounded observation, pre-stop cancellation without interruption, exact bootout, clean-marker plus witness readback, then real pair custody. Audit EX unchanged. |

Every PR remains capped at200 changed production lines. Measure before tests. No partial implementation may enable the body.
There is no approved large receiver/app/background fence matrix under this sequence.
The historic audit explains what existing shutdown joins; it is not a list of new lifecycle services to implement.

The archived M05a draft is uncommitted and uncompiled. Its tests also remain unexecuted.
Toni2998 asks Bepi to send this plan revision, then resume that draft and add the required staged-pairing observation if it fits.
Use the M04 base7698e3ef until its actual merge permits main reconciliation. Do not invent merge readiness.
M03b2/M03c writers do not block these supporting observations. M15 still owns final reachability, full qualification and the attended boundary.
