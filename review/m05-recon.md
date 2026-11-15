# M05: work observation and clean shutdown

Current decisions: Toni3104,3108,3111,3112,3117 and3131. Earlier appendices retain historical source states. The current table and final section govern active work.
This revision supersedes the full live-idle design in689ee08e. That commit retains the detailed hosted-owner audit as history.
The current implementation source is645f4dfd above the locally qualified acknowledgement repairf54fed93.
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
| M05b2b | Authenticated endpoint with committed-state outcomes, rollback and joined operations | 191 measured | Source905b3bfb, gate68601:22 endpoint +24 admission +15 codec +10 Debug checks fresh;73 focused methods/54 Python transferred. Refused arm leaves no block from that request; uncertain rollback returns nil. Cancel/reopen have no fallible checks after release. Root producer/listener remain later. |
| M05b2c | Fixed listener, signed participant scope and joined retired endpoints | 146 measured | Source94a9ee11. Core and Debug builds passed. Gates14466 and84763 admit50 fresh unique methods and110 transferred methods. All6 scope methods ran fresh under Toni3088. Anonymous XPC proves lifecycle with owned controls. The Root access producer and product registration remain for b4. |
| M05b3 | Native authenticated Setup client with serialized exchanges and bounded recovery | 169 measured | Source8e494e12. Core/Debug and110 fresh methods passed;73 unrelated methods and54 Python results transferred. Harmless hello precedes identifiers and changes no admission state. Only stagesPending permits another arm before the original deadline. Refused is terminal; nil, timeout or malformed reply requires recovery. No product entry. |
| M05b4a | Protected command frame and actual pairing stage reservations | 94 measured | Source645f4dfd above acknowledgement repairf54fed93. Gate5876 passed76 fresh native methods and143 explicit unchanged-method transfers, fresh Python manifest checks, Core/Debug. One read transaction binds installation, gate, phase, current revision and incarnation. Retained Stage handles keep one attempt counted through actual reply cleanup. No Root factory. |
| M05b4b | Root factory and actual M05a owner composition | 100–180 planned | Use the one protected command reader and real journal, execution and pairing owners. Never accept a Root-usable injected observation. No close-time read. If this cut registers maintenance, include both version1 format declarations, fixed per-account MachServices, generator and real-manifest tests together. |
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

### Outcome follows committed state (Toni3076/3078)

All access, activity and cancellation checks occur before the transfer or release mutation.
Arm may capture work after transfer. If any post-transfer step throws, cancel that exact shutdown binding before reporting refused.
A successful rollback leaves neither the armed target nor that connection's unarmed block. reserveStage must work again.
Refused retires the connection. A subsequent attempt needs a fresh connection and open/observe/arm sequence.
If rollback fails, return nil as an ambiguous result. Never report refused while this request may still hold an armed target.
A stale rollback must not release a newer binding. The client recovers uncertain state through b3.
Cancel/reopen prepare their applied reply first. Release is their last fallible operation; no post-release validate or capture follows it.
Failure before cancel leaves the existing armed block untouched and reports refused.

Setup serializes exchanges and waits for each response. A second concurrent exchange closes the connection.
Before arming, that close releases only the connection's unarmed block and preserves existing stage tokens.
After arming, connection close still cannot release the process-owned shutdown target.
The correction gate covers rollback, uncertain rollback, fresh reconnection, pre-release validation and actual concurrent calls.
The listener candidate remains unapplied, uncompiled and untested in /private/tmp; b2c follows the corrected endpoint.

### Fixed listener completion (Toni3073 and3088)

Source94a9ee11 adds the fixed account maintenance listener above corrected endpoint905b3bfb.
The complete listener cut changes146 production lines and adds16 test methods.
Scope checks bind each active participant to the retained role, identity, team, generation, code hash and fixed executable path.
Both participants must read and write maintenance wire version1.
The native constructor requires Root identity and validates the current Authority executable before activation and each accept.
The injected owned constructor refuses Root. It provides the anonymous XPC test fixture.

The listener retains disconnected endpoints until their actual work and release activity settle.
Listener teardown preserves the process-owned armed binding. Only the exact explicit cancel or reopen target can release it.
Concurrent joined closes wait for actual noncooperative work, including work disconnected before listener close.
Connection limits, handshake expiry, builder failures and early close return their exact reservations.
No product listener registration or maintenance writer declaration is added.
The protected native access producer and actual owner composition remain required in b4.

The first83d61ddc run failed because one test constructed an invalid ReleaseFormat before scope validation.
Its failed terminal74242/1/3a6d4d and original logs remain unchanged.
Fixture-only94a9ee11 passed gate14466/0/3a77a7 and the full scope class in gate84763/0/c44f42.
Toni3088 requires byte-identical test files for reuse. The five earlier scope passes are not admitted as transfers.
There are50 fresh unique methods and110 explicit unchanged-class transfers. One selected method also ran before the full class.
The54 Python results remain explicit transfers. This is not a full Core or Release qualification.
Root positive code admission, installed execution, the b4 factory and the full goal remain incomplete.
Next is b3, following the existing serialization and ambiguous-state recovery contract.

### Setup maintenance client and registration boundaries (Toni3091/3094/3096)

The native client derives the fixed account service. It validates the Setup self path, code hash and generation.
It configures the Authority signing requirement before activation. Hello contains only a version and no identifying metadata.
The endpoint authenticates hello on the original invocation stack. Hello creates no Connection, admission state, work task or held budget.
It does not report the listener's open handshake as complete. Open still includes the actual M05a capture.
The client verifies the Authority's kernel identity after hello and before sending any identifying request.
Each request carries a fresh challenge and the fixed account, attempt, revision, installation and gate scope.

The client allows only one complete operation at a time, including the bounded stagesPending wait.
A concurrent operation closes the connection and requires recovery. It never sends a second concurrent request.
Only stagesPending allows another arm, with the same binding and original absolute deadline.
Expiry sends cancel for that exact binding. That cleanup has its own bounded RPC timeout and never renews the arm deadline.
Refused terminates the attempt without another arm. A refused cancel or reopen requires owner recovery.
Nil, transport loss, timeout or malformed correlation requires recovery. No arm is replayed after an uncertain result.
An applied arm cannot be repeated on that client. Connection close preserves its process-owned armed target.
Explicit reopen can use an exact retained target only after a new open confirms the same incarnation.
These responses remain observations and correlation data. They grant no idle proof, marker or stop permit.

The registration cut, whether b4 or M15, must add these items together:
- Authority and Setup declare authority.maintenance-channel reader1 and writer1.
- The per-account plist declares the fixed <namespace>.maintenance address in MachServices.
- The release manifest generator and tests/test_macos_release_manifest.py include those exact declarations.
- A test checks the real generated manifest and per-account plist. A synthetic metadata fixture is insufficient.
No supporting cut may add the declarations before the actual producer becomes reachable.

Live session#725 must measure open latency with the journal busy, including the actual M05a capture.
Keep the current5-second handshake bound pending that measurement.
If open exceeds1 second, recalculate the bound or move the handshake completion before capture through a reviewed change.
The source tests do not supply this live measurement. No timeout adjustment or handshake movement is claimed here.

Source8e494e12 changes169 production lines and adds23 tests above94a9ee11.
The gate runs all affected maintenance classes fresh, plus Debug inspection, with explicit unrelated transfers.
The injected owned client and anonymous transport fixture refuse Root. Installed Root admission and product wiring remain unqualified.
Next is b4 under Toni's protected record and real owner composition contract.

### b4a, phase binding and Setup recovery (Toni3104/3108/3111/3112/3117)

The b4 responsibility is split. b4a adds the protected command reader and actual pairing stage ownership.
b4b adds the Root producer and real M05a owner composition. The listener remains unregistered.
The reader uses one protected transaction and one stable frame.
It checks the actual installed account, prepared directory, installation, registered gate, record account, attempt and current revision.
It compares a supplied binding to the current incarnation. Retained gate metadata cannot replace the native owner's incarnation.
Open, observe, arm and cancel are accepted only in draining. No action is accepted in stopping.

Only reopen may carry two revisions. request.revision is the exact current reopenPending revision.
binding.revision remains the original draining revision. Request and response codecs both enforce equality for every other action.
The b4a reader admits reopen only for notStopped/notStarted and the exact armed binding retained by this incarnation.
A missing, stale or foreign target refuses. The reader is metadata validation; b4b must retrieve the actual live shutdown owner.
A healthy reopen is refused by b4a and belongs to M09. No binding is reconstructed from readback alone.

The pairing access owns one admission object per account incarnation, shared by all its endpoints.
A real pairing attempt acquires a Stage reservation before staging can proceed.
Its staged, commit, cancel and reply owners retain handles to that same reservation.
The admission count remains one attempt until every actual owner settles.
Endpoint close inside a stage reply cannot drop the last reservation before the reply returns.
Existing stages are neither cancelled nor force-expired to make arm succeed.
Natural expiry, disconnect, failed staging and completed commit release only their actual references.

The native arm retry interval is250ms. The original absolute arm deadline is never extended.
An exact cancel after deadline is cleanup. Its bounded RPC can add up to5 seconds after the wait bound.
An uncertain cleanup reply requires owner recovery and cannot authorize a stop or body.

M07 must persist the exact five16-byte binding values with the attempt before sending arm.
Those values are correlation metadata, not credentials. Native peer authentication remains mandatory.
If persistence is uncertain, do not send arm. Never invent the saved connectionID or draining revision after a restart.
M09 reloads the saved binding, performs hello and verifies the peer again.
For notStopped, A retains that exact armed target in the same incarnation.
M09 needs an explicit hello-to-reopen path without open or a new Connection reservation.
The current b3 start method sends open and b2b begin requires an open context; this path remains unimplemented.
For healthy, A has a new incarnation and no old armed block.
M09 admits open in reopenPending/healthy, then releases only the M02 startup hold through the proper native owner.
It must retain the explicit previous-revision relationship for that restart branch. It must not adopt or mint an armed block.
Both branches still require actual admission readback before the durable Restored transition.

The original b4a draft245335ce was uncompiled and remains on its saved local reference.
Toni3117 supplied main-basedb1a1ef4a with the merged M03b2 writer and transition rules.
The draft rebased to0d0deaf1; source377f3e4a added the reply ownership tests. That gate failed on the pre-existing client race; it remains failed.
RuntimeMaintenanceWindowRecord and its tests remain byte-identical to that approved base.
No old-stack qualification or test outcome was retargeted.
The original b4a gate51157 failed; base diagnostic35382 failed1 of5, and phase diagnostic34479 failed5 of20.
The latter traces showed reopen data delivered before invalidation, then discarded by the original client.
Separate endpoint8b39f0c6 and clientf54fed93 fixes passed gate16001, including deterministic applied/refused ordering and20 clean transport repeats.
Applied cancel/reopen no longer closes on the server. The client records on-time replies synchronously before actor processing.
Local cancellation, invalidation before delivery and late replies remain closed. No armed operation is replayed.
The combined repair source is locally qualified for114 fresh unique methods plus20 extra executions and Core/Debug builds.
Intermediate b4a sourcecd5c447c replayed only its two implementation commits abovef54fed93.
Its gate24811 passed180 methods, including all10 command reader tests, then stopped at a zero-method writer selector with exit65.
The selector used the SQL writer class for a pure transition test. RuntimeMaintenanceWindowTransitionTests is a separate class.
That command contributes no test outcome. The old gate remains stopped with its original terminal and logs.
Toni3136 requested a separate gate on exact PR768 head5b265f54. Gate37748 compiled Core and passed62 fresh endpoint/admission/codec methods.
No b2c, b3 or b4a source was in that exact PR tree. No unrelated app or installed proof is claimed.
Final source645f4dfd adds the Toni3135 guard and a deterministic close-during-authorization test.
It refuses transfer of a new attempt into an endpoint that closed reentrantly. Both local and reply Stage handles then settle normally.
The changed pairing test file runs all38 methods fresh. All143 transferred test files and their production paths are unchanged.
Only the one method-body guard changed aftercd5c447c. No transferred test invokes that pairing endpoint.
The final evidence admits219 unique methods, not219 fresh methods. The20 new b4a tests include earlier exact-source admissions.
The final gate runs76 native methods fresh and reuses143 exact unchanged methods from the source-bound partial run. Python and Core/Debug are fresh. The selected base checks include the actual schema29 context method.
Two helper-only test changes add a database path; their constructor/read smoke methods run fresh. No whole replacement or unrelated native-context suite is claimed.
Gate5876 admits219 unique native methods (76 fresh and143 transferred) and54 Python manifest tests fresh, with no transfers.
Installed Root admission, the b4b factory, M09, product registration and the full goal remain incomplete.
