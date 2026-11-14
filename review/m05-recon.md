# M05 source reconnaissance for Toni

Authority: Toni2980/2984. Source7698e3ef, based on mainc7c8a222 plus M04.
This report changes no tracked source and runs no build, test or native service operation.
The requested method timings were delivered in2982, independently verified sent.
Saturn2979 reviewed M04 source only and found no blocker. Keep its poison rule: recreate only with fresh proof after any error.

## Base

M05 depends on M04's derived cohort/session. It has no compile dependency on the M03b2/M03c writers.
Use7698e3ef, or main after Toni verifies the actual M04 merge. Do not invent a ready merge.
The runtime may read an executing/draining record through the existing reader; issuing a native capability still requires fresh ownership.
The write that makes an attempt reachable remains a later composition obligation.

## Existing owners and gaps

- AuthorityCommandAuthorizationNotice.swift:6-25 and37-69: exchange ownership begins before the journal operation and ends after its post-lock authorization callback. Reuse this reservation. A journal-only zero count can miss an authorization already committed but not yet enqueued.
- AuthorityJournal.swift:308-320: one recursive lock serializes request work and rejects re-entry. Capture the actual coordinator state under this lock.
- ApprovalRequestCoordinator.swift:111-130,1097-1129: entries retain request activity and original command captures; terminal lifecycle removes these references. Expose a narrow nonmutating settlement check. Do not close or expire requests to force idle.
- AuthorityCommandExecutionWorker.swift:64-100: pending covers reservation through the queued start turn and its report. Rejected starts also reserve completion while rejectUnowned settles the journal. Inspect both actual reservations; pending.count alone misses the rejected-start path.
- AuthorityJournal.swift:1077-1081 and CommandExecution.swift:304-309: executions remain until terminal delivery, pump readiness and actual native monitor disposal succeed. Check the owned execution set, not the terminal consumption row.
- AuthorityCommandReceiveWorker.swift:199-228 and CommandReceiveHost.swift:24-40: the receiver has a serial loop, active input and retained sessions. No resumable maintenance barrier exists. Its current close requests stop and destroys the receive lifetime; it cannot be presented as passive idle observation.
- AuthorityCommandExchangeOwnership.stopAndDrain and worker.close are irreversible shutdown operations today. Reusing them would prevent pre-stop cancellation from resuming A normally. A bounded reversible owner fence needs its own state, without closing existing decisions or execution.
- AuthorityWakeService.swift:229-231 composes the authorization callback and execution enqueue. It also owns the receiver and execution worker. The final local proof must compose those actual owners with the journal and incarnation.
- GatewaySettingsControlXPCEndpoint.swift:26-45,87-100 demonstrates per-invocation Setup peer verification before async handoff and retained work through disconnect. Reuse its authentication pattern, not an injected native verifier or a caller idle Boolean.
- The M02 projection is negative metadata. On this source there is no runtime-local maintenance hold consumer outside its store reader. M05 must bind a real local hold to the exact attempt, account gate and incarnation; bytes alone cannot grant an idle permit.

## Proposed capped responsibilities for Toni to confirm

The full M05 closure spans local admission/settlement, a reversible receiver boundary, the authenticated connection, and the Setup permit/factory. It does not fit one credible200-line cut.
These are planning ranges, not measured implementations.

1. Local request/execution settlement boundary:100-180 changed production lines. Read actual coordinator owners, command execution custody, worker reservations and exchange reservations under the appropriate locks. Keep this internal; issue no stop permit or endpoint.
2. Reversible receiver/attempt ownership boundary:110-190 lines. Close new A creation using the exact existing gate and local hold, join pre-drain receive work and original session resources, preserve decision/execution lifetimes, and cancel without stopping A. No partial idle endpoint.
3. Complete authenticated live proof and permit/factory: expected to need further division if above200. Reuse the actual control authentication, bind account/installation/attempt/revision/gate/incarnation and fixed Setup code/path, and validate every local owner. Introduce the real proof type, native stop permit and factory together only when these dependencies are complete. No reachable production caller until M15.

A third cut must first be measured as a complete responsibility. If it exceeds200, split supporting wire/peer validation from the final private issuer; neither supporting cut may return an idle success or authorize a stop.

## Required negative proofs

Pause an authorization callback after the commit and before enqueue; idle must refuse.
Keep a rejected-start cleanup active without a pending dictionary entry; idle must refuse.
Keep a terminal native execution with an unsettled pump/monitor; idle must refuse.
Pause receive input/session cleanup and pre-drain creation; idle must refuse.
Keep an existing pending decision or execution; preserve its lifecycle and refuse idle.
Change attempt/revision, protected gate, current A, Setup code/path or listener incarnation; revoke the proof.
Disconnect before removal, cancel or exceed the pre-stop bound; no stop and no forced expiration.
Bind the stop to the same Authority incarnation that supplied the proof. A replacement PID cannot inherit it.
After the exact removal starts, expected connection loss must be reconciled with the original process witness, not a fabricated live reply.
Keep audit EX guards unchanged and B/transport/gateway/other accounts outside the cohort.

No native identity, installed handshake, live idle, child-settlement, service stop or Release qualification is claimed by this report.
