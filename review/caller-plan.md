# First authenticated retained runtime caller

## Status and prerequisites

This is a document-only proposal from Toni's assignment 2693. It adds no caller or native operation.
The inspected main is `b899e1ad34836b37745f9099db8d2594ea384150`, tree `3117e2d9c6460a2c52bea8a55c25dd80f8328f3a`.
Toni owns the plan, implementation order, native capacity, publication and merges.
This revision applies Saturn's review 2702 and Toni's decisions 2703, 2706 and 2708. The prior same-owner rule was contradictory.

Toni's 2757/2763/2767 decisions supersede the old busy-first implementation prerequisite.
The [source analysis](725-busy-analysis.md) established the lock conflict; retained work uses the [per-account maintenance window](maintenance-window-plan.md).
C01/C02/C04 may proceed as library/contract work without dispatch. C03/C05 wait for M05–M07 and the retained M15 closure.
The [725 plan](725-experiment-plan.md) retains installed commit and timing validation before enabling a real caller.
A11k is merged on inspected main `b899e1ad34836b37745f9099db8d2594ea384150`.
Reconcile the actual merged APIs and preceding ready PR before each cut. No installed live gate is passed by this document.

## Entry and request boundary

Use the existing signed app to local Root Setup XPC boundary as the proposed first entry.
The calling app session belongs to the owner of the current authority, not the owner of the historical target.
Reuse `AdministrativeSetupXPCListener`, `XPCInvocationGuard` and the existing administrator authorization policy.
Do not add a command-line authority selector, a phone RPC, a new service or a second privileged process.
A dedicated retained operation needs an explicit negotiated capability. Do not broaden ordinary `prepareRuntime` or `activateRuntime`.
Choose its final protocol names and version after reconciliation with the current interface. This document defines no existing selector.

The request carries only bounded stale-state observations and the existing administrator authorization form.
Do not accept a current authority account ID, policy, code hash, journal path, file path, native context or custody Boolean.
Any target identifier or revision is a stale-state comparison, never a source of authority.
The service derives the installed candidate and current machine state through existing protected readers.
The result describes the actual retained stage. It grants no consent, enrollment, activation or ordinary-ready state.

C05 applies C01's peer binding to `retainedRuntimeProgress` before returning or encoding any target observation.
Only the verified owner of the current authority, using its approved app peer, may receive target ID, revision or digest.
This binding is required even though the progress selector carries no administrator authorization form.
A different local user with a correctly signed app receives nil or a refusal without any target observation.
The listener's accepted local UID and a valid app signature alone do not establish the current authority binding.
Derive the peer from the actual invocation and protected C01 state. A request UID or target identifier cannot replace that derivation.
C05 tests must include the current authority owner and another local user with the signed app.
The first receives scoped progress. The second receives nil or refusal, with no target ID, revision, digest or target-existence disclosure.

Authenticate each exported invocation synchronously before task dispatch.
`XPCInvocationGuard.verifyInvocation()` supplies the kernel UID, process ID and audit session for the accepted connection.
The listener and connection signing requirements must already be configured before activation.
Never replace these checks with a request UID, an environment value or a later PID-based code lookup.
Import administrator rights on that exported invocation. Retain a scoped rights owner, not the external form bytes.
Bind cancellation and request identity to that connection. Expiry, invalidation or cancellation stops further stages.
Keep credential and authorization checks separate: a signed peer does not establish user consent.
The imported administrator rights authorize this privileged machine operation. They do not select the target or create its consent.

## Derive the current authority from the verified peer

Introduce one internal connection-bound caller capability. Its production factory accepts the actual invocation guard and protected Setup owner.
Owned tests cannot mint a production capability. Do not expose an initializer that accepts arbitrary credentials or an account ID.
Record the accepted peer policy, invocation incarnation and verified UID with the scoped rights owner.

Resolve the current authority from a fresh protected inventory using the verified peer's UID.
`InstallationInventory` requires unique owner UIDs. Require exactly one matching current account; absence or ambiguity refuses.
Validate its retained account record, complete initialization, installation and current directory identity.
Use `LocalAccountDirectory` to bind the account's directory ID to the verified UID. A recycled UID must refuse.
Then use the existing published command-host validation for that derived account.
Never scan published accounts until one happens to pass, or substitute the target's historical account.

Bind the accepted app signing requirement to this current authority's active `.app` policy entry.
Require the configured requirement to match the requirement derived from its approved app identity and code hash.
Keep the accepted policy evidence in the connection capability. Do not reconfigure an active connection to manufacture a match.
If the accepted hash set cannot prove that match, refuse and add a reviewed connection-bound verification seam before proceeding.
The UID mapping alone does not establish the current authority's code policy or release floors.

Pass only the derived current account ID to `RuntimeNativeAuthority.withNativeScope`.
Its internal `currentAuthorityAccountID` argument remains an implementation detail behind the caller capability.
The held current authority policy supplies executing-code checks and `ReleaseGenerationPreflight` floors.
The target's recorded startup policy supplies historical file bytes only. Neither policy can replace the other.
Derive the target only from fresh protected retained machine state, including inventory and the actual journal records.
Require exactly one retained setup operation in progress. Zero or multiple operations refuse; the request cannot choose between them.
Require its target account ID to differ from the current authority account ID.
The target can be outside the current inventory. `MachineUpdateStableRuntimeSource` requires unique owner UIDs across all source accounts.
Its protected retained account therefore binds a different UID from every installed account. Validate its current directory identity independently.
That target's verified `LocalAccountIdentity` becomes `runtime.setup.owner` and the `owner` argument passed to `prepare`.
Never pass the peer's owner identity as the target owner merely because the peer invoked Setup.

Admission needs three separate proofs, as decided by Toni in message 2706:

1. Administrator rights imported on the verified exported invocation authorize the privileged machine operation.
2. The target's existing retained initialization, material, import and relay records bind its recorded choices and consent.
3. The unique in-progress retained operation identifies a different target account and UID through protected machine state.

The caller may advance only that retained operation through A10/A11's exact frame checks.
Validate actual absent or empty material/import states through the existing phase rules; do not require fabricated consent records.
It cannot create target consent, replace recorded choices, enroll an account or choose another target from a payload.
The peer-derived current authority supplies code policy and release floors; it does not supply the target's consent.
Retain those two account bindings as distinct values throughout the invocation.
Compare any client target observation with the selected protected state before a mutation. It grants no authority.
Revalidate both account bindings and the exact selected operation at acquisition and before the final reply.
A successful final transition may complete the selected operation; validate that actual result instead of selecting a different pending operation.
Changed identities, choices or unrelated retained work refuse.

## Scope construction and lifetime

Reserve one Setup operation for the authenticated caller. Reuse the existing owner reservation and reply lifetime machinery.
Keep the reservation distinct from machine writer locks and the current authority journal lease.
Do not reuse an audit-upgrade scope merely because it already carries administrator rights.
That scope owns a different operation and state transition.

Capture the actual retained Entry and import Inputs through the existing owners, under the scoped reservation.
The production storage contract is decided: no Setup pool suspension is needed or added in C03.
`SetupAccountOwner.open` uses `Machines.scoped`; each `machines.use` opens a fresh handle and closes it before returning.
The `.retained` form serves logical fixtures. It does not describe the production lease lifetime.
Return successfully from the scoped capture before constructing any native loan. Never call the native factory inside `machines.use`.
A capture-close failure prevents native entry. Keep the reservation until cleanup settles; do not silently reopen or admit another operation.
Use the existing native factories to open their own scoped machine handles. Test their closed boundaries, not a persistent pool.
This decision depends on production keeping scoped access. If production adopts `.retained`, revisit C03 and its estimate before implementation.

Enter the qualified per-account maintenance owner before constructing native loans: shared machine admission, A account drain, live idle proof, stop and process/child exit.
C03 must prove each authorized window-record transition, then recapture the same A/B source and choices under the actual invocation owner.
Do not ignore a full-source mismatch or reselect another target. Persist the executing phase before borrowing body frames.
No window-row writer runs inside those callbacks.
The existing native composition then uses this nested lifetime:

1. Call `MachineUpdateRetainedSetupRuntimeNativeAuthority.withNativeScope` with the fresh Frame and derived current authority account ID.
2. That factory creates the actual `HeldScope` and `NativeCustody`. The caller does not construct either token.
3. Call `RuntimeNativeContext.withCurrentAuthorityApproval(from: heldScope)` for the scoped current authority approval.
4. Call `RuntimeNativeContext.withNativeContext(custody:approval:expected:candidate:perform:)` to construct the `NativeContext`.
5. Call `MachineUpdateRetainedSetupRuntimeNativeEntry.prepare(context:authority:owner:candidate:)` once inside those loans.
6. Validate the actual result, settle all resource owners and the reply, then release the Setup reservation.

The shorter `RuntimeNativeContext` name above refers to `MachineUpdateRetainedSetupRuntimeNativeContext`.
The factory chain must match the merged A11k APIs. No new public token or general verification callback is needed.
Construct all process/thread-bound loans inside one worker execution. Do not suspend, await or change thread while they are active.
Move work to that worker only after authenticating and importing rights on the exported invocation.
Check cancellation and rights through their bound owners. Do not call `verifyInvocation()` from an unrelated asynchronous executor.
Provider callbacks use borrowed frames. They perform zero public machine queries and never reopen a held import journal.
Preserve the capture caps, exact comparisons, poison guards and close-before-policy-write boundary from A11.
Do not hold the historical target read-only pair across P04's startup write.
Do not cache a `HeldScope`, approval, `NativeContext` or prepared Frame across requests.

## Maintenance ownership and installed validation

The current service retains its exclusive journal; an idle queue cannot make the local native pair available.
Do not add busy polling, a weaker lock, a second journal owner or a synthetic approval.
The retained owner keeps shared machine admission and drains only A's account through its registered barrier.
It obtains the real live idle/child-settlement proof before stop. A pre-stop timeout cancels and reopens A without stopping it.
After the separate maintenance stop facade and exit witnesses, the existing native factory pins A's full read-only pair.
Other accounts continue approval work; no machine-wide quiescence loan or P04/A11 admission rewrite is required.
Conflicting bootstrap/recovery must respect the durable window. A's account closure restores before new requests after restart.
The outer owner restores/adopts A and verifies readiness/floors before releasing its account drain and shared machine activity.

Seb attends installed native commit and timing validation on the selected qualified artifact after these mechanisms exist.
Measure A's full unreachable interval separately from current-pair hold time and end-to-end invocation time.
Validate current/target directory identities and aliased journal/continuity paths. Busy or uncertainty refuses; no automatic body replay.
The [maintenance plan](maintenance-window-plan.md) defines actual idle proof, bootstrap guards, visible recovery and the attended restoration-only exit.
It does not claim those installed mechanisms already exist. No service stop is reachable before the retained M15 gate qualifies.

An unresolved `writing` marker remains unavailable. [Issue 722](https://github.com/rock3r/remozio/issues/722#issuecomment-6856960221) assigns its explicit owner action to P05.
P05 still requires exact fresh source equality, including checkpoint/revision; normal resume never resets it.
P05a–d may follow M03 as library work. Its native facade/reachability require the same M05–M07/M15 closure.
Conflicting published file bytes refuse; they authorize no overwrite or automatic repair.

## Open product decision: retained consent age

The current proposal has no age-based expiry for the target's recorded retained consent, as Toni specified in message 2708.
This does not relax exact frame, identity, revision, scope or authorization checks. Changed state still refuses.
Toni will ask Seb whether an old retained setup needs an additional age limit during the attended installed session for issue 725.
If Seb selects a limit, add its `stale` refusal at C01's protected target admission check and test its boundary before implementation.
Do not invent an expiry duration, refresh recorded consent automatically or infer a new target confirmation from administrator rights.
This question does not block review of this document. The installed prerequisites still precede enabling real caller dispatch; C01/C02/C04 can proceed without it.

## Proposed cuts and maintenance prerequisites

Each cut is a complete responsibility. Every changed production line counts, including helpers, guards and deletions.
The hard cap is 200 lines per cut. Measure before tests. Replan with Toni if the complete responsibility does not fit.
Each ready PR merges before the next cut. No stub, permissive default or temporarily exposed native token is acceptable.

| Cut | Responsibility and proposed production paths | Estimate | Required focused proof |
| --- | --- | ---: | --- |
| C01 | Bound current-authority peer and unique protected target resolver; new caller binding file, narrow Setup owner access | 110–195 | Different UIDs; admin rights plus retained target consent; zero/multiple pending setups and changed state refuse; age-based stale seam if selected |
| C02 | Per-invocation rights, cancellation and Setup reservation; new invocation scope, narrow existing reservation adapters | 120–190 | Rights imported before dispatch; disconnect/expiry, re-entry, cleanup failure and reply ownership |
| C03 | Native factory composition using A11k after existing scoped capture closes; no pool suspension | 100–190 | No native entry inside machines.use; close failure prevents entry; exact factory order, one call, result comparison and all exits close |
| C04 | Bounded versioned retained request/progress/result values; new local contract and existing interface declaration | 90–170 | Size, fields, versions and stale observation refusal; no authority or arbitrary path fields |
| C05 | Authenticated exported dispatch, peer-bound progress and service wiring | 110–195 | C01 binding on progress; another signed local user receives no target data; reservation, cancellation, reply and cleanup ordering |
| C06 | App channel and existing retained maintenance flow integration; channel, driver and localized strings only | 100–190 | Unsupported capability, administrator decline/expiry, busy, stale state and explicit later recovery |

C01 must include a successful admission with different authority/target UIDs and different policy floors.
Assert that the authority policy supplies floors while the target supplies only its recorded choices.
Keep forged-ID, recycled-UID, signing-policy mismatch and changed-binding refusals.

C01 and C02 add no exported dispatch. C03 adds no new privileged process or job registration.
C04 exposes no implementation callback or native token. C05 uses only the native factory in a Root endpoint.
C06 preserves the Setup UX and current approval contracts. It adds no automatic startup, timer or activation action.
The file names are proposals. Reuse an existing owner where its contract matches instead of adding a second responsibility owner.

Source checks must cover each changed class on the exact committed source through ATC after Toni grants the native slot.
Retain actual commands, source hashes, environment, per-case outcomes and consumed terminals. Failed attempts remain failed.
Use owned controls for refusal, ordering and lifetime. They do not prove Root custody, live service contention or provider semantics.
Keep the existing 120-second command limit and 1800-second allocation per assigned cut. A larger scope needs Toni's explicit replan.
Do not rerun unchanged passed suites to repair records. No test bypasses a mandatory native verifier.

## Attended matrix and timing evidence

Every row below requires Seb at the Mac. No row is passed by this document or by source tests.
Toni selects the final qualified artifact and exact installed configuration before preparing the interactive handoff.
Source ownership decisions precede dispatch implementation; complete the required installed rows before enabling the first real caller.

| Gate | Observation to retain | Refusal or recovery case |
| --- | --- | --- |
| Current authority maintenance, issue 725 | Peer-derived authority, distinct protected target, healthy-service busy control, A account drain/idle/exit, acquired pair and full held duration | Live contention, self-contention, lease duration over the bound, changed identity or aliased pair; no marker write on admission refusal |
| Native custody, A11c | Real Root Setup, signed installed bundle, fixed executable, admission/placement, account and service identities | Changed signature, placement, generation, identity or lease refuses |
| Material, A11f | Missing material prepared once; existing key/material/activity remains exact | Custody failure, existing conflicting material or service activity refuses |
| Publication, A11g/A11i | All eight actual protected paths, modes, owners and bytes; exact existing inodes retained | Partial publication resumes only from fresh state; conflicting bytes or missing ancestors refuse |
| Completion, A11h/A11i | Correct files precede the single marker UPDATE; actual published result | Lost marker acknowledgement recaptures; published missing or damaged files refuse without repair |
| ACK, A11j | Actual held machine writer and shared journal; one conditional advance; no machine-row mutation | Real contention; committed and unchanged uncertain outcomes; no automatic repeated advance |
| Installed sequence, A11k | Material, recorded policy, files, marker and ACK under the same native loans | Fresh recovery between stages, absent/empty import skip, host changes and cleanup failure |
| Authenticated caller | Current-authority owner calls signed app XPC; imported admin rights; unique different target and retained consent from protected state | Wrong policy, same account/UID, zero/multiple pending setups, changed target consent, decline, expiry, disconnect and stale observation |
| First end-to-end policy commit, issue 725 | Real installed request through P04 and final reply, with exact resulting policy pair and retained stage | Busy before writing; unresolved writing is unavailable; explicit later invocation recaptures |

Record monotonic end-to-end time from exported invocation receipt through the settled reply and cleanup.
Separate peer/rights checks, reservation wait, fresh capture, current authority acquisition and native context creation.
Record current authority journal lease acquisition and actual release separately. Include all native stages in its held duration.
Measure material, P04, C2 publication, D2 marker completion and ACK separately.
Count repeated `SignedReleaseInspection.inspect` calls, code checks, metadata reads and pair reads by phase.
Retain journal/machine transaction intervals separately from the enclosing method time.
Include cold and subsequent invocations, refusal latency and A's unreachable interval. Verify that other accounts continue normal approval work.
Do not describe an invocation duration as BEGIN/COMMIT time, or one fixture benchmark as installed end-to-end performance.
Toni and Seb set the acceptance bound from the attended measurements before enabling this caller.
The acceptance bounds cover end-to-end delay, A's full unreachable interval and the current journal lease duration separately.
Initial acquisition success alone cannot pass this acceptance gate.
An overrun fails attended acceptance and blocks enabling the caller. It never authorizes forced lease release or replay of a committed stage.
Keep existing timeout, capture and lease limits during measurement; no quiet timeout extension or relaxed verification.

Evidence contains artifact/source identifiers, environment, commands, actual outcomes, durations and redacted state comparisons.
Do not record authorization forms, keys, account secrets or raw request payloads. Do not invent unattended terminal or GUI evidence.
Installed approve/decline/expiry checks precede the 14 provider fixtures; lock/logout/restart and screen-sharing cases follow them.
Provider semantic adapters, hardware, TalkBack and platform gates remain explicit obligations outside this caller slice.
The caller does not widen shared-update ownership, consent, activation or ordinary admission.
The full Remozio objective remains incomplete.
