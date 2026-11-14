# First authenticated retained runtime caller

## Status and prerequisites

This is a document-only proposal from Toni's assignment 2693. It adds no caller or native operation.
The inspected main is `86729223e4b29780800a2959cffbef20e7785a9f`, tree `f29e57b4775309d71f312d5937c2d0ce09462b6a`.
Toni owns the plan, implementation order, native capacity, publication and merges.

Start with [issue 725](https://github.com/rock3r/remozio/issues/725).
Its authority selection and attended checks remain required. CI does not prove them.
Use the A11 live matrix in `review/a11-plan.md` at commit `65ef55fbd97f7d0e31eb6b4cc4eece404f98958e`.
That plan explicitly requires the live authority busy check before the first caller is written.
Run that attended check before implementing the cuts below. If it blocks, fix the lease ownership design first.

A11k's assembly is absent from the inspected main. Its reviewed contract is at `a81e38559d68aea18c79b35985c22f5e8294edc0`.
Implementation must wait for A11k and its actual predecessors to merge. Reconcile the final APIs with main before each cut.
The A11 source tests and the private C2 timing probe do not satisfy the attended gates in this plan.

## Entry and request boundary

Use the existing signed app to local Root Setup XPC boundary as the proposed first entry.
Reuse `AdministrativeSetupXPCListener`, `XPCInvocationGuard` and the existing administrator authorization policy.
Do not add a command-line authority selector, a phone RPC, a new service or a second privileged process.
A dedicated retained operation needs an explicit negotiated capability. Do not broaden ordinary `prepareRuntime` or `activateRuntime`.
Choose its final protocol names and version after reconciliation with the current interface. This document defines no existing selector.

The request carries only bounded stale-state observations and the existing administrator authorization form.
Do not accept a current authority account ID, policy, code hash, journal path, file path, native context or custody Boolean.
Any target identifier or revision is a stale-state comparison, never a source of authority.
The service derives the installed candidate and current machine state through existing protected readers.
The result describes the actual retained stage. It grants no consent, enrollment, activation or ordinary-ready state.

Authenticate each exported invocation synchronously before task dispatch.
`XPCInvocationGuard.verifyInvocation()` supplies the kernel UID, process ID and audit session for the accepted connection.
The listener and connection signing requirements must already be configured before activation.
Never replace these checks with a request UID, an environment value or a later PID-based code lookup.
Import administrator rights on that exported invocation. Retain a scoped rights owner, not the external form bytes.
Bind cancellation and request identity to that connection. Expiry, invalidation or cancellation stops further stages.
Keep credential and authorization checks separate: a signed peer does not establish user consent.

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
Require the target to belong to the authenticated owner and the exact retained machine operation.
Use a fresh actual target capture; compare any client observation before a mutation.
Revalidate the peer/account binding at acquisition and before the final reply. Changed bindings refuse.

## Scope construction and lifetime

Reserve one Setup operation for the authenticated caller. Reuse the existing owner reservation and reply lifetime machinery.
Keep the reservation distinct from machine writer locks and the current authority journal lease.
Do not reuse an audit-upgrade scope merely because it already carries administrator rights.
That scope owns a different operation and state transition.

Capture the actual retained Entry and import Inputs through the existing owners, under the scoped reservation.
Close the capture's machine handle before lending native providers. Do not leave a Setup pool handle to contend with A11k.
Validate any new pool suspension/resumption contract on every exit, including cleanup failure.
Keep admission closed if resource cleanup cannot complete; do not release the reservation on an uncertain close.

The proposed native composition is exactly this nested lifetime:

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

## The live busy decision comes first

Seb must attend this check on Toni's selected installed artifact, with the actual authority service running normally.
Measure `ProtectedJournalLease.acquire` for the derived current authority journal. Record the real refusal or acquisition and lease owner.
Also inspect current/target directory identities, including the case where their journal or continuity directories alias.
Distinguish contention with the live service from contention caused by this invocation's own held pair or Setup machine handle.
A free-service test alone does not prove the running-service path. Do not stop the service to obtain a green result.

If the live service keeps the exclusive lease, the current `withNativeScope` cannot yet provide this caller's normal path.
If the held current pair conflicts with the target startup writer, the same limitation applies even without another process.
Return a bounded busy/unavailable result before the policy writer can retain a new `writing` marker.
Do not add a retry loop, a second journal owner, a weaker lock or a synthetic approval.
Replan an explicit operation through the existing journal owner, or another reviewed lease handoff, before implementing the caller.
Preserve idle-only activation and the signed drain contract. This plan grants no service suspension or shared-update deferral.

An existing unresolved `writing` marker remains unavailable. Do not automatically replay or clear it.
[Issue 722's decision](https://github.com/rock3r/remozio/issues/722#issuecomment-6856960221) assigns an explicit attended owner action to P05.
It requires an exact fresh source pair, including checkpoint and revision, and follows the busy investigation.
Conflicting published file bytes also refuse. They do not authorize an overwrite or an automatic repair.

## Proposed cuts after the attended prerequisite

Each cut is a complete responsibility. Every changed production line counts, including helpers, guards and deletions.
The hard cap is 200 lines per cut. Measure before tests. Replan with Toni if the complete responsibility does not fit.
Each ready PR merges before the next cut. No stub, permissive default or temporarily exposed native token is acceptable.

| Cut | Responsibility and proposed production paths | Estimate | Required focused proof |
| --- | --- | ---: | --- |
| C01 | Bound peer/account capability and fresh resolver; new caller binding file, narrow Setup owner access | 110–185 | Two published accounts with different floors; forged ID/UID, recycled UID, policy mismatch and changed binding refuse |
| C02 | Per-invocation rights, cancellation and Setup reservation; new invocation scope, narrow existing reservation adapters | 120–190 | Rights imported before dispatch; disconnect/expiry, re-entry, cleanup failure and reply ownership |
| C03 | Native factory composition using A11k; new retained caller operation, narrow store-pool suspension if required | 100–190 | Exact factory order, capture handle closes, one call, result comparison, all exits close; no token leakage |
| C04 | Bounded versioned retained request/progress/result values; new local contract and existing interface declaration | 90–170 | Size, fields, versions and stale observation refusal; no authority or arbitrary path fields |
| C05 | Authenticated exported dispatch and service wiring; endpoint and native-only operation factory | 110–195 | Hello and invocation authentication, reservation before work, cancellation, one reply and cleanup ordering |
| C06 | App channel and existing retained maintenance flow integration; channel, driver and localized strings only | 100–190 | Unsupported capability, administrator decline/expiry, busy, stale state and explicit later recovery |

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
The busy prerequisite runs before caller implementation; complete the remaining rows before enabling the first real caller.

| Gate | Observation to retain | Refusal or recovery case |
| --- | --- | --- |
| Current authority busy, issue 725 | Exact verified owner/account binding, running service, real journal lease result and current/target identities | Live service contention, self-contention, changed owner or aliased pair; no marker write |
| Native custody, A11c | Real Root Setup, signed installed bundle, fixed executable, admission/placement, account and service identities | Changed signature, placement, generation, identity or lease refuses |
| Material, A11f | Missing material prepared once; existing key/material/activity remains exact | Custody failure, existing conflicting material or service activity refuses |
| Publication, A11g/A11i | All eight actual protected paths, modes, owners and bytes; exact existing inodes retained | Partial publication resumes only from fresh state; conflicting bytes or missing ancestors refuse |
| Completion, A11h/A11i | Correct files precede the single marker UPDATE; actual published result | Lost marker acknowledgement recaptures; published missing or damaged files refuse without repair |
| ACK, A11j | Actual held machine writer and shared journal; one conditional advance; no machine-row mutation | Real contention; committed and unchanged uncertain outcomes; no automatic repeated advance |
| Installed sequence, A11k | Material, recorded policy, files, marker and ACK under the same native loans | Fresh recovery between stages, absent/empty import skip, host changes and cleanup failure |
| Authenticated caller | Actual signed app XPC invocation, verified peer-derived authority, imported rights and correct target owner | Foreign user/account, unsupported capability, decline, expiry, disconnect and stale observation |
| First end-to-end policy commit, issue 725 | Real installed request through P04 and final reply, with exact resulting policy pair and retained stage | Busy before writing; unresolved writing is unavailable; explicit later invocation recaptures |

Record monotonic end-to-end time from exported invocation receipt through the settled reply and cleanup.
Separate peer/rights checks, reservation wait, fresh capture, current authority acquisition and native context creation.
Measure material, P04, C2 publication, D2 marker completion and ACK separately.
Count repeated `SignedReleaseInspection.inspect` calls, code checks, metadata reads and pair reads by phase.
Retain journal/machine transaction intervals separately from the enclosing method time.
Include cold and subsequent invocations, refusal latency and the service's ability to continue normal work.
Do not describe an invocation duration as BEGIN/COMMIT time, or one fixture benchmark as installed end-to-end performance.
Toni and Seb set the acceptance bound from the attended measurements before enabling this caller.
Keep existing timeout, capture and lease limits during measurement; no quiet timeout extension or relaxed verification.

Evidence contains artifact/source identifiers, environment, commands, actual outcomes, durations and redacted state comparisons.
Do not record authorization forms, keys, account secrets or raw request payloads. Do not invent unattended terminal or GUI evidence.
Installed approve/decline/expiry checks precede the 14 provider fixtures; lock/logout/restart and screen-sharing cases follow them.
Provider semantic adapters, hardware, TalkBack and platform gates remain explicit obligations outside this caller slice.
The caller does not widen shared-update ownership, consent, activation or ordinary admission.
The full Remozio objective remains incomplete.
