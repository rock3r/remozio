# M11 and M12: visible status and explicit restoration (contract, Toni, 2026-11-16)

Source: bepi's audit `/private/tmp/remozio-bepi-M11-M12-source-audit-3786-20261116/AUDIT.md`, on current main plus the unmerged M10b (`d49979f9`) and M09d (`83a3f816`) snapshots. Plan: `maintenance-window-plan-c762abad.md`, lines 279–349, and the M09d contract section 8.1.

## 1. Decisions

1. **Code waits for the merges.** M11 and M12 build on M09d (#790), M10a (#791), M10b (#792) and M10c1 (#793). Until those merge, only design proposals are written, with no code.
2. **Status never borrows admission.** M11 adds a separate status lane. It keeps the signed peer policy, the exported invocation check, the protected installation identity and the process checks. It needs neither of the two reserved admissions, and it never waits for a body to settle. Nothing in `verifyCurrent`, mutation admission or the handshake is weakened.
3. **Each fact is reported separately.** Status reports, each as its own field:
   - the reservation state;
   - the operation outcome;
   - the restoration state;
   - the cleanup state;
   - the supervisor observation.

   An orphan is not a failure, a rollback or a success. If the durable facts cannot be read without blocking, status says "unavailable" and never infers a terminal result.
4. **The owner is recorded at construction.** The reservation record keeps the authenticated peer UID (account A's owner) when it is created. It adds the protected A/B binding only after the capture has validated it. Status and the M12 action are disclosed only to that same authenticated owner. A UID taken from the request is never trusted, and the target account B's UID is never treated as the peer's.
5. **M12 is explicit and separate.** It has its own factory and needs fresh administrator rights. It never relaxes the automatic startup policy (M09d section 8.1), and the `needsOwnerRecovery → restoring` edge is not an authorization by itself.
6. **No body replay, no invented state.** M12 never repeats a body, invents a shutdown binding or clears another drain. A missing process is never accepted as proof of safety.

## 2. Cuts

| Cut | Scope | Notes |
| --- | --- | --- |
| M11a | The status model, plus the authenticated owner and binding in the reservation record. Bounded, non-mutating reads. Library only, not reachable. | After #792 merges. |
| M11b | The status lane in the Setup endpoint: authenticated, bounded and available during a reservation. | A design proposal comes first (section 3). |
| M12a | Explicit claim of an exact orphan record. Fresh rights from the same owner; the new connection incarnation is kept separate from the old one. Joins run outside the owner and invocation locks, and the tokens are released only after every join. No second admission. | After #792 merges. |
| M12b | Explicit restoration of a `needsOwnerRecovery` window, with fresh custody, through `needsOwnerRecovery → restoring` and the M09d healthy flow. This also covers a startup `reopenPending` whose healthy candidate was lost: M09d already moved it to `needsOwnerRecovery`, so M12b restores it from there with a fresh healthy open. A not-stopped window uses the existing saved-target reconnect. | After #790 merges. The order stays: pending, matching drain release, reopen, readback, restored. |
| M12c | Explicit release of an `authorized` window that has no shutdown binding. | It needs an Authority-side command, so a design proposal comes first (section 3). |

## 3. Design proposals to write now (source only, no code)

- **M11b, the status lane.** Decide between a status-only connection mode on the existing listener and a separate method. Show exactly which checks run at connection time and which run per call, and why a mutation can never ride on a status-only connection. Explain how the lane stays bounded while the owner lock is held, without blocking.
- **M12c, the unbound release.** Describe how Setup proves that no body, loan or cleanup remains for a window without a shutdown binding. Describe the Authority command that releases A's startup hold for such a window: its request, its authentication, and the checks against the row and the incarnation. Explain why the command cannot release any other hold.

## 4. Tests

The test boundaries in the audit (its final table) are the required tests for these cuts. Each cut takes the rows that apply to it.

## 5. Decisions on the M11b and M12c proposals (Telegram 3797)

Proposals: `/private/tmp/remozio-bepi-M11b-M12c-design-3795-20261116/{M11b.md,M12c.md}`.

**M11b, accepted as proposed:**
- An authenticated facade on the existing listener. A connection that selects status first becomes StatusOnly for good. Only a full normal handshake creates the mutation endpoint, and every normal selector requires it.
- Status reads a projection published separately from the owner lock. Facts are reported as unavailable when the writer lease or the publication lock is busy. Status never waits for a body.
- **Slot accounting accepted:** within the existing total of 8, at most 6 normal or opening connections, 1 StatusOnly and 1 undecided. The 5 s handshake timeout is unchanged.
- One test lists every exported selector and tries each normal selector before and after status is selected.

**M12c, accepted, and scheduled last among M11 and M12:**
- A separate typed unbound-release request and an unbound gate readback, sent on the existing maintenance channel. There is no `reopen(nil)` and no fake binding.
- Setup proves positively that the body never entered, no stop was issued, and every worker, loan and cleanup has joined. The evidence comes from a sealed claim and a lifetime ledger kept apart from the weak invocation. A missing PID, a nil weak reference or elapsed time is never proof.
- **Durable format accepted:** a new, bounded unbound-release descriptor, in an explicit new window-record format version, with a compatibility declaration for both peers. Old readers refuse the feature.
- **Narrow edge accepted:** only the typed unbound-release writer may take `needsOwnerRecovery → reopenPending`. It needs the same positive non-entry proof and exact authorized-origin evidence. Every other writer keeps its current rules.
- **Per-account command exclusion accepted:** it is short and non-blocking; a held exclusion returns busy, and it also excludes an arm that validated earlier.
- On the Authority side, the startup hold keeps a typed identity (origin, account, installation, window, revision or digest, incarnation). Startup holds and command holds stay distinct.
- After a Setup restart without a ledger that can be rebuilt, the result is `repairRequired`. Until M12c ships, an `authorized` window without a binding also stays `repairRequired`, shown by M11.

**Order after the merges:** M11a, then M12a, then M12b, then M11b, then M12c. M10c2 and M10d come before M11b, because the status lane is only useful once recovery is connected.

## 6. M11a review and M12a boundary (Telegram 3831, 3833)

**M11a fixes before the PR** (independent review `m11a-independent-review.md`, no serious defect):
- Status binds the exact window identity (id, revision or digest, purpose, candidate) as soon as the maintenance capture knows it. Without it, `observing` exposes no window, operation or restoration fact. An older window for the same A/B pair must never lend its outcome.
- The worker is its own fact. "Cleanup pending" only means registered cleanups exist.
- Before the binding is captured, status exposes the reservation state only, not the reservation ID or the incarnation.
- Tests: bind through the real caller and maintenance capture paths, record replaced during a read, status while the worker runs, another window with the same A/B pair.

**M12a boundary:**
- The claim seals the record and keeps its ledger even if the caller disappears. Joins are single-flight and run outside the locks. Nothing resets the never-entered marker.
- A join alone is never permission to reopen a window.
- An orphan with no maintenance window (no captured binding, or no window write before the body) has nothing to restore. M12a releases its admissions and shared activity after all joins are verified, because M12b and M12c never handle it.
- An orphan with a window keeps its tokens until M12b or M12c settles it.

## 7. Obligations from the #795 review (Telegram 3860)

- M11b: the endpoint selects the owner slot from the authenticated peer, so another UID never reaches A's slot. As defence in depth, the reader answers `unavailable` (not `absent`) for an empty slot when the UID does not match the slot's owner.
- M12a (already in its draft): the reservation records the authenticated directory identity at construction, and status compares it before answering, so a recycled UID sees nothing even before the binding.

## 8. M12b origins (Telegram 3867, decision 3868)

M12b restores a bound `needsOwnerRecovery` window explicitly, through two origins of the same flow:
1. **In-process:** requires M12a's exact `Joined` for the same window and scope. No restoration without it.
2. **Restart:** fresh rights from A (UID and directory identity verified on the actual peer) plus the current Setup's real native custody: fixed instance (M10a lease), machine lease, exclusive drain and protected frame. It refuses if this process holds a retained record for the same account or window; that case must use the in-process origin. A distinct capability type; no invented never-entered proof.
3. **Both:** a durable bound window with a real shutdown binding, `needsOwnerRecovery` and a recognised origin; then `needsOwnerRecovery → restoring` and the M09d healthy or reconnect flow in the same order (pending, matching drain release, reopen, readback, restored). An unbound window stays `repairRequired` until M12c. The automatic startup policy does not change.
4. If the patch is too large for a clear review, split it by origin (M12b1 in-process, M12b2 restart), each a complete scope.

## 9. M12a review fixes (independent review, Telegram 3869)

- The window latch fires when `maintenanceCapture` succeeds, before the capture is returned, and again in `recaptureMaintenance`, which must also match `capture.window` and the chain's window to `capturedWindow`. Window-free release then applies only to orphans with no maintenance capture at all. An orphan with a capture but no durable row stays held until restart (safe side).
- Endpoint obligation (M11b and the M12 endpoint): call `abandon()` when the claimant's connection is lost, or a dead claimant blocks fresh claims while `join()` waits.
- Limits count live loans and cleanups, or the lifetime limit is justified. Record and ledger get redacted mirror and dump output. Status reports a failed join explicitly.

## 10. From the #796 review (Telegram 3880)

- M12b: `authenticatedOwner` becomes a required parameter (no `nil` default) in `SetupAccountOwner.reserveRetainedInvocation` and in `SetupRetainedInvocationReservation.init`, so a future caller cannot skip the directory-identity check in status.

## 11. M12b1 v1 review (independent review m12b1-v1-independent-review.md, Telegram 3889)

Request changes before any gate:
1. Explicit reconnect follows the automatic path's revision handling exactly (the v1 random pending revision made every reconnect end in `needsOwnerRecovery(admissionUnconfirmed)`), with a test that reaches `restored`.
2. Blocking native stages (open, rights checks, launchctl, final readback) run on the owner's 8 MiB executor in sequential stages; XPC awaits stay outside.
3. While an unsettled completion exists, a new attempt is refused; only adoption is allowed.
4. Failure and abort writes use Setup's fixed identity and real custody, not caller rights. No new row shape that M09d cannot already handle; test M09d startup on every row the explicit path can leave after a crash.
5. The pre-release completion check matches the post-write check (host, job, account directory). `originalRunFailed` is either refused or documented as safe.
6. Explicit reconnect only where M09d would reconnect, with the same incarnation rules.

## 12. M12b1 v2 review decisions (m12b1-v2-independent-review.md, Telegram 3896)

- Accepted: after a crash, automatic M09d continues an explicit `restoring` row through its healthy path with its own fresh custody. The restoration was already authorized and written. Documented and tested.
- Accepted for M12b1: same-incarnation reconnect is always refused with `repairRequired` until `retainMaintenanceRecoveryTransition` gets a production caller (M10d wiring). The refusal writes nothing (tested).
- `verify()` in `AuthorityMaintenanceXPCClient.invoke` stays only if it is existing base behaviour; otherwise it moves into an executor stage.
- Automatic M09d must stay identical: restore the original error mapping in `requireRestoringProcess`, restore the healthy check order (or prove identical behaviour by test), keep the exact failure code on deadline cancellation, record a reconnect that failed before pending as not stopped, and validate the code once.
- Then the 15-scenario matrix and the full gate (1800 s, extendable to 2700 s by a separate continuation).

## 13. M12b1 gate notes (Telegram 3907–3919)

- The first gate run failed one healthy new-incarnation scenario: the fixture's 12 s forward deadline was hit (restore ~13–14 s; `restored` lands at ~12 s). Production behaviour was correct (tokens held, close `unavailable`). Fix, test only: 25 s for that case (as the M09d helper) plus an explicit "forward deadline expired" assertion. Measured 13.86 s of 25 s.
- Follow-up, not in M12b1: profile the healthy path. In the fixture about 8 s pass between the decision and `pending`, spent in real frame re-reads and floor checks (`requireCurrent`, `validateBeforePending`), not in fixed waits. Production deadline is 120 s.

## 14. #797 review fix (chiacchiersaturn, Telegram 3941–3943)

- With no phases (automatic path), `restorationPhase`/`restorationCleanup` run `body()` synchronously on the client actor, with no added suspension points, so the automatic path is identical to main. The guards in `restoreStartupHealthy` must not be separated from the work by an await.
- `RecoveryToken.settleRestoration` becomes fileprivate, or performs the readback itself.
- Reduced gate on the touched classes, Debug/Release and 57 manifest tests; budget 1800 s.

## 15. M12b2 v1 review decisions (m12b2-v1-independent-review.md)

- H1: the restart slot (2 admissions + shared activity) must have a rights-checked exit, and must be released on every refusal before custody or RPC, when no live task, unsettled completion or uncertain writer remains. It must never stay held until process exit.
- M1: adopting a finished completion is allowed while the owner closes, so `closeWhenIdle` can finish.
- M2: the restart capability cannot be forged inside the module: record init and claim are fileprivate, no injectable owner check outside an Owned-only seam, phases/work/barrier constructors stay fileprivate.
- M3 (decided): the restart origin refuses only when an in-process record for the same account or window is NOT settled. A settled record has no `Joined`, so M12b1 cannot resume it; refusing it would leave a dead end until restart.
- Low: blocking calls in `claimRestartRecovery` run on the executor; restore the original error type order in capture.

## 16. M12b2 v2 decisions (m12b2-v2-independent-review.md)

- N1: the restart attempt records whether its last confirmed row is at rest (`needsOwnerRecovery` or `restored`). The rights-checked exit requires that; otherwise the slot stays held, as for an uncertain writer.
- N2: the exit is bound to the current claim's identity, so an older abandoned or failed claim cannot release a newer claimant's slot.
- The closing test uses a stopped origin and asserts no new write or RPC.
- Known and accepted: a failed attempt with forward effects waits for A's rights to exit or retry, and an uncertain writer holds the slot until process exit; `closeWhenIdle` then waits for launchd.
- Gate approved after these: all methods of added/changed classes, Debug/Release, 57 manifest, 10 Signed; 1800 s, extendable to 2700 s.
