# Issue 725: journal ownership and maintenance choices

## Result and scope

The busy conflict is structural while the selected authority service owns its healthy open journal.
It is not a rare scheduling race. An idle listener or a completed SQLite transaction does not release `writer.lock`.
An independent P04b/A11 opener cannot obtain that same exclusive lease during this lifetime.
An alive but failed, starting or already closed process is not a counterexample to that healthy-service statement.

This is source analysis of main `987ea4eee9bd4e4b25428508d2afb39069fc5e29`, tree `d7eca2ef5d6c00fec9b745cad02bd845721df063`.
The working branch adds review documents only. No build, test, live probe, service action or platform experiment ran.
Toni requested this analysis in messages 2731, 2734 and 2737. No maintenance design is selected here.

## 1. The lease has no healthy-service release window

| Source anchor under `macos/core/Sources/RemozioCore/` | Actual behavior |
| --- | --- |
| `AuthorityService.swift:23`, `:72`, `:138` | The service retains its journal. Production startup opens the protected store and transfers ownership to the service. |
| `JournalDatabase.swift:18`, `:46`, `:163`, `:443` | The database privately owns `ProtectedJournalLease`. `close` rejects an active transaction; shutdown closes SQLite and then the lease. Transaction completion does not close it. |
| `ProtectedStorageLease.swift:67` | The actual `writer.lock` open gets `LOCK_EX | LOCK_NB`. `EWOULDBLOCK` becomes `JournalLeaseError.busy`. Read-only SQLite does not make this a shared file lock. |
| `AuthorityService.swift:253`, `:256`, `:274`, `:285` | Destruction, failed startup, maintenance retirement and explicit close release resources. Explicit close first stops maintenance and the listener. This is service shutdown, not a running-service loan. |
| `AuthorityRuntimeRunner.swift:108`, `:130`, `:163` | Closing or retiring a runtime closes its owned instance. Retry after startup failure can occur, but there is no healthy running lease handoff to Setup. |

`MachineUpdateRetainedSetupPolicyNativeEntry.swift:18–36` opens the current authority journal before the target policy writer runs.
`MachineUpdateRetainedSetupRuntimeNativeAuthority.swift:63–87` does the same for A11's whole native scope.
Both use the protected read-only opener, which still acquires the exclusive journal and continuity leases.
`MachineUpdateRetainedSetupPromotionNativeSupport.swift:60–101` holds that pair through the callback and closes it afterward.

The lock also supplies a consistency contract, not just access permission.
`MachineUpdateRetainedSetupPolicyNativeEntry.swift:84–93` captures one full boundary and requires each later read to equal it.
That boundary includes the policy snapshot and checkpoint. A one-time remote copy of the policy is not equivalent.
An authority processing normal journal events may change the checkpoint even when its code policy is unchanged.

The retained target is a separate account, not the current authority.
`publishedAuthority` rejects the target account at `MachineUpdateRetainedSetupPolicyNativeEntry.swift:69`.
The retained snapshot requires unpublished, unactivated target state with no registered jobs (`MachineUpdateRetainedSetupPolicySnapshot.swift:11`).
That target has no legitimate running authority in this state. The structural conflict identified here concerns the current approving authority.

## 2. Other journal users and the actual stop path

| User | Coordination found | What it does not establish |
| --- | --- | --- |
| `AuthorityAccountInitialization` | Incomplete setup opens and closes both stores within the operation (`:28–43`, `:76–125`). A completed initialization returns after validation without reopening the journal. | It never drains or stops a running service. An unexpected competing owner still causes busy. |
| Account initialization ordering | `RuntimePublicationController.swift:67–69` requires initialization complete before runtime publication. `RuntimeActivationPlan.swift:55` requires published configuration before a job plan exists. | A retained completion flag alone is not current service health or permission to reinitialize a live store. |
| `MachineUpdatePolicyRead` | `:18–30` reacquires an exclusive protected lease even with `readOnlyForCutover`. `MachineUpdatePolicyPreflight.captureNative` requires a quiescence token and reads account policies through it. | The reader itself cannot stop the service, borrow its journal or make its lock available. |
| `GatewayJournalCutoverLease` | Audit drain supplies exclusive role/root activity and verifies file identity; the gateway writer lock remains exclusive. | It is not a general idle-time gateway or authority read while services retain their locks. |
| `AuthorityJournalCutoverInspection` | Audit drain opens it only after registration removal, exit witnesses and exclusive role activity; it retains both existing read-only stores. | The inspection grants no dispatch, policy write or service-restart permission. |

The concrete stop implementation is the **audit-upgrade drain**, not `UpdateQuiescenceLease`:

1. `RuntimeAuditUpgradeNativeDrain.swift:69–73` creates exact job stop sessions for the selected graph.
2. `RuntimeJobStopSession.swift:17–32` checks the known job and constructs `/bin/launchctl bootout system/<exact label>`.
3. Its `poll`, at `:81–99`, removes registration and waits on captured process exit witnesses. Absence alone is not exit proof.
4. `RuntimeAuditUpgradeNativeDrain.swift:130–140` waits for removal/temporary-job settlement, takes exclusive role activity, then opens authority/gateway leases.
5. `JournalLeaseError.busy` returns pending rather than forcing lock takeover. The caller must retain the drain and actual cleanup owner.

This drain is bound to an audit graph, startup fence, installed identities and durable cutover state.
It cannot be reused by fabricating an audit graph for retained setup.
Its low-level stop, witness and identity mechanisms are the reusable parts; a new retained maintenance owner would be necessary.

`ServiceReleaseActivityBarrier` coordinates the dedicated role activity files. Its lock does not close the authority's journal.
`ReleaseActivityBarrier`/`UpdateAdmissionBarrier` coordinate activity and new work, independently of journal ownership.
`UpdateActivationAdmission.swift:38–48`, `:73–86`, `:125–147` create/validate exclusive machine activity and closed admission.
None of those methods calls service close, unregister or bootout. Quiescent request activity can coexist with an idle service retaining its journal.

### Normal update has the same latent composition problem

There is no native update bootout path feeding `MachineUpdatePolicyPreflight.captureNative` on this main.
The source/reference search across Core, app and experiment Swift code found no production caller of that native factory.
Do not report an already operational update maintenance window or a currently reachable update failure.

A future caller that only wraps it in `UpdateQuiescenceLease` still gets busy for each journal retained by a live service.
The factory also pins the executing **Authority** executable (`MachineUpdatePolicyPreflight.swift:32`); calling it from its already open service would contend with its own owned journal.
Therefore the retained and multi-account update paths need one coherent ownership decision. This belongs in #603, as Toni requested.

There is a second composition constraint for a maintenance window:
P04/A11 use `UpdateOrdinaryAdmissionLease` (`:50–52`: shared activity plus ordinary admission).
`MachineUpdateRetainedSetupRuntimeNativeContext.swift:239` opens that lease during native custody.
It cannot run unchanged under an already held exclusive quiescence token and closed admission.
A maintenance design needs an explicit typed loan of the existing drain; reopening ordinary admission or weakening the guard is not acceptable.

## 3. Three options with the same constraints

Estimates are preliminary changed-production-line ranges, not measured diffs. Tests and docs are additional.
Every implementation cut must remain complete and at most 200 lines; choose the model before writing those cuts.

### A. Read current policy through the authority service over XPC

- **Reuse:** the existing service's serialized journal owner, accepted XPC connection checks, native peer policies and scoped lifetime patterns. The existing trust snapshot RPC is not a current-code-policy custody API.
- **Custody change:** Setup must replace its local `HeldScope` with a connection-bound, account-bound remote capability. The service must preserve the same full policy/checkpoint boundary for the entire sequence, or the stronger A11 invariant must be explicitly redesigned. Before/after snapshots alone do not prevent a change after a partial mutation.
- **Approver outage:** freezing that full boundary blocks journal-changing approval work for the whole sequence even if the process stays alive. A policy-only revision capability might allow normal checkpoint changes, but that is a different, unproved contract. Do not claim zero outage from XPC alone.
- **Estimated work:** roughly 500–1000 lines across 5–7 cuts: native endpoint/peer binding, remote lifetime and loss handling, boundary conservation, Setup approval adapter, cancellation/recovery and integration. No such API exists today.
- **Live proof:** actual installed peers and administrator rights; current policy/checkpoint activity during every stage; disconnect/restart/expiry; partial mutations on invalidation; actual approver availability and complete capability cleanup.

### B. Run in an explicit stopped-service maintenance window

- **Reuse:** audit drain's exact registration removal, process witnesses, exclusive role/root activity, existing read-only pair inspection and restart/readiness owners. Normal update supplies admission/quiescence primitives, not an existing bootout composition.
- **Custody change:** the stopped current authority's pair can remain locally pinned as A11 expects. Add a retained-specific maintenance scope and an explicit closed-admission loan replacing the ordinary-admission assumption. Preserve durable drain state, idle-only automatic admission and the signed explicit-drain contract. Restart health and required floors must precede reopening.
- **Approver outage:** from actual stop through acquisition, the full retained sequence, lease release, re-registration and confirmed readiness. A nil/pending drain is not a bounded outage promise. The private #737 case took 38.489 seconds, including 30.349 seconds of fixture setup and 6.970 seconds in the C2 owner phase; none is an installed downtime measurement. Plan for material work plus shutdown/restart overhead, not a millisecond gap.
- **Estimated work:** roughly 450–850 lines across 4–6 cuts: retained drain/fence owner, typed admission/custody loan, stop/lease sequencing, durable failure recovery and restart/readiness integration. Reusing the audit class directly is not safe.
- **Live proof:** actual idle/drain eligibility, known process exit, lock acquisition after stop, all error/uncertain outcomes, signed artifact continuity, no restart race, readiness/floor ordering and measured approving-service unavailability.

### C. Run the sequence in the authority process that already owns the journal

- **Reuse:** the existing serialized journal and request owner, retained sequence owners and actual paired boundary. Use a borrowed owner capability rather than reopening its private lease.
- **Custody change:** incompatible with the native entries as written. P04's native context requires the `.setupController` code requirement and exact Setup path (`MachineUpdateRetainedSetupPolicyNativeContext.swift:95–100`). A11 requires the same (`MachineUpdateRetainedSetupRuntimeNativeAuthority.swift:44–52`). The Authority executable cannot pass either. This needs an explicit new code/operation custody model, not removing those checks or accepting either executable opportunistically.
- **Approver outage:** serializing/fixing the whole boundary inside its owner can block normal approval transactions for the entire sequence. Keeping the service process alive is not evidence that approval work continues. Existing no-reentry guards also prevent treating a long request callback as a general nested journal loan.
- **Estimated work:** roughly 700–1300 lines across 6–9 cuts: approved Authority-native custody, borrowed journal access, target/native provider adaptation, bounded work ownership, admission/cancellation and recovery. Delegating the protected work back to Setup instead returns to option A.
- **Live proof:** independently approved role/code boundaries, no reentrant journal operation, actual concurrent request behavior, lease ownership throughout shutdown/retirement, native material/file permissions and complete sequence recovery.

## Consequence for the two pending plans

Do not spend E01/E02 implementation effort to discover whether this unchanged lock composition normally works; source already answers it.
Keep a bounded live contention observation as later confirmation of the chosen ownership/maintenance design, actual identities and cleanup.
Issue 725 still needs a real installed commit and timing. Source analysis cannot mark those attended results passed.

The experiment plan's busy-first sequence must become an ownership-decision prerequisite followed by targeted installed validation.
P05's reset remains a separate explicit owner action. It must not compensate for an unchanged structural conflict or enable repeated failed resumes.
P05 still requires the fresh exact source pair, an atomic new prepared marker/revision and zero journal writes.
Toni selects the ownership option before the experiment and P05 plans are revised. Both remain unchanged in this analysis commit.
No option is implicitly approved by this document. The full Remozio objective remains incomplete.
