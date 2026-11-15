# Explicit service maintenance window

## Decision and scope

Toni selected option B in 2740, then narrowed retained work to a per-account window in 2763/2767.
The global closed-quiescence proposal is superseded for retained work. Normal update keeps its machine-wide drain.
Messages 2742, 2746, 2751 and 2754 require recovery without replay, a minimum cohort and a visible attended exit.
Saturn's 2747 and 2752 clarify recovery when launchd already restarted the current authority.
This revision follows the source checks requested in 2760/2763 and the drain order decided in 2767.
C01 proceeds independently without dispatch. This plan precedes the revised [725 experiment](725-experiment-plan.md), [P05](p05-plan.md) and authenticated caller work.
Toni owns implementation order, native slots, publication and merges. This document adds no code or live procedure.
Toni2996/2998/3002 supersede the live-idle design with bounded user-work observation, ordered shutdown and a durable close marker.

Fetched main is `b899e1ad34836b37745f9099db8d2594ea384150`, tree `3117e2d9c6460a2c52bea8a55c25dd80f8328f3a`.
Its merge of #753 includes all A11 cuts. The planning branch remains based on preceding main `987ea4ee`.
The A11k changes were checked for their admission interfaces. The lifecycle mechanisms below are unchanged between those mains.
The [source analysis](725-busy-analysis.md) explains the structural conflict: a healthy authority keeps its exclusive journal lease.
An idle request queue does not release that journal. Retained work keeps ordinary shared machine admission and avoids exclusive machine quiescence.

For retained setup, current authority A approves work for distinct retained target B.
Preserve A11's locally pinned, read-only current policy/checkpoint pair through the complete native body.
The window owns A's account drain, stop, custody, cleanup and restoration. P04, A11 and P05 keep their own mutation contracts.
Normal update uses the same lifecycle owner with its actual replacement cohort and update-specific state.
Do not fabricate an audit graph, update activation, scheduling candidate or success receipt to reuse another owner.

## Existing mechanisms and missing composition

Source paths below are under `macos/core/Sources/RemozioCore` unless stated otherwise.

| Source evidence | Reuse | Required addition |
| --- | --- | --- |
| `RuntimeJobStopSession.swift:17–32,70–99` | Exact label, native identity checks, process witnesses and bounded `bootout` | Separate maintenance stop facade: the current native factory requires machine activity EX, unavailable under ordinary SH |
| `RuntimeJobRegistration.swift:90–115` | Inspect exact registration; bootstrap only the expected plist; reconcile ambiguous command results | Restoration state and actual health checks; matching registration is not readiness |
| `InstalledAccountJobManifest.swift:6,33–54,64` | Per-account `/Library/LaunchDaemons` paths, derived labels and `RunAtLoad`/`KeepAlive` | Validate the exact retained cohort before stopping anything |
| `UpdateOrdinaryAdmissionLease`; `UpdateAdmissionBoundary.swift:22–39` | Shared machine activity/admission and an existing optional account drain | Hold A's actual account drain independently; keep P04/A11 ordinary admission unchanged |
| `AuthorityUpdateAdmissionStartup.swift:20–26`; `MachineUpdateAdmissionRecovery.swift:61–100` | Account gate identity and fresh recovery checks | Restore only A's durable maintenance closure before its request listeners; never fabricate an update intent |
| `AdministrativeSetupService.swift:106–108,130–162`; `macos/app/Setup/SetupMain.swift:47–54` | Verified Root Setup host, temporary startup activity and existing service loop | Recovery before conflicting Setup request dispatch and after interrupted windows |
| `RuntimeAuditUpgradeRestart`, `MachineUpdateRestartHealthCoordinator`, `MachineUpdateInstalledActivationFinalizer` | Exact restoration, live readiness, joined cleanup and release ordering | Purpose-specific maintenance outcomes; no invented update completion |

No generic maintenance worker, durable maintenance record or restoration-only app action exists on this main.
P04/A11 already require `UpdateOrdinaryAdmissionLease`; retain those interfaces. The authenticated observation channel, close marker, native permit and recovery composition remain required.

## Per-account scope and actual drain order

| Role | Retained policy/A11/P05 window | Effect |
| --- | --- | --- |
| Current AuthorityA | Drain A's new requests, await its live work, then stop its exact derived job | A waits during drain and is unreachable from stop through verified restoration |
| Current transportA and gatewayA | Keep registered; do not take their lifetime role locks exclusively | Their unchanged files/binaries need no stop; A may remain unreachable through these transports |
| Other accounts | Leave their account admission, services and journals open | They continue approvals; do not take machine admission or activity EX |
| Retained target B | No job stop or registration | Selected retained state stays unpublished/unactivated with no registered target jobs |
| Root Setup | Never stop | Executes the operation and autonomous recovery |
| Normal update roles | Derive from the actual signed replacement plan and inventory | Machine-wide drain and all affected roles remain separate from this retained exception |

`ServiceReleaseActivityBarrier` is per account directory, but `ServiceAccountRole` has only transport and gateway.
There is no authority activity file to take exclusively. Do not invent one or misuse a transport lock.
Keep a real shared `UpdateOrdinaryAdmissionLease` from window acquisition through settled restoration. It excludes machine update activation.
Open A's already registered account barrier by its protected identity and `.account(A)` scope; absent registration is NO-GO.
Do not use a fake update scheduling action to close it. Other account barriers and machine admission stay open.

Use this exact order, as Toni revised in2996/2998/3002:

1. Persist the window intent and A-drain phase, then hold A's real account drain under ordinary shared machine admission.
2. Through the authenticated Setup-to-A channel, observe actual pending decisions, requests, exchange/worker reservations, native cleanup and staged pairing.
3. Wait within the configured pre-stop bound without cutting that user work. On timeout, cancel and explicitly reopen A without stopping it.
4. Under the authenticated binding, block new pairing stages and preserve existing attempts. Revalidate zero staged pairing after the block, then the exact incarnation and shutdown binding. Boot out only A's derived Authority job.
5. Use the existing ordered runtime shutdown. A writes its exact durable marker only after runner.close succeeds under that binding.
6. Setup requires the original incarnation's exit witness and exact marker readback, then acquires A's real exclusive journal/continuity pair.
7. Only after every check passes may the purpose-bound body loan begin. Missing or mismatching evidence leaves needsOwnerRecovery and no body execution.

No phase widens the cohort after busy. An artifact with another necessary dependency refuses before stop and needs a reviewed cohort.
Cancellation is reversible without a stop before bootout. After bootout, cancellation means restoration through M09, never body replay.

### User work observation and ordered shutdown

The account gate closes request creation only. Existing decisions, genuine expiry and execution keep their ordinary lifetimes.
A queued authorization callback, a rejected-start report and terminal native cleanup are work even when a request queue appears empty.
A staged pairing attempt also remains user work. Never clear or force-expire it to obtain permission to stop A.
M05a observes these real owners; it grants no idle proof or stop permit.

The existing shutdown joins receiver, producer callbacks, worker turns, publisher and settings/recovery tasks before request/storage closure.
It does not replace the pre-stop wait: ApprovalRequestCoordinator.close retires pending requests with unknown outcomes.
AuthorityJournal.close does not wait for released command executions. Their actual cleanup must already have settled before removal.
Other hosted app/transport/background owners use the existing ordered close path instead of a new full-runtime live-idle fence matrix.
The detailed historical audit remains in the history of review/m05-recon.md; the current document defines the hybrid contract.

M05b provides the authenticated native Setup-to-A channel, also used by M09 reopen/readback.
Setup supplies the account, attempt and revision. A validates the protected scope and stores a connection/incarnation-bound context in memory.
A restart or disconnect before bootout retires that binding. No marker for that attempt may then be written.
The armed shutdown transition must preserve the exact binding through its expected listener teardown.
An unrelated retirement, startup failure, deinit or unbound close cannot create the marker.
A reads the window record at protected startup and authenticated commands only. It never rereads that record inside close.

M05c writes the bounded canonical marker to fixed protected storage only after successful runner.close under the exact binding.
The marker binds account, attempt/revision, installation, incarnation and current code/release scope; Setup compares its exact retained expectation.
Require crash-safe durable publication and strict protected readback. Missing, stale, foreign or uncertain evidence cannot authorize the body.
The marker proves completed close followed by exit of the same incarnation. It does not reveal the numeric exit status.
A SIGKILL after durable marker publication occurs after close has already finished; do not claim the Boolean witness distinguishes it.

Neither A's generated plist nor its bundled plist sets ExitTimeOut. The local launchd.plist manual defines the default as system-defined.
This plan does not promise20 seconds or change the installed timeout. A timeout before successful marker publication fails closed.
An explicit timeout would require a separate scoped plist change and qualification.
M05d introduces the native permit and stop factory together, using the actual bounded observation, bootout, marker and witness contracts.
Audit keeps its exclusive-machine guard. Retained work keeps ordinary shared machine admission and A's exact account drain.

### Concurrent bootstrap and KeepAlive

Current bootstrap callers include `RuntimeActivationFiles`, `GatewayRuntimeActivationOperation` and `RuntimeAuditUpgradeRestart` through `RuntimeJobRegistration.ensure`.
None currently recognizes this proposed maintenance record. A Setup reservation alone does not cover another Root process or recovery path.
Add one shared protected attempt/phase check to native registration and relevant recovery admission before any selected A bootstrap.
While the body is active, conflicting bootstrap refuses as maintenance-pending. During restoration, only the exact restoration owner may ensure A.
Keep the check purpose-bound and preserve all existing job/code/placement guards. A request flag cannot bypass it.

The held journal lease would make a premature A open fail busy; that is exclusion, not an acceptable restoration protocol.
`AuthorityStartupFailure:12` classifies busy as temporary; `AuthorityRuntimeRunner:160–170` retries temporary startup with bounded backoff.
Prevent repeated bootstrap attempts rather than accepting KeepAlive/retry churn, silent failures or lost readiness as normal maintenance behavior.
Reboot is different: old owners have died, A may already be running, and recovery adopts that exact instance after health/floor checks.

### Phone and requester behavior

`ApprovalRequestCoordinator:356,393` maps account-admission busy to the command-admission waiting/retry result.
Do not assume that result is itself a phone UI message. It is not a signed decision or denial.
Before stop, existing phone decisions and commands retain their normal lifecycle until their actual owners settle. Staged pairing also remains in the bounded wait.
While A is stopped, Android `CommandConnection:108–115` reports unavailable/disconnected; `CommandInboxScreen:50–56` displays disconnected with reconnect.
`CommandRequestSession:66–76` changes terminal status only through validated status observations, not from a transport exception.
These source paths do not prove the full outage UX. Test waiting, disconnect, stale cards and reconnection on the selected phone artifact.
No outage or timeout may manufacture decline, execution failure, delivery success or an automatic replay. Genuine authorization expiry keeps its meaning.
After reconnect, fetch current authenticated state and reconcile ambiguous replies; never resend a decision or command to create a green result.
Question 2 for Seb is how long A may remain unreachable, including the full body, cleanup and verified restoration.

## Durable intent and phases

Create a distinct, canonical maintenance record through protected machine storage and exact compare-and-swap writers.
Its format readers and release requirements must ship before a producer can make the window reachable.
The store stays at schema 28 until the first retained window commits its row and migration together; only these machines raise the rollback floor.
Bind these fields to actual protected state:

- Machine/installation, unique attempt and revision, purpose, selected release and exact restoration declarations.
- Current account A, distinct target B when applicable, directory identity and the protected operation/candidate digests.
- Existing authority, target consent and administrator authorization references; never persist an external authorization form.
- Durable phase, operation outcome, restoration outcome, last bounded failure and the expected mutation footprint.
- Current A's protected policy/floor bindings needed for independent restoration; do not confuse them with B's historical policy.

Allow one active retained window on A and one Setup operation reservation; do not close machine admission.
The body and restoration retain shared machine activity, so an update cannot acquire its exclusive replacement ownership. PID alone is not a durable owner identity.
The record grants no native capability. Fresh code, placement, protected-state and real ownership checks remain mandatory.
Existing update activation keeps its own identity, irreversible phases and scheduling authorization; link rather than counterfeit it.

| Phase | Required boundary |
| --- | --- |
| Authorized | Persist intent and mutation restrictions before any stop |
| Draining A | Persist A closure; hold its real account drain; observe user-work settlement through the authenticated channel within the pre-stop bound |
| Stopping | Boot out only the fixed Authority cohort; retain the authenticated shutdown binding and await the clean-close marker and original exit witness |
| Stopped and excluded | Require exact close-marker and same-incarnation exit evidence, then acquire the actual pair leases; busy never grants lock takeover |
| Executing | Issue one scoped body loan for this attempt; no automatic body retry |
| Work settled | Close every borrowed writer/store, join children and persist the known or uncertain operation outcome |
| Restoring A | Keep A admission closed and machine admission shared; restore/adopt A and run readiness checks |
| Reopen pending | Persist readiness/floors and explicit release intent; confirm the actual A gate state through the authenticated command |
| Restored | Persist the confirmed open A gate state and terminal recovery outcome; release shared activity after cleanup joins |
| Needs owner recovery | Keep a visible bounded failure; allow authenticated status and the reviewed attended exit |

These are proposed semantic phases, not an implemented enum or a promised schema number.
Persist transitions before their external side effects. Reconcile an interrupted transition from actual state, not a guessed command result.
If a store commit is uncertain, retire the handle and reopen through the existing uncertainty rules.
An error, cancellation, lost reply or Setup process exit never proves rollback or completion.

## Existing ordinary admission and native body

Retained work does not use `UpdateAdmissionDrain` or `UpdateQuiescenceLease` for the machine.
P04/A11 retain their existing `UpdateOrdinaryAdmissionLease` APIs and native code/path checks.
Do not add a general sealed ordinary/maintenance proof, alter every frame/store signature or reopen a global gate temporarily.
The outer maintenance owner holds shared machine admission/activity and A's independent account-drain token through actual cleanup and restoration.
Existing nested ordinary leases remain shared. No compatibility Boolean, copied token or replacement drain is needed.
The stop facade receives actual purpose-bound maintenance ownership and the M05d permit. It verifies bounded work observation and exact shutdown evidence.
No forged audit graph, copied observation or machine-EX token can substitute.
Existing audit/update native factories keep their machine-exclusive requirement intact.

Keep process, thread, re-entry, expiry and poison guards in every native loan. A cancelled owner cannot release resources before work settles.
Callbacks receive actual transaction frames and perform no public machine query or nested transaction.
Close capture handles before native entry. Production `Machines.scoped` has no retained machine pool to suspend.
A's local policy/checkpoint pair stays pinned for the whole native body, then closes before restoration.
Persist the executing window phase before capturing the body's fresh B entry/import frames. Keep window-row writes outside borrowed body transactions.
C01's earlier full source comparison must not silently ignore the new window record.
Under the actual C02 invocation owner, require the exact authorized record-only transition and recapture the same A/B bindings and choices.
Every unrelated row remains exact. Re-resolution cannot select another target or invoke the XPC guard from an unrelated worker.
After the body closes, its result and later window transitions retain their separate validated boundaries.
Normal update's closed machine quiescence remains unchanged and is not a retained permission.

## Recovery executor and triggers

Use the existing Root Setup daemon, not a new job or a GUI-dependent worker.
Its bundled plist, `macos/app/Setup/dev.sebastiano.remozio.macos.setup.plist:7–25`, declares `KeepAlive`, `RunAtLoad` and Root.
`MacSetupServiceControls.swift:149–157` and `AdministrativeSetupService.swift:130–135` validate that manifest.
Apple's [launchd startup guidance](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) describes loading daemon plists and maintaining KeepAlive jobs.
That OS contract is not proof of this artifact's installed crash/reboot recovery. Those live gates remain unexecuted.

Run the new worker on Setup startup, after each interrupted window, and on an explicit restoration-only action.
Startup recovery begins after verified `AdministrativeSetupService.open` releases its temporary shared activity, before conflicting Setup dispatch starts.
Reserve the Setup owner and retain shared machine activity; retained work never asks for machine activity EX.
Keep authenticated Setup status/recovery available while its reservation reconciles the interrupted window.
Authority startup must restore A's durable account drain before request creation; other account admission remains open.
A launchd restart must not erase A's closure merely because process-held drain descriptors disappeared.
The shared machine lease also disappears on process death. Every update activation/preflight owner must freshly refuse an unresolved maintenance record before replacement.
This prevents an update from racing recovery without closing ordinary machine admission or blocking unrelated approvals.
A decoded record still grants no live token; recovery reacquires real shared ownership and validates the exact attempt.
No app connection, still-live administrator form or logged-in desktop is required for automatic restoration under the original durable intent.
That intent permits recovery only. A new mutation always needs fresh authorization and a new operation scope.

Before stopping, verify that this exact Setup daemon is installed, registered, enabled and capable of autonomous recovery.
Missing or disabled recovery is NO-GO. KeepAlive declaration alone is insufficient.
After Setup crashes or is killed, launchd is expected to restart it. The new instance closes the previous window; it never resumes its body.
Acquire actual recovery ownership and prove the previous operation has settled before inspecting or restoring affected resources.
A competing live owner remains busy. A stale PID or missing launchd registration is not sufficient exit proof.

### M10: retain an orphan reservation until explicit recovery

C02 review 2809 requires an explicit close to release its reservation. A lost invocation closes rights but leaves both Setup admissions closed.
The Setup owner retains the admission and shared activity tokens independently of the invocation. Their deinitializers cannot reopen admission when that invocation disappears.
Source inspection: `SetupAccountOwner.reserveRetainedInvocation` and `SetupRetainedInvocation.deinit`, C02 source `04ac6511`, base `683a67b5`.
This source supplies retention only. Orphan detection, status and recovery below remain future M10/M11/M12 work.

Associate each retained reservation with its exact incarnation and a weak reference to the invocation owner.
A nil weak reference proves that object ended. A missing process ID, old timestamp or cancelled flag cannot substitute for this proof.
M10 also joins the actual worker, native loans and cleanup owners before declaring the old operation settled.
If any owner remains live or settlement is uncertain, keep the reservation and report recovery pending.
The worker never releases an orphan automatically or repeats its body. It exposes the orphan to M11 and the explicit M12 action.

`SetupAccountOwner.closeWhenIdle` waits while either Setup admission remains held. An orphan therefore prevents orderly shutdown from finishing.
launchd can terminate Setup after its existing `ExitTimeOut`. A durable window must already record any native body before this boundary.
After restart, M10 reconciles that recorded attempt and its actual outcome. It never repeats the body or treats termination as rollback.
Before a durable window exists, C02 has no native body or mutation loan. This pre-window orphan leaves no durable trace after process termination.
Reopening local admission after Setup restarts is acceptable only in that pre-window case. It proves no operation completion.
The future shutdown test must distinguish these two cases and preserve every unresolved durable window across restart.

### Reboot and an authority already running

`RuntimeJobStopSession` uses `launchctl bootout system/<label>`; it does not delete the plist, disable it or call `SMAppService.unregister`.
The plist remains in `/Library/LaunchDaemons`. Reboot can therefore start AuthorityA before Setup recovery runs.
For retained work, A's journal was read-only. No uncertain target-B write justifies a new fence blocking A's journal startup.
Do not add an A startup fence copied from audit cutover. Audit's graph-bound fence protects a different mutation footprint.
The durable restrictions belong to the machine/target operation and admission, not a false claim that A's journal was modified.

If the exact AuthorityA is already running, adopt its restoration after native identity, readiness and floor checks.
Do not stop it again merely because the old maintenance phase is still open.
The old pinned A pair and native context are invalid after that restart; they cannot resume or validate the old operation body.
Keep A admission closed through restoration checks, then release its drain without requiring uncertain B to become usable.
Release the shared machine lease only after all work and restoration settle; no machine-wide gate was closed.
This requires proof that A and shared admission state are safe independently of B. B's unresolved intent remains blocked.
If an old body could still be live, its A lease and process ownership must settle before restoration; never steal its lock.
Normal update does not inherit this exception: replacement/epoch/floor state determines which artifact may start each role.

## Classify the operation separately from restoration

Read the actual protected markers, rows, policy/checkpoint pairs and publication receipts after reopening.
Use purpose-specific existing reconciliation; a remembered return value alone is insufficient.
For P05, distinguish exact old writing, exact new prepared, and foreign/unknown states without generating another revision.
For P04/A11, preserve their actual committed/partial/unknown states and required explicit continuation rules.

| Observed state | Recovery behavior and visible result |
| --- | --- |
| Operation committed; service restore failed | Report committed plus restoration failed; retry only restoration, never the operation |
| Operation failed before mutation | Report the actual failure; restore the existing cohort; no body retry |
| Operation outcome unknown; A independently safe | Restore/adopt A and reopen safe A admission; keep B blocked and show outcome unknown |
| Authority already healthy after reboot | Validate identity/readiness/floors, adopt it and close the window; no second stop |
| A/artifact/shared state cannot be proved safe | Persist `needsOwnerRecovery` or `repairRequired`; retain the relevant restriction and expose the cause |
| Restore command timed out or reply was lost | Freshly inspect the exact job/process and health; never infer absence, success or permission to replace |

Automatic recovery never reruns P04, A11, P05 or update mutation bodies.
Readback/reconciliation and bounded restoration are allowed; replaying a transaction is not restoration.
No recovery path clears `writing`, manufactures a startup receipt or advances B's activation/completion floors to restore A.

## Visible failure and attended exit

Recovery failure must not leave an approver down silently or make Setup crash repeatedly without a durable diagnosis.
Persist attempt/revision, last safe phase, separate operation/restoration outcomes and a sanitized actionable failure category.
Expose authenticated read-only Setup status before conflicting Setup dispatch. The app shows approver availability and the blocked operation separately.
Emit bounded diagnostic logs without authorization data, policy payloads, private paths or credentials.
Apply bounded retry/backoff to restoration only. Permanent mismatches stop retries and remain visible.

### M11: show and resolve an orphan reservation

Authenticated read-only status reports **orphan reservation** when the retained incarnation has no live invocation owner.
Status remains available without acquiring the blocked mutation or reply reservation. It reveals no authorization data or private paths.
Show the separate operation, restoration and cleanup outcomes. An orphan does not mean the body failed or rolled back.

Use M12's explicit restoration-only action to release the orphan in the same Setup process. No Setup restart is required.
The source already retains the tokens in the Setup owner. An exact release therefore needs no new service-control authority.
M12 uses a dedicated recovery entry bound to the stored reservation, not a second operation admission.
Require fresh administrator rights, the current peer binding and the exact reservation incarnation plus durable attempt/revision when present.
Under the Setup owner lock, recheck the nil weak owner and the actual joined worker, loan and cleanup owners.
Complete applicable restoration, health, floors and gate readback before releasing the matching reservation and shared activity tokens.
A request without a durable window must prove that no body or cleanup resource remains before releasing those tokens.
A live owner, changed incarnation, new attempt or uncertain cleanup refuses. Never release another reservation or replay a committed operation.
This is a proposed recovery path, not an existing endpoint, automatic unlock or qualified installed action.

The M11/M12 test must prove: lose the invocation owner, observe authenticated orphan status, perform the explicit action, then admit fresh work.
Also prove that foreign or live incarnations and unsettled cleanup remain closed. The action preserves the actual operation outcome.

Provide an explicit owner action: **Restore the service without repeating the operation**.
Require the approved current peer/owner binding, fresh administrator rights, the exact attempt/revision and fixed installed-artifact checks.
This action takes recovery ownership, joins previous work, verifies current A and applicable floors, then restores/adopts only its exact job.
It records abandonment of the old body and its actual known/unknown result. Target B remains unavailable if unresolved.
It cannot accept an arbitrary label/path/artifact, clear a fence blindly, reset a marker, replay the body or bypass readiness.
If A's safety remains unprovable, report `repairRequired` with the exact blocked check.
A separately reviewed attended repair uses a compatible qualified artifact and fresh protected readback; no force flag is permitted.
The exact repair procedure must exist and qualify before any window becomes reachable. This plan invents no repair command.
Missing visible status, restoration-only action or safe repair route is NO-GO before the first service stop.

## Restart, readiness and floors

Join all operation tasks and close every A/B writer, pair loan and scoped store before restoring A.
Keep the same shared machine lease and A account-drain ownership through restart and health checks.
No retained `releaseActivityForRestart` transfer is needed: retained work held no machine-EX token.
Authorize the exact restoration owner to register A; reject conflicting bootstrap through the shared maintenance phase check.
`RuntimeJobRegistration.ensure` proves registration only. Require actual serving identity, readiness and unchanged applicable A floors.
Persist reopenPending and the actual health/floor facts before releasing Setup's matching drain token.
Persist Restored only after the explicit command and the gate readback below succeed; release shared activity after cleanup joins.
Do not invent floor writes or require B's completion merely to restore A.
Normal update still requires the actual selected artifact, durable manifest, floor/epoch commits and closed machine admission through restart health.
Only an explicitly designated update owner may defer shared updates. Idle-only automatic update activation stays unchanged.
An explicit signed machine update drain remains indefinite; the bounded retained pre-stop wait does not change that contract.
A stop/outage acceptance limit never grants forced cleanup, fake success or body replay.

## Addendum: explicit admission reopen (Toni 2778; M02/M09)

M02 restores A's maintenance admission hold before request creation at startup. The hold is bound to the protected account, attempt and revision.
It is a local admission restriction, not a second exclusive token competing with Setup's actual account-drain token.
The authenticated M05b command must also establish the exact local hold and in-memory shutdown binding before removal. Unknown command outcomes authorize no stop or body.
A reads the maintenance record at protected startup and on authenticated maintenance commands only. M05b observation/arming and M09 reopen use that same boundary.
It does not reread the record inside close to discover a marker binding.
Do not add per-request rereads, event-driven reconciliation or a polling fallback for this maintenance record. Existing update admission checks stay unchanged.

M09 uses one reopen mechanism on the same native channel as the M05b authenticated observation and shutdown binding:

1. Settle the body and cleanup; verify A's actual identity, recovery health and applicable durable floors.
2. Persist reopenPending with the exact attempt/revision and release intent. This phase does not mean ordinary admission is open.
3. Release only Setup's matching account-drain token; A's local maintenance hold still prevents new requests.
4. Send the explicit authenticated reopen command. A verifies the Setup peer and freshly reads the protected phase/account/attempt before releasing that hold.
5. Read A's actual admission gate state, including its local hold and ability to acquire the registered account gate. Record that observation, not just an ACK.
6. Only after confirmed open admission, persist Restored and finish the window. A must accept a fresh request without another restart.

The command is idempotent and bound to the exact active window. It cannot release another attempt's hold or an update scheduling drain.
On a lost signal/reply, Setup retries only this explicit reconciliation and gate readback. A does not reopen itself from another event.
A timeout without confirmed gate state leaves needsOwnerRecovery visible, with separate actual operation and service outcomes.
The owner's restoration-only action includes this command/readback. It never repeats P04, A11 or P05, even if the body already committed.
Pre-stop cancellation uses the same explicit reopen/readback path without stopping or restarting A.

M02/M09 tests must prove a fresh request is admitted after Restored without an A restart.
Also cover lost/duplicate/stale commands, lost ACK with an already-open gate, confirmation timeout, pre-stop cancellation and a foreign drain that stays closed.
Health plus an ACK alone cannot pass. Gate state must be read back and durably recorded before Restored.
These native control operations and live results remain unimplemented/unqualified by this document.

## Normal update policy preflight

The common low-level lifecycle pieces also supply stopped-journal access for `MachineUpdatePolicyPreflight.captureNative`.
That factory currently requires the Authority executable (`MachineUpdatePolicyPreflight.swift:30–34`) and has no production caller on inspected main.
Calling it unchanged from Setup would fail its native identity guard. Keep that guard intact.
Add a separate narrow Setup-native maintenance facade over the existing policy capture/comparison algorithm.
It must verify the fixed `.setupController` code/path, actual activation/scheduling/candidate, selected signed artifact and stopped replacement cohort.
The retained administrator action alone cannot authorize a machine update.
Both facades revalidate exact machine/source/candidate inputs; no permissive `Authority OR Setup` branch or injected native verifier is acceptable.
Recovery must understand both old/new artifact readers across irreversible replacement. Never restore old binaries merely because preflight used them.
The common lifecycle owner does not merge the purposes' mutation permissions, completion receipts or rollback rules.

## Focused implementation cuts

Each estimate counts every changed production line, including helpers and deletions. Tests and prose are additional.
The hard cap is 200 per PR. Measure before tests; replan a complete responsibility that does not fit.
The earlier 450–850-line option sketch omitted the now-explicit recovery/status/native-adapter work. It is superseded, not a delivery estimate.
The ranges below are source-planning estimates, not measured diffs. Toni confirms sequencing and any required further division before implementation.

| Cut | Complete responsibility | Estimated lines | Required proof |
| --- | --- | ---: | --- |
| M01 | Canonical purpose-bound record with separate operation/restoration outcomes | 80–160 | Exact decode; no capability from bytes |
| M02 | Protected reader/format requirements and A-only startup admission hold | 100–190 | Hold survives restart and releases only by the authenticated M09 command; other account admission stays open |
| M03b1 | Complete startup recovery boundary | 23 | Store open/read failures retain A's hold and expose owner recovery |
| M03b2 | Exact CAS phase/outcome writer and atomic first-window migration | 100–195 | One active attempt; unrelated rows exact; uncertainty retirement; no production caller |
| M03c | Schema 29 policy, material and publication writers | Separate capped cuts | Each writer has an actual schema 29 test; no blanket version widening |
| M04 | Derived A-only cohort and ordinary-owner stop session | 113 measured | Exact registered scope/identity, retained exit witnesses; no native factory or caller |
| M05a | Actual work observation through pairing reply/activity release; shared budget releases at work return | 152 measured | Sourcec86366af, published by Toni as #764/ab540f5e. Gate18129 passed Core/Debug,31 pairing and10 Debug checks fresh;42 focused methods and54 Python outcomes transferred. |
| M05b1 | Canonical binding and shared pairing stage admission owner | 115 measured | Source303fcc08. Gate26372 passed Core/Debug,10 admission and10 Debug checks fresh;73 focused methods and54 Python outcomes transferred. No endpoint integration. |
| M05b2t | Process-owned armed pairing block, independent of the connection | 49 measured | Source970f30df; gate46648 passed Core/Debug,20 admission and10 Debug checks fresh;73 focused methods/54 Python transferred. Exact cancel/reopen only; closed admission stays unavailable. |
| M05b2a | Canonical channel codec with applied/stagesPending/refused outcomes | 119 measured | Source7c293c7d; gate66084 passed Core/Debug,15 codec and10 Debug checks fresh;93 focused methods/54 Python transferred. Pending only for arm with work; refused has no work. Applied arm reports actual transfer. |
| M05b2b | Authenticated endpoint with committed-state outcomes, rollback and joined operations | 191 measured | Source905b3bfb, gate68601:22 endpoint +24 admission +15 codec +10 Debug checks fresh;73 focused methods/54 Python transferred. Refused arm leaves no block from that request; uncertain rollback returns nil. Cancel/reopen have no fallible checks after release. Root producer/listener remain later. |
| M05b2c | Fixed listener, signed participant scope and joined retired endpoints | 146 measured | Source94a9ee11. Core and Debug builds passed. Gates14466 and84763 admit50 fresh unique methods and110 transferred methods. All6 scope methods ran fresh under Toni3088. Anonymous XPC proves lifecycle with owned controls. The Root access producer and product registration remain for b4. |
| M05b3 | Native authenticated Setup client with serialized exchanges and bounded recovery | 169 measured | Source8e494e12. Core/Debug and110 fresh methods passed;73 unrelated methods and54 Python results transferred. Harmless hello precedes identifiers and changes no admission state. Only stagesPending permits another arm before the original deadline. Refused is terminal; nil, timeout or malformed reply requires recovery. No product entry. |
| M05b4a | Protected command frame and actual pairing stage reservations | 94 measured | Source645f4dfd above acknowledgement repairf54fed93. Gate5876 passed76 fresh native methods and143 explicit unchanged-method transfers, fresh Python manifest checks, Core/Debug. One read transaction binds installation, gate, phase, current revision and incarnation. Retained Stage handles keep one attempt counted through actual reply cleanup. No Root factory. |
| M05b4b | Root factory and actual M05a owner composition | 121 measured | Source8ce7c89c above645f4dfd. The factory accepts the installed registration and actual WakeService only. Command reads use a short protected lease. Pairing endpoints remain retained through reply cleanup. Core and124 fresh supporting fixture methods passed. Installed Root execution remains unqualified. No registration. |
| M05b5 | Existing presence listener multiplexing | 110 measured candidate | One listener/delegate, exact App/Setup branch policies, independent maintenance connection owner, installed eligibility and channel1 declarations. No plist/host/schema change. Unapplied and unqualified. |
| M05c | Durable clean-close marker written after successful bound runner.close, with exact Setup readback | 110–195 per complete cut | No marker after failed/unbound close; crash/durability and mismatch tests; no exit-status claim |
| M05d | Purpose-bound native permit and stop factory, introduced together | 120–195 after support | Bounded work wait, pre-stop cancellation, exact bootout, clean marker plus original exit witness; then actual pair custody |
| M06 | Shared bootstrap/recovery phase guard for the M05d stop lifecycle | 110–195 | Audit EX guard unchanged; no conflicting A bootstrap or KeepAlive churn |
| M07 | Ordinary admission, durable armed binding and fresh body capture | 80–160 planned | Preserve the same A/B bindings and pair. Persist the exact five-value maintenance binding with the attempt before arm; uncertain persistence means no arm. Prove all opaque digests and candidateDigest. Window writes stay outside borrowed transactions. |
| M08 | Purpose-specific observation after interruption | 90–180 | Old/new/partial/unknown stay distinct; zero replay |
| M09 | Exact restoration and explicit reopen for both incarnation branches | 110–195 planned | notStopped: hello then exact durable-target reopen without open or a new reservation, on the same incarnation. healthy: new connection/open on the new incarnation releases only the M02 startup hold, never inventing an armed block. GateReadback.authorityIncarnation must equal the actual AuthorityClock epoch used by pairing admission. Record actual gate readback before Restored. |
| M10 | Root Setup startup/interruption recovery worker | 110–195 | No GUI dependency; actual owner/worker/cleanup settlement; orphan retained for explicit recovery |
| M11 | Authenticated status and durable visible failure | 80–170 | Orphan status available while reserved; lost owner → explicit M12 action → fresh admission; live or uncertain owners stay closed |
| M12 | Explicit restoration-only native action | 100–190 | Fresh rights/binding/revision; no arbitrary job, reset, force or replay |
| M13 | App restoration UI and phone waiting/unavailable integration | 100–190 | Clear A outage, genuine expiry distinguished from denial, safe reconnect/readback |
| M14 | Separate Setup-native normal-update preflight facade | 110–195 | Actual update authority/candidate and closed machine drain; Authority guard preserved |
| M15 | Final retained authenticated composition/reachability gate | 90–180 | M01–M13 complete before stop. If maintenance registration occurs here, include Authority and Setup maintenance reader/writer1 declarations, per-account MachServices, manifest generator and real-manifest tests in this cut. Qualify bounded observation, clean-close marker, restart, status and attended exit. |

M14 belongs to normal update and does not block the retained M15 closure.

M10 must open A's actual store inside `RuntimeMaintenanceAdmissionProjection.startup {}`. Its integration test must prove that an unopenable store leaves A held and visibly awaiting recovery, without a startup crash.

The first native cut that calls the window writer must require a private token from a factory that checks the fixed Setup selfPath and code. No DEBUG seam usable by Root may create that token. This runtime boundary must qualify before M15. Metadata format tests do not prove the calling process identity.

M03c must complete before M15 permits retained work. Policy, material and publication execute inside the window.
Issue #760 owns the missing completion and readiness SQL producers and schema 29 promotion support. A schema 29 machine cannot reach promotion before retained completion exists. These producers do not block the window itself.
M03b2 migrates only inside the window writer's first transaction. That writer has no production caller before M03c, so these library cuts migrate no real machine.
M03b2 preserves the candidate, policy, grant, operation and footprint digests as opaque immutable references. M07's native owner must prove their meanings, including candidateDigest; an historical epoch digest is not an assumed equivalent.
Both Authority and Setup must read schemas 28/29 and window record 1. Only Setup declares window writes on schema 29, record 1 writes and migration 28→29. Authority writer declarations cannot substitute for Setup's declarations.
The old M05–M07 general closed-quiescence adaptation is removed; P04/A11 production interfaces remain unchanged.
Existing account gate and ordinary leases remain. Toni2996/2998/3002 replace the full live-idle model with bounded user-work observation and clean shutdown evidence.
Measure each complete change before tests. Split M05a–d/M06 further if needed; incomplete observation, marker, permit or guard never enables the body.
C01/C02/C04 can proceed without dispatch. C03/C05 wait for the actual M05–M07/M15 closure.
P05a–d may follow M03 as library work. Its native facade/reachability wait for the same maintenance closure.
Reuse the approved caller identity/rights owners. No second resolver or temporary privileged endpoint is acceptable.

## Writer declarations

Declare a writer in the real release manifest only in the cut that makes its producer reachable in production. That cut must test the real app manifest against the compiled producer contract.

The following writers remain deliberately undeclared today:

- `runtime.retained-setup-release` writer 1 and `runtime.gateway-settings-consumer-host` writer 3 belong to the retained reachability cut, no later than M15.
- `runtime.gateway-settings-consumer-host` writer 2 belongs to the cut that connects machine update to a production entry.

M03c uses owned fixture declarations. It does not enable these writers in the real manifest. Current v1 and v2 declaration checks remain unchanged; the generated Setup host writer set contains only v1.

M15 must carry the retained producer consumer audit and the real Debug bundle regression. Before its declaration change, that regression fails with `incompatibleStore`. The reachability cut must make it pass and verify the remaining identity, admission, generation, policy and service checks. A declaration alone grants no native custody.

When M15 opens, copy this rule into `docs/macos-release-manifest.md`. Keep that documentation update in the reachability cut.

The accepted M03b2 storage 29 declarations remain unchanged. Their metadata audit does not qualify a native caller or runtime reachability.

## Tests and unexecuted live gates

Use disposable protected stores, actual typed owners and fault injection at each durable/side-effect boundary.
Tests must distinguish operation success from restoration success and assert zero operation replays.

| Case | Required observation |
| --- | --- |
| A drain with live work or idle-proof timeout | Other accounts continue; no stop/forced idle; cancel and reopen A on the bounded pre-stop timeout |
| Exact cohort and conflicting job | Only selected A stops; unrelated jobs remain; mismatch refuses without replacement |
| Lost bootout/bootstrap reply or PID reuse | Fresh exact observation plus original exit/exclusion proof; no guessed terminal |
| Failure before/after each commit | Actual old/new/unknown state retained; store retired as required; no body retry |
| Setup killed, logout, reboot | Startup worker runs before ordinary mutation; original operation never resumes |
| Reboot already restarted A | Adopt exact healthy A after readiness/floors; never stop it again for the stale phase |
| Unknown B but safe A | Restore approver independently; target intent stays blocked and visible |
| Repeated restoration failure | Bounded retries, durable visible status, attended restoration-only action or explicit repairRequired |
| Wrong PID/thread, escaped/reentrant native scope or close during callback | Refusal/poison; defer cleanup until real settlement; no stale frame use |
| Competing activation/audit/recovery bootstrap | Shared phase guard refuses A bootstrap during body; no journal-busy retry churn treated as success |
| A restart after Setup crash | Durable A gate restores before new requests; all other accounts keep admission |
| Phone waiting/disconnect/reconnect | No synthetic denial or automatic replay; genuine expiry remains distinct; current authenticated state restores UI |
| Normal update irreversible phase | Restore only authorized artifact/roles; actual floors and manifest precede machine reopen |

Installed native identity, real administrator approve/decline/expiry, actual service stop/exit, recovery and measured downtime remain unexecuted.
Select a qualified signed artifact and exact commands before scheduling any attended gate. No service action is authorized by source planning alone.
Crash/logout/reboot and repair tests need prepared attended slots; a 30-minute initial session does not qualify all of them.
Product question 2 sets how long A may remain unreachable and the acceptable end-to-end delay. Record overruns honestly; never force unsafe cleanup to meet a bound.
Provider semantics, physical hardware, installed activation and the remaining full Remozio work remain explicit separate obligations.

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
The changed pairing test file runs all38 methods fresh. All143 transferred methods use11 unchanged test files and unchanged production paths.
Only the one method-body guard changed aftercd5c447c. No transferred test invokes that pairing endpoint.
The final evidence admits219 unique methods, not219 fresh methods. The20 new b4a tests include earlier exact-source admissions.
The final gate runs76 native methods fresh and reuses143 exact unchanged methods from the source-bound partial run. Python and Core/Debug are fresh. The selected base checks include the actual schema29 context method.
Two helper-only test changes add a database path; their constructor/read smoke methods run fresh. No whole replacement or unrelated native-context suite is claimed.
Gate5876 admits219 unique native methods (76 fresh and143 transferred) and54 Python manifest tests fresh, with no transfers.
Installed Root admission, the b4b factory, M09, product registration and the full goal remain incomplete.

### Current b4b composition and registration order (Toni3150/3155)

This section supersedes earlier statements that the b4b factory is unimplemented or that registration may wait until M15.
Source8ce7c89c adds121 production lines and six tests above645f4dfd.
The Root factory accepts the installed registration and the actual AuthorityWakeService. It accepts no observation or callback factory.
Only native service composition retains the real journal, command execution worker, presence listener and AuthorityClock.
The ordinary fixture initializer cannot populate those private native owners.
Factory and command checks require the current live service. Close and deinitialization disable new native access without reading the machine store.
The installed registration captures the expected prepared account, then each command reads one protected stable frame through a short lease.
No machine store survives an await. The current record, account, installation, release, gate, phase, revision and incarnation remain mandatory.
Only the actual admission owner can retrieve the exact armed target for pre-stop reopen.
The healthy branch remains M09 work. It never adopts a decoded armed target.

Pairing aggregation retains actual endpoints through their operation, reply and activity cleanup, including a close inside the reply.
A closed, fully settled endpoint is pruned. A foreign admission cannot enter the aggregate.
The stage guard and attempt/activity/stage transfer now share one state.withLock.
The work samples remain separate observations. They grant no atomic idle proof, clean marker, stop permit or native stop authority.

M05b5a ships the host5 reader baseline first. M05b5b follows with explicit Setup selection and complete native registration.
Both precede M07 or any first native channel caller. B4b does not register or start that listener.

M09 GateReadback.authorityIncarnation must equal the epoch of the actual AuthorityClock used by this process's pairing admission.
A separate startup UUID is wrong, even when it has16 bytes. Every later command would otherwise refuse with changedScope.
The protected reader regression uses an actual AuthorityClock epoch and rejects another clock's epoch.
The admission regression checks that the existing access uses its actual clock epoch.
The same-incarnation notStopped and new-incarnation healthy branches still need their distinct native reopen operations.
Installed Root positive admission, product registration, Release qualification and the full goal remain incomplete.

### Retired host5 design (Toni3192; retired by3221)

This section supersedes the earlier single M05b5 registration cut. Toni selected option B: a persisted host5 marker.
The source matrix remains source analysis. It does not prove a durable publication transition or an installed listener.

M05b5a is the reader-only release. It decodes host5 and reconstructs both exact Authority plist variants.
The complete reader matrix includes ordinary plans, retained plans, compatibility projections, release configurations, completion archives and readiness hello.
Authority and Setup declare host readers1–5 and writers1–4. No public selector emits host5.
This release adds no channel1 announcement, listener startup or automatic migration. It must ship before the writer release.

M05b5b owns the first host5 write. Only Setup may select it, on the first explicit maintenance request.
The change requires durable intent, progress and exact readback before any restart. Add a supporting cut if this transition lacks qualification.
Host writer5, channel1, MachServices, native registration, generator checks and the actual generated-manifest test ship together.
Do not publish a partial announcement. Do not treat a fixture or a parsed marker as native startup authority.

After the first host5 write, the supported rollback baseline includes M05b5a reader5.
Every supported rollback target must read host5. Explicitly reject a target that lacks reader5 before changing installed state.
The exact release baseline and the transition remain gates for b5b. A local reader test does not establish either gate.

The pairing ready value is true when there are no endpoints. It is not an idle decision.
M07 uses stage, operation and activity counts together with the actual arm result. Persist the binding before arm.
Live session#725 measures store opens per second during the250ms arm wait, open latency and the effect of a busy journal.
Installed Root admission, Release qualification, M09 and the full objective remain incomplete.

### Current M05b5 decision: presence multiplexing (Toni3221/3223)

This section retires M05b5a, M05b5b and the dedicated host/plist publication proposal. Their commits and receipts remain history.
Do not publish the host5 branch. Keep the host codecs, installed plist and machine schema unchanged.
M05b5 uses the existing per-account N.presence name, one native listener and one delegate.
The prepared production candidate is based on bca7a7d6, before the retired host5 work.
Its complete delta measures110 lines across six production files, including additions and deletions.
Git independently counted the patch and checked it against the exact base. This is no compile or runtime result.
Candidate: /private/tmp/remozio-presence-mux-candidate-3221-r3-20261115/preparation.json.
That initial candidate was unapplied at preparation time. The implementation and local gate are recorded below.

The listener admits the union of the current App and Setup signing requirements.
UID0 routes to maintenance before any App reservation. All other UIDs route to the existing App path.
Each branch configures its exact signing requirement before connection activation. UID routing grants no authority.
Maintenance requires the current Setup team, identifier, cdhash and generation, UID0, authenticated hello and synchronous invocation checks.
The existing App endpoint already configures its exact App requirement before activation; preserve that behavior and test it.
Keep independent maintenance connection limits, work budget and retained endpoint cleanup. The owner cannot activate, invalidate or replace the shared listener.
The old standalone maintenance listener becomes a connection owner. The client and fixed-address scope resolve N.presence.
Remove the unused .maintenance Mach-name derivation in the same cut. Preserve the b3 wire payload and reply semantics.

Installed composition checks the current signed release and both authority.maintenance-channel version1 declarations.
Authority and Setup gain that declaration together, with generator, Python checks and actual generated-manifest inspection.
Configure the listener filter before startup. Attach the maintenance owner only after the actual service and pairing listener start.
Root connections during that interval receive unavailable and reserve no App capacity.
Close and deinitialization join retained maintenance work before closing its stores. Closing the shared listener must preserve an armed block.
No endpoint, callback or parsed payload can stand in for the actual b4b native owners or current protected frame.

#### Installed eligibility

AuthorityCommandRuntimeComposition.openInstalled passes the concrete presence configuration to openInstalledPresence.
That path creates account presence and its app endpoint, then the listener, and starts it in startRequests.
It does not depend on the readiness listener, optional phone push or the gateway settings listener.
The generic request-only AuthorityWakeService.open path has no presence listener and is not maintenance eligible.
Native maintenance also needs the actual execution worker and pairing admission. Pairing configuration remains optional in the startup codec.
If pairing, execution, active Setup metadata or signed channel declarations are absent, the account is not eligible.
Its existing App/command behavior remains intact. Do not create a weaker maintenance path or claim degraded maintenance support.
The candidate exposes this eligibility explicitly before configuring the union or starting the root connection owner.

An owner UID0 is already invalid in AuthorityAccountPresenceConfiguration and AuthorityPresenceEndpointConfiguration.
Retain both guards and add regressions through the actual composition inputs. No root owner can enter the App route.

#### Required focused evidence

Test App saturation without blocking maintenance, and maintenance saturation without consuming App capacity.
Test root non-Setup, stale Setup hash, App with UID0 and Setup with nonzero UID through both relevant policies.
Test exact requirement installation before activation on both branches and harmless authenticated hello before any work.
Test close, reentrancy, endpoint retirement and joining. Reprove an armed block after closing this actual shared listener.
Test installed composition eligibility and explicit refusal without a fallback for accounts lacking pairing or execution.
Run Core, the affected fresh focused methods, Debug, actual Debug manifest inspection and the Python manifest suite through ATC.
Source checks and injected peer tests do not prove native Root code admission. Preserve those attended boundaries.
M07 still uses counts and the actual arm result. Ready is vacuously true with no endpoints.
The separate M09 branches and live#725 measurements remain required. The full objective is incomplete.


### M05b5 implementation and local gate (Toni3227)

Source `4b151d09dbfbb6bbdb53b912b818505caccd025c`; tree `2b60135a8d69093dabdd73b8f320a96033f4d99f`; base `bca7a7d623f7b4e20f4072e5f99f9d6c98e042f8`.
The complete production delta is160 changed lines. The earlier110-line candidate remains immutable preparation history.
One presence listener admits App or Setup. Each branch selects its exact policy before activation.
Maintenance uses its own connection owner and budget. Root arrivals before attachment reserve no App capacity.
The client resolves N.presence. Authority and Setup declare channel1 together.
The host codecs, installed plist and machine schema remain unchanged. The retired host5 branch remains unpublished.

Core and Debug built. The gate passed193 fresh native methods with0 allowed GUI skips and zero transfers.
All11 new mux methods passed. Python passed54 fresh manifest tests.
The193 expected methods include actual Debug manifest inspection and all affected classes.
Gate73076 exited0/d042fc; the actual terminal was consumed.
The cumulative mux budget is635.557/1800 seconds, including three preserved failed runs.
The first run failed compilation. The second had an owned fixture identity error.
The third omitted an observe binding and expected a new connection to reuse the old binding.
The final recovery test preserves the old armed target and uses its exact binding to reopen.

The anonymous XPC tests use the real listener, endpoints, budgets and journal.
Their UID, role, current-hash and eligibility controls are synthetic. Native Root admission remains unqualified.
The native constructor cannot accept owned controls; the owned factory requires an ordinary account.
Release, installed Root, the full Core suite and merge readiness remain unqualified.
Toni owns publication, review, the watcher, merge and main reconciliation. Bepi did not push.
M07, M09, live#725, attended provider tests and the full objective remain incomplete.
