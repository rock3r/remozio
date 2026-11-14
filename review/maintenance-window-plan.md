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
4. Revalidate the exact live incarnation and arm its authenticated shutdown binding. Boot out only A's derived Authority job.
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
| M05a | Internal coordinator, exchange, worker, native-cleanup and staged-pairing observation | 71-line command draft plus pairing; under200 or an immediate pairing cut | No mutation of user lifetimes; gap/rejected-start/cleanup/staged-pairing tests; no endpoint or permit |
| M05b | Native authenticated Setup-to-A observation channel and in-memory shutdown binding, shared with M09 | 120–195 per complete cut | Fixed Setup peer and exact account/attempt/revision/gate/incarnation; disconnect/restart invalidation; no close-time record read |
| M05c | Durable clean-close marker written after successful bound runner.close, with exact Setup readback | 110–195 per complete cut | No marker after failed/unbound close; crash/durability and mismatch tests; no exit-status claim |
| M05d | Purpose-bound native permit and stop factory, introduced together | 120–195 after support | Bounded work wait, pre-stop cancellation, exact bootout, clean marker plus original exit witness; then actual pair custody |
| M06 | Shared bootstrap/recovery phase guard for the M05d stop lifecycle | 110–195 | Audit EX guard unchanged; no conflicting A bootstrap or KeepAlive churn |
| M07 | Existing ordinary-admission composition, record-only source transition and fresh body capture | 80–160 | Same A/B bindings and pair; prove every opaque digest and define candidateDigest; window writes outside borrowed transactions; native frame/provider contracts unchanged |
| M08 | Purpose-specific observation after interruption | 90–180 | Old/new/partial/unknown stay distinct; zero replay |
| M09 | Exact A restoration/adoption, health/floors and explicit admission reopen | 110–195 | Actual gate readback recorded before Restored; timeout needsOwnerRecovery; fresh request without restart |
| M10 | Root Setup startup/interruption recovery worker | 110–195 | No GUI dependency; actual owner/worker/cleanup settlement; orphan retained for explicit recovery |
| M11 | Authenticated status and durable visible failure | 80–170 | Orphan status available while reserved; lost owner → explicit M12 action → fresh admission; live or uncertain owners stay closed |
| M12 | Explicit restoration-only native action | 100–190 | Fresh rights/binding/revision; no arbitrary job, reset, force or replay |
| M13 | App restoration UI and phone waiting/unavailable integration | 100–190 | Clear A outage, genuine expiry distinguished from denial, safe reconnect/readback |
| M14 | Separate Setup-native normal-update preflight facade | 110–195 | Actual update authority/candidate and closed machine drain; Authority guard preserved |
| M15 | Final retained authenticated composition/reachability gate | 90–180 | M01–M13 complete before stop; bounded work observation, clean-close marker, restart, status and attended exit qualified |

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
