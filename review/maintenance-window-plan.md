# Explicit service maintenance window

## Decision and scope

Toni selected option B in message 2740: stop the required services for an explicit maintenance window.
Messages 2742, 2746, 2751 and 2754 require recovery without replay, a minimum cohort and a visible attended exit.
Saturn's 2747 and 2752 clarify recovery when launchd already restarted the current authority.
This plan precedes the revised [725 experiment](725-experiment-plan.md), [P05](p05-plan.md) and authenticated caller work.
Toni owns implementation order, native slots, publication and merges. This document adds no code or live procedure.

Fetched main is `b899e1ad34836b37745f9099db8d2594ea384150`, tree `3117e2d9c6460a2c52bea8a55c25dd80f8328f3a`.
Its merge of #753 includes all A11 cuts. The planning branch remains based on preceding main `987ea4ee`.
The A11k changes were checked for their admission interfaces. The lifecycle mechanisms below are unchanged between those mains.
The [source analysis](725-busy-analysis.md) explains the structural conflict: a healthy authority keeps its exclusive journal lease.
An idle request queue does not release that journal. An ordinary admission lease cannot run inside exclusive quiescence.

For retained setup, current authority A approves work for distinct retained target B.
Preserve A11's locally pinned, read-only current policy/checkpoint pair through the complete native body.
The window owns drain, stop, custody, cleanup and restoration. P04, A11 and P05 keep their own mutation contracts.
Normal update uses the same lifecycle owner with its actual replacement cohort and update-specific state.
Do not fabricate an audit graph, update activation, scheduling candidate or success receipt to reuse another owner.

## Existing mechanisms and missing composition

Source paths below are under `macos/core/Sources/RemozioCore` unless stated otherwise.

| Source evidence | Reuse | Required addition |
| --- | --- | --- |
| `RuntimeJobStopSession.swift:17–32,70–99` | Exact label, native identity checks, process witnesses and bounded `bootout` | Maintenance owner and fixed cohort independent of an audit graph |
| `RuntimeJobRegistration.swift:90–115` | Inspect exact registration; bootstrap only the expected plist; reconcile ambiguous command results | Restoration state and actual health checks; matching registration is not readiness |
| `InstalledAccountJobManifest.swift:6,33–54,64` | Per-account `/Library/LaunchDaemons` paths, derived labels and `RunAtLoad`/`KeepAlive` | Validate the exact retained cohort before stopping anything |
| `UpdateActivationAdmission.swift:38–86,125–194` | Closed admission, actual exclusive activity, scoped loans and transfer to restart admission | Purpose-bound maintenance custody accepted by P04/A11 without ordinary admission |
| `MachineUpdateAdmissionRecovery.swift:61–100` | Fresh durable-state checks and reconstruction of a blocked drain | Separate maintenance state; existing recovery recognizes actual update activation only |
| `AdministrativeSetupService.swift:106–108,130–162`; `macos/app/Setup/SetupMain.swift:47–54` | Verified Root Setup host, temporary startup activity and existing service loop | Recovery before ordinary request dispatch and after interrupted windows |
| `RuntimeAuditUpgradeRestart`, `MachineUpdateRestartHealthCoordinator`, `MachineUpdateInstalledActivationFinalizer` | Exact restoration, live readiness, joined cleanup and release ordering | Purpose-specific maintenance outcomes; no invented update completion |

No generic maintenance worker, durable maintenance record or restoration-only app action exists on this main.
The current native paths still require `UpdateOrdinaryAdmissionLease`; source qualification alone cannot make this composition work.

## Minimum exact stop cohort

| Role | Retained policy/A11/P05 window | Reason |
| --- | --- | --- |
| Current AuthorityA | Stop its exact derived job and prove exit | It holds the current journal needed by the pinned read-only pair |
| Current transportA and gatewayA | Keep registered; do not take their lifetime role locks exclusively | Their files/binaries do not change and they do not own AuthorityA's `writer.lock` |
| Retained target B | No job stop or registration | The selected retained state must be unpublished, unactivated and have `jobsRegistered == false` |
| Root Setup | Never stop | It executes the operation and autonomous recovery |
| Normal update roles | Derive from the actual signed replacement plan and inventory | Stop every affected role; do not import the whole audit cohort or touch unrelated accounts |

`GatewaySettingsConsumerNativeScope.swift:83–95` holds a separate `ServiceReleaseActivityBarrier` for the role lifetime.
Copying audit's exclusive role-lock acquisition would force unnecessary gateway/transport stops. Do not do that for unchanged roles.
Close new work admission and wait for existing command/child work to settle. Never kill work to force an idle result.
Validate all selected roles, dependencies and activity holders before the first stop.
An artifact that requires a larger retained cohort refuses. Review a new exact cohort before another attempt; never widen it after busy.
If retained work later mutates A's files, policy or floors, this cohort and recovery isolation no longer apply.

## Durable intent and phases

Create a distinct, canonical maintenance record through protected machine storage and exact compare-and-swap writers.
Its format readers and release requirements must ship before a producer can make the window reachable.
Bind these fields to actual protected state:

- Machine/installation, unique attempt and revision, purpose, selected release and exact restoration declarations.
- Current account A, distinct target B when applicable, directory identity and the protected operation/candidate digests.
- Existing authority, target consent and administrator authorization references; never persist an external authorization form.
- Durable phase, operation outcome, restoration outcome, last bounded failure and the expected mutation footprint.
- Current A's protected policy/floor bindings needed for independent restoration; do not confuse them with B's historical policy.

Only one active machine window can own the drain. PID alone is not a durable owner identity.
The record grants no native capability. Fresh code, placement, protected-state and real ownership checks remain mandatory.
Existing update activation keeps its own identity, irreversible phases and scheduling authorization; link rather than counterfeit it.

| Phase | Required boundary |
| --- | --- |
| Authorized | Persist intent and mutation restrictions before any stop |
| Draining | Persist closed admission; retain the real drain and wait for actual activity settlement |
| Stopping | Stop only the fixed cohort; retain command outcomes, witnesses and exclusion checks |
| Quiescent | Prove exit and acquire the real required leases; busy is pending/refusal, never lock takeover |
| Executing | Issue one scoped body loan for this attempt; no automatic body retry |
| Work settled | Close every borrowed writer/store, join children and persist the known or uncertain operation outcome |
| Restoring | Preserve the closed gate; restore or adopt exact jobs and run readiness checks |
| Restored | Persist applicable floor/readiness facts and terminal recovery state before reopening ordinary admission |
| Needs owner recovery | Keep a visible bounded failure; allow authenticated status and the reviewed attended exit |

These are proposed semantic phases, not an implemented enum or a promised schema number.
Persist transitions before their external side effects. Reconcile an interrupted transition from actual state, not a guessed command result.
If a store commit is uncertain, retire the handle and reopen through the existing uncertainty rules.
An error, cancellation, lost reply or Setup process exit never proves rollback or completion.

## Typed loan of closed quiescence

The window retains the real `UpdateAdmissionDrain` and `UpdateQuiescenceLease` through the body.
Adapt their underlying ownership with a narrow maintenance proof bound to purpose, machine, attempt, phase and actual owner lifetime.
P04/A11 receive a scoped loan of that proof. They must not call `UpdateOrdinaryAdmissionLease.open` inside the window.
Preserve ordinary callers through a sealed proof abstraction whose cases wrap actual ordinary or maintenance owners.
Audit every context, frame, store writer and native provider accepting the old ordinary type; changing one guard is insufficient.
No public constructor accepts `isMaintenance`, an injected verifier or a decoded record as proof.
Do not serialize live tokens, acquire a replacement drain, or briefly reopen ordinary admission for the body.

`UpdateQuiescenceLease.withExclusiveActivity` releases its internal mutex before calling the scoped body and validates ownership afterward.
Reuse that lifetime pattern. Do not call back while retaining a mutex that body validation needs.
Keep process, thread, re-entry, expiry and poison guards. Close during a loan defers resource release until that loan settles.
Pass the actual borrowed transaction frame to callbacks. No public machine queries or nested transactions run inside that callback.
Close capture handles before borrowing the mutation frame. Production `Machines.scoped` has no retained machine pool to suspend.

## Recovery executor and triggers

Use the existing Root Setup daemon, not a new job or a GUI-dependent worker.
Its bundled plist, `macos/app/Setup/dev.sebastiano.remozio.macos.setup.plist:7–25`, declares `KeepAlive`, `RunAtLoad` and Root.
`MacSetupServiceControls.swift:149–157` and `AdministrativeSetupService.swift:130–135` validate that manifest.
Apple's [launchd startup guidance](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) describes loading daemon plists and maintaining KeepAlive jobs.
That OS contract is not proof of this artifact's installed crash/reboot recovery. Those live gates remain unexecuted.

Run the new worker on Setup startup, after each interrupted window, and on an explicit restoration-only action.
Startup recovery begins after verified `AdministrativeSetupService.open` releases its temporary shared activity, before ordinary dispatch starts.
Reserve the Setup owner without acquiring an ordinary shared-activity wrapper that would block its own exclusive drain.
Keep the existing authenticated listener available for restricted status/recovery requests; gate ordinary mutation dispatch until reconciliation ends.
No app connection, still-live administrator form or logged-in desktop is required for automatic restoration under the original durable intent.
That intent permits recovery only. A new mutation always needs fresh authorization and a new operation scope.

Before stopping, verify that this exact Setup daemon is installed, registered, enabled and capable of autonomous recovery.
Missing or disabled recovery is NO-GO. KeepAlive declaration alone is insufficient.
After Setup crashes or is killed, launchd is expected to restart it. The new instance closes the previous window; it never resumes its body.
Acquire actual recovery ownership and prove the previous operation has settled before inspecting or restoring affected resources.
A competing live owner remains busy. A stale PID or missing launchd registration is not sufficient exit proof.

### Reboot and an authority already running

`RuntimeJobStopSession` uses `launchctl bootout system/<label>`; it does not delete the plist, disable it or call `SMAppService.unregister`.
The plist remains in `/Library/LaunchDaemons`. Reboot can therefore start AuthorityA before Setup recovery runs.
For retained work, A's journal was read-only. No uncertain target-B write justifies a new fence blocking A's journal startup.
Do not add an A startup fence copied from audit cutover. Audit's graph-bound fence protects a different mutation footprint.
The durable restrictions belong to the machine/target operation and admission, not a false claim that A's journal was modified.

If the exact AuthorityA is already running, adopt its restoration after native identity, readiness and floor checks.
Do not stop it again merely because the old maintenance phase is still open.
The old pinned A pair and native context are invalid after that restart; they cannot resume or validate the old operation body.
Keep ordinary admission closed through restoration checks, then release it without requiring uncertain B to become usable.
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
| Operation outcome unknown; A independently safe | Restore/adopt A and reopen safe admission; keep B blocked and show outcome unknown |
| Authority already healthy after reboot | Validate identity/readiness/floors, adopt it and close the window; no second stop |
| A/artifact/shared state cannot be proved safe | Persist `needsOwnerRecovery` or `repairRequired`; retain the relevant restriction and expose the cause |
| Restore command timed out or reply was lost | Freshly inspect the exact job/process and health; never infer absence, success or permission to replace |

Automatic recovery never reruns P04, A11, P05 or update mutation bodies.
Readback/reconciliation and bounded restoration are allowed; replaying a transaction is not restoration.
No recovery path clears `writing`, manufactures a startup receipt or advances B's activation/completion floors to restore A.

## Visible failure and attended exit

Recovery failure must not leave an approver down silently or make Setup crash repeatedly without a durable diagnosis.
Persist attempt/revision, last safe phase, separate operation/restoration outcomes and a sanitized actionable failure category.
Expose authenticated read-only Setup status before ordinary admission. The app shows approver availability and the blocked operation separately.
Emit bounded diagnostic logs without authorization data, policy payloads, private paths or credentials.
Apply bounded retry/backoff to restoration only. Permanent mismatches stop retries and remain visible.

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
Transfer the original quiescence ownership through `releaseActivityForRestart`; the same admission gate stays closed.
Allow only the actual shared activity needed by scoped startup/health during that phase.
`RuntimeJobRegistration.ensure` can restore exact registration. It cannot attest process identity, serving readiness or floor durability.
Reuse the restart health coordinator's live role proofs and the finalizer's joined-cleanup ordering with actual maintenance outcomes.
Validate A's unchanged floors for retained work; persist the actual required health/floor facts before reopening.
Do not invent a floor write when no floor changed. Do not require B's completion to release A's unrelated availability.
Normal update requires its real selected artifact, durable manifest, floor/epoch commits and closed admission through restart health.
Only an explicitly designated update owner can defer shared updates. Idle-only automatic activation remains unchanged.
An explicit signed drain remains indefinite until settlement. A time budget does not authorize forced release.

## Normal update policy preflight

The shared owner also supplies stopped-journal access for `MachineUpdatePolicyPreflight.captureNative`.
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
| M01 | Canonical purpose-bound durable value and outcome model | 80–160 | Exact decode, unsupported values refused, no capability from bytes |
| M02 | Protected reader/format requirements and admission recovery projection | 100–190 | Current readers gate producer; pending state cannot take a legacy bypass |
| M03 | Exact CAS phase/outcome writer and mutation footprint | 100–195 | One active attempt, unrelated protected rows exact, uncertainty retirement |
| M04 | Fixed cohort derivation and native stop/witness orchestration | 110–190 | Retained stops only A; no Setup or dynamic widening; missing recovery refuses before stop |
| M05 | Typed closed-quiescence loan and sealed admission proof | 100–185 | Real same drain; thread/process/expiry/close guards; no ordinary reopen |
| M06 | P04 frame/store/native admission adaptation | 100–195 | Complete typed transaction boundary; ordinary path still strict |
| M07 | A11 context/provider admission adaptation | 110–195 | Whole sequence pins A and actual frames; all loans close before restoration |
| M08 | Purpose-specific operation observation after interruption | 90–180 | Old/new/partial/unknown outcomes stay distinct; zero body replay |
| M09 | Exact restoration plus health/floor finalization | 110–195 | Adopt already running A; same closed gate until checks; no fake completion |
| M10 | Root Setup startup/interruption recovery worker | 110–195 | Runs before ordinary requests, without GUI; previous owner settlement; bounded retry |
| M11 | Restricted authenticated status and durable failure projection | 80–170 | Available while ordinary dispatch blocked; no mutation/export of sensitive state |
| M12 | Explicit restoration-only native owner action | 100–190 | Fresh rights/binding/revision; no arbitrary target, reset or replay |
| M13 | App recovery presentation and reviewed attended repair handoff | 100–190 | Distinct outcomes and actionable repair; no silent unavailable approver |
| M14 | Setup-native normal-update preflight facade | 110–195 | Actual update authority/candidate; original Authority guard preserved |
| M15 | Final authenticated composition and reachability gates | 90–180 | Every preceding guard/recovery path present before any service stop is reachable |

M04/M10 can expose internal library seams while incomplete. No ordinary endpoint can enter a window before M15's full dependency closure qualifies.
M06/M07 must split further if their complete adapter changes exceed the cap; never publish a permissive partial adapter.
M12/M13 reuse the approved caller identity/rights owners. Do not create a second account resolver or temporary Root endpoint.
Normal update integration follows its real replacement dependencies; it is not enabled by retained-source tests alone.

## Tests and unexecuted live gates

Use disposable protected stores, actual typed owners and fault injection at each durable/side-effect boundary.
Tests must distinguish operation success from restoration success and assert zero operation replays.

| Case | Required observation |
| --- | --- |
| Busy drain or active command | No stop; no forced idle; durable restrictions and actual owner remain coherent |
| Exact cohort and conflicting job | Only selected A stops; unrelated jobs remain; mismatch refuses without replacement |
| Lost bootout/bootstrap reply or PID reuse | Fresh exact observation plus original exit/exclusion proof; no guessed terminal |
| Failure before/after each commit | Actual old/new/unknown state retained; store retired as required; no body retry |
| Setup killed, logout, reboot | Startup worker runs before ordinary mutation; original operation never resumes |
| Reboot already restarted A | Adopt exact healthy A after readiness/floors; never stop it again for the stale phase |
| Unknown B but safe A | Restore approver independently; target intent stays blocked and visible |
| Repeated restoration failure | Bounded retries, durable visible status, attended restoration-only action or explicit repairRequired |
| Wrong PID/thread, escaped/reentrant loan or close during callback | Refusal/poison; defer cleanup until real settlement; no stale frame use |
| Normal update irreversible phase | Restore only the authorized artifact/roles; actual floors and manifest precede reopen |

Installed native identity, real administrator approve/decline/expiry, actual service stop/exit, recovery and measured downtime remain unexecuted.
Select a qualified signed artifact and exact commands before scheduling any attended gate. No service action is authorized by source planning alone.
Crash/logout/reboot and repair tests need prepared attended slots; a 30-minute initial session does not qualify all of them.
Product question 2 sets the acceptable approver outage and end-to-end delay. Record overruns honestly; never force unsafe cleanup to meet a bound.
Provider semantics, physical hardware, installed activation and the remaining full Remozio work remain explicit separate obligations.
