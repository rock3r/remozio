# M05: complete Authority work boundary

This revision follows Toni2990 and Saturn2989. It supersedes the initial command-only scope in11bc8a82.
Inspected source:7698e3ef1761a145aea841a866336ed1b440e4de, tree3a0b1275e7aec5b2fb8745f196cf820adee5671e.
This is source analysis only. It does not prove an installed handshake, idle state or safe service stop.

After Toni2987, Bepi drafted M05a locally:71 production lines,8 new methods and1 strengthened existing method.
Toni2990 paused implementation before any commit, build, test or publication.
The complete draft is retained in /private/tmp/remozio-bepi-M05a-paused-WIP-2990-20261114.
Its custody SHA256 is e4be09d772cfa41360de01c32992a07a3e107b2553fa332154d78d24d1ac96f4.
Only those draft edits were restored. The checkout is clean at7698e3ef on the M05a branch.
The draft is not qualified and must not be applied before Toni publishes and confirms this revision.

## 1. Receiver admission does not cover session creation

The proposed simplification is not valid for every kind of receiver state.
The real account drain blocks command request creation. It does not block HELLO acceptance or all temporary input ownership.

| Event or state | Actual source path | Account gate before state creation? | Required maintenance treatment |
| --- | --- | --- | --- |
| Receive a message and retain its Mach rights | CommandReceiveHost.receiveTurn:218-249 | No. The receiver owns the message before the journal admission call. | Observe the actual active turn and retained input. Do not call a receive timeout idle proof. |
| HELLO negotiation and retained session | CommandReceiveHost:251-252; CommandSessionRegistry.accept:44-58 | No. It validates current code and scope, sends the profile, then stores a RetainedCommandHandshake. It does not acquire account admission. | New sessions can appear after the drain. A passive pre-drain counter alone cannot stabilize this set. |
| Decode/select an existing session and create an admission attempt | CommandSessionRegistry.prepareAdmission:114-136; CommandReceiveHost.pollAdmission:176-187 | No. This happens before AuthorityJournal.admitCommandAttempt. | Track the real attempt and its original resources until ownership transfers or cleanup finishes. |
| Resolve and assemble a command, then create its request and replay reservation | AuthorityJournal:409-451 and following capture/admission code | Yes on the production configured path. The journal acquires admission at435 before resolve/capture. A busy gate sends updateWaiting and closes the attempt. | Reuse the actual registered A gate. Do not add a second request-creation gate or fabricate a scheduling action. |
| Direct retained-command/public adapter request creation | ApprovalRequestCoordinator.admit and acquireUpdateAdmission; AuthorityUpdateAdmissionStartup:10-27 | Configured production request creation uses the attached boundary. That boundary can be absent in legacy or fixture modes. | The future factory must require the exact installed A boundary. Optional admission is not a maintenance capability. |
| Existing decision, expiry and execution | ApprovalRequestCoordinator:181-185; AuthorityCommandAuthorizationNotice:37-69 | Intentionally not blocked by the request-creation drain. | Let existing work finish through its ordinary lifecycle. Do not expire, cancel or stop it to force idle. |

CommandSessionRegistry.synchronize:173-182 prunes on code revision or failed identity recheck.
MachCommandHandshake.recheck:279-287 has no normal session expiry for a still-valid frontend.
Therefore a session can remain retained while A's account drain is held. New HELLO traffic can also add sessions during the drain.
The receiver is serial, not protected by a public observation lock that another thread can borrow today.
Inspection must run on its actual queue or through a safe owner boundary. Cross-thread access to registry.retainedSessionCount is insufficient.

M05b cannot simply wait for all pre-drain sessions to disappear and assume no new ones exist.
There are two safe design choices for Toni to select before implementation:

- Add a narrow reversible receive boundary that prevents new HELLO/attempt ownership while preserving the existing receive right and session lifetimes.
- Prove that passive HELLO sessions have no request mutation or unsettled work, exclude only those passive resources, and still fence/join active turns before stop.

The second choice needs actual ownership evidence and a documented treatment for the remaining passive rights.
Neither choice may clear sessions, destroy the receive right or fabricate an expiry to obtain zero work.
CommandReceiveHost.close, worker.close and commandExchanges.stopAndDrain are irreversible shutdown paths on this source.
They do not implement cancellation that returns A to ordinary service without restarting it.

## 2. Process composition and scope

AuthorityMain:8-18 has three modes:legacy configuration, presence configuration and installed command configuration.
The per-account maintenance owner must require the supported installed command incarnation. Other modes do not inherit its proof.

InstalledAuthorityCommandRegistration:421-503 composes the installed runtime.
AuthorityWakeService:190-246 creates the foreground journal/service, app presence/pairing listener, receiver, execution worker and publisher factory.
It also owns phone registration capability, scheduling offers and background tasks.
Registration additionally composes settings control, settings recovery and the optional extension monitor.
The rows below cover those concrete construction paths. They are not an inventory of every type in the repository.

| Hosted endpoint or owner | Writes or non-idempotent work | Required idle boundary or reason for a narrower exclusion |
| --- | --- | --- |
| AuthorityXPCEndpoint through AuthorityXPCListener and AuthorityTransportAccess | Decision exchange consumes signed decisions. Frame access can update delivery state and expire requests. Routing challenge/apply writes protected routing state. | Include real invocation work, the journal operation and post-lock authorization callback. The account creation drain does not fence these operations. |
| Transport trust/peer snapshots, phone audit queries, pairing receipt and wake hints | Trust/audit queries read and sign; they do not authorize target execution. Replies can be lost during disconnect. Some delivery/status paths also update clock or retained delivery state. | Exclude only proven read-only suboperations from mutation blocking. Join any admitted journal access and reply/resource ownership. A lost read reply can retry its observation, never a decision or command. |
| Phone push registration and recovery, exported through AuthorityXPCEndpoint | AuthorityPhonePushRegistration.process/processRecovery can renew or register candidates and update the token ledger. Capability selection and provider lifetime are separate owners. | Include authenticated handler reservations, protected writes and provider installation/retirement. A routing/request count does not cover these owners. |
| Phone update scheduling endpoint | AuthorityTransportAccess:152-166 leaves the journal lock before the provider takes machine scope. Registration:323-335 invokes journal.exchangeUpdateScheduling. Challenge/apply writes or consumes scheduling state. | Track the complete invocation across the lock handoff and actual machine/account loan. No fake scheduling action or blanket update cancellation is allowed. |
| AuthorityPresenceXPCEndpoint, optionally wrapped by AuthorityAppXPCEndpoint | current reads state; publish changes RAM presence; setMode writes durable routing state through AuthorityPresenceAccess. | Include active setMode and current/publish handlers. After their work joins, volatile presence observations and withdrawn RAM state may be discarded at stop. They are not execution outcomes. |
| AuthorityPairingXPCEndpoint on the app listener | stagePairing retains a confirmation attempt, release activity and expiry timer. commitPairing writes enrollment/checkpoint state and signs a receipt. An unknown commit must reconcile its receipt. | Include both active handlers and staged attempts between calls. Do not clear or force-expire an attempt to get idle. A safe natural expiry is its existing lifecycle, not proof from elapsed time alone. |
| AuthorityService's AuthorityMaintenanceLoop | Expiry runs under journal.withRequests and retires actual pending requests/resources. An optional fixture maintain callback is not a native proof. | Include admitted maintenance turns. Preserve genuine expiry. Prevent another mutating turn after the final boundary is captured. |
| AuthorityJournal command execution owner and cleanup timer | Starts commands and records terminal outcomes. It retains execution and release activity until terminal delivery, pump readiness and native monitor disposal succeed. | Include every retained execution, even after its durable consumption becomes terminal. Do not equate native exit, terminal row or pending-queue emptiness with released resources. |
| AuthorityCommandExchangeOwnership and AuthorityCommandExecutionWorker | The exchange reservation spans the post-lock enqueue callback. Worker reservations span queued starts, rejected starts and reporting. | Include all actual reservations. A rejected start can own work while pending.count is zero. Do not stop the producer or worker merely to observe it. |
| Command receiver and session registry | Own Mach rights, validated sessions, inputs and synchronous admission callbacks before request creation. | Use the exact treatment in section1. Joined pre-drain creation alone does not cover later HELLO sessions. |
| AuthorityWakePublisher, its GatewayRootChannel and publication worker | Reconcile sends external wake registration/withdrawal and later acknowledges under the journal owner. Phone mapping/head reconciliation also writes or renews protected state. | Include the complete async turn across the channel and post-response journal commit. An empty request queue does not cover an in-flight acknowledgment or withdrawal. Do not replay an uncertain external mutation to make the window green. |
| AuthorityPhonePushCapability, settingsDrain and recoveryDrain | Provider install prepares the ledger and phone registration. Settings/recovery can fence capability selection and replace an installed provider. Prior cleanup survives cancellation until joined. | Include installing state, exact provider generation and all admitted replacement/cleanup tasks. Existing settings-change tokens are purpose-bound; do not invent one for maintenance. |
| GatewaySettingsControlXPCEndpoint and AuthorityGatewaySettingsListenerSupervisor | A Root Setup control can quiesce or accept phone settings. It owns async work until closeAndWait joins it. The supervisor can build/start another listener. | Include the endpoint's operation/budget, retired tasks and listener generation. New admission needs reversible maintenance handling rather than destructive listener close. |
| AuthorityGatewayExtensionMonitor and AuthorityGatewaySettingsStartupRecovery | The optional monitor can reload protected state, invoke recovery and install a provider. Startup can publish or reconcile optional configuration before normal service starts. | Include its actual refresh and cleanup, not the last diagnostic status. Suspend future turns through a reversible owner boundary, or reject the window while a conflicting recovery is active. |
| AuthorityGatewayRecoverySupervisor and GatewaySettingsRecoveryCoordinator | Registration:370-409 can prepare/remove settings recovery publication and send control to transport/gateway consumers. It also retains Root pause tickets and joined cleanup. | Include the whole recovery transaction and external control lifetime. This is non-command work with machine metadata effects. Do not shut down or replay it to force the retained window. |
| AuthorityUpdateSchedulingOfferOwner | Registration:310-317 calls journal.refreshUpdateSchedulingOffer under a selected candidate scope. This is protected offer/challenge state, not merely a UI timer. | Include the refresh and its actual selection/loan. Fence future refresh turns reversibly. A cached offered/absent status does not establish settlement. |
| Optional MachineUpdateConsumerHealthXPCListener factory | Registration:200-217 can expose signed readiness observation. There is no call to startInstalledReadinessListener in the inspected installed composition. | Do not claim it is currently started. If a later composition starts it, add its exact invocation and journal/resource ownership before the same proof can cover it. Readiness replies remain observations, not command grants. |
| Listener connection registries, timeout timers and endpoint retirement | Own accepted connections and delayed close callbacks. Pairing can retain an attempt between operations. Presence close withdraws volatile state. | Join admitted operations and cleanup. Passive transport connections or timeout diagnostics may be excluded only after their mutation capability is fenced. Connection absence is not an idle proof. |
| AuthorityRuntimeRunner and installed registration lifetime | Startup/retry can recover storage and create a new instance. Retirement/deinit can join old work asynchronously. | Bind the proof to the current running incarnation, native identity and retained registration. A replacement instance cannot inherit it. A diagnostic running status alone is insufficient. |

No other-account service, transport or gateway process belongs to the stop cohort.
Their external replies can still be dependencies of A's hosted work. Join those exact exchanges without stopping the other processes.
The native CommandMonitor and CommandChild are separate executables, but A owns their cleanup through CommandExecution.
Those child/resource owners remain inside the proof until actual settlement.

## 3. What a complete boundary must do

A journal lock protects a transaction. It does not stop a new handler or async callback from arriving after a zero-count sample.
A valid design needs a purpose-bound, reversible admission boundary for all hosted mutations and background turns listed above.
It must preserve ongoing decisions and execution while joining them. It must also preserve status/recovery availability under the reviewed protocol.
Do not count the authenticated maintenance verifier as ordinary work, or exempt arbitrary caller flags from the boundary.
A concrete operation classification must decide which status observations stay available and prove their lack of mutation or resource transfer.

Ownership starts before native handoff or task scheduling and ends after actual work, callbacks, reply ownership and cleanup settle.
A reservation without an installed task remains work, as OwnedTaskHandoff already demonstrates.
Cancellation cannot release a reservation while its task or machine/account loan survives.
An observation can report work. It cannot grant idle merely because another owner was sampled earlier with zero work.

Bind the eventual proof to A, machine/installation, exact attempt/revision, registered gate identity, Setup peer, listener incarnation and current Authority process.
Revalidate before mutation. A changed PID, code, gate, connection or attempt refuses entry.
After exact removal starts, reconcile expected disconnect against the same retained process witness. Do not invent a final live reply after stopping A.
Keep audit's EX requirement intact. Keep ordinary machine activity shared and A's real account drain held through the reviewed lifecycle.

## 4. Revised estimates and order

These are source-planning estimates. The hard cap remains200 changed production lines per PR.
The wider process scope does not fit three single PRs. It also does not fit the old command-only M05b estimate.
No final idle endpoint, proof type, permit or native factory exists before the complete M05c composition.

| Group | Complete supporting responsibility | Estimate | Sequencing condition |
| --- | --- | --- | --- |
| M05a | Internal command owner observations, including actual request/capture/activity, exchange, worker rejection and native execution custody | 71 drafted; allow80-140 after review | No endpoint or idle predicate. The uncompiled draft has no claim over the other rows. Mandatory command negative tests belong here. |
| M05b1 | Receiver ownership classification and queue-confined observation, with a reviewed treatment for post-drain HELLO and input ownership | 110-190 | First decide passive-session exclusion versus a narrow reversible receive boundary. Do not duplicate the actual request gate. |
| M05b2 | App pairing/presence and transport mutation admission plus active/staged owner settlement | 140-195 per complete responsibility; likely more than one cut | Preserve existing decisions, natural expiry and receipt reconciliation. Read-only exclusions need tests. |
| M05b3 | Async publisher, capability, offer and recovery ownership across external replies and cleanup | 300-550 total, split into complete cuts under200 | Separate publisher/provider and settings/scheduling recovery if necessary. Existing close routines do not supply reversible pause. |
| M05b4 | Per-incarnation composition of those owners under one reversible maintenance attempt, without an idle-success endpoint | 120-190 | Every contributing owner must already have its real fence/observation/join contract. No Boolean provider seam usable by Root. |
| M05c support | Bound request/reply validation and native peer/attempt/incarnation checks, without issuing proof or exporting idle success | 100-180 | Remains inside M05c. Keep it unreachable until the final issuer exists. No manifest declaration merely for dormant capability. |
| M05c final | Complete live proof, purpose-bound permit and separate native stop factory, introduced together | 140-195 if all support is complete | Measure before tests. If it does not fit, revise supporting cuts first. Never ship a factory that can open without real proof. |

M05a's minimum base is M04 at7698e3ef, or verified main after its actual merge.
M03b2/M03c writers are not needed to compile these supporting observations. Reachable attempt creation still needs its qualified durable owner later.
Toni must publish this revised scope and select the next complete cut before Bepi restores or expands the archived draft.
The exact protocol, operation classification and passive-session treatment remain design work. These estimates do not assert their implementation.

## 5. Mandatory tests by responsibility

M05a: pause a committed authorization before enqueue; observe its real exchange and capture ownership.
Keep a rejected-start/report callback active with no pending dictionary entry; observe the real reservation.
Keep a durable terminal outcome with unsettled pump/monitor disposal; observe the retained native execution.
Observe a pending decision without changing its clock, deadline or resources. Refuse missing, closed or reentrant owners.

M05b receiver: hold an input across drain acquisition; verify exact updateWaiting refusal before any request/replay reservation.
Send HELLO after A's drain; prove its actual state treatment. Preserve the original receive right and valid passive-session semantics on cancellation.
Never declare idle from a timeout, empty queue, valid frontend exit guess or manually cleared registry.

M05b other owners: pause pairing after staging and inside commit, presence setMode, routing/scheduling apply and rejected/unknown replies.
Pause wake registration after its external response and before its journal acknowledgment.
Pause a settings/recovery control, provider replacement, offer refresh and their cleanup or machine/account loans.
Each must remain represented until settlement. Cancellation must not force expiry, replay work or discard a reservation.
Prove that approved read-only observations cannot mutate state or transfer an unsettled resource.

M05c: test foreign/replaced code, Setup path, attempt, revision, protected gate, account, connection and Authority incarnation.
Test cancellation/disconnect before removal, the exact authorized transition to removal, and reconciliation of expected disconnect through the original exit witness.
No installed service stop or physical device operation is authorized by this source report.
