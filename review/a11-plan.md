# A11: native retained runtime providers

## Status and authority

This is a source-based plan, not an implementation or a live validation result.
Toni requested this document in message 2413 and added the review requirements in message 2416.
The base is `74a5cecdfc954f3a7774853cdbc5a95e6043803e`, tree `a1f697ad1858d67e0912703e813900ea41c3e83d`.
This branch adds only this document. It starts no build, test, native provider or service.
Toni owns plan publication, implementation order, native capacity, wider qualification, PR readiness and merges.
Implementation must wait for the actual A10e merge and reconciliation with main.
Each implementation cut must merge before the next cut starts.

A11 supplies native material, publication and import-acknowledgement providers for A10e.
It also supplies the native publication and completion facades deferred from A09.
Authenticated callers remain outside A11. No command, RPC or service calls these entries in this plan.
The internal authority-account parameter does not prove a peer identity or authorize a request.
The first authenticated caller still requires the attended busy check in issue 725.

## Inspected responsibilities and gaps

- `MachineUpdateRetainedSetupMaterialPreparation.prepareNative` already owns native material preparation.
  It checks Root, installed placement, release and executing code, service identities, authority material and retained file identity.
  Reuse it. Do not copy the material writer, regenerate an established identity or create another key path.
- `MachineUpdateRetainedSetupPolicyNativeEntry` already selects a published current authority and holds its fresh read-only pair.
  Reuse its authority selection and typed journal access. The historical target cannot supply the executing-code policy.
  `MachineUpdateRetainedSetupPolicyNativeContext` accepts policy transitions only. Do not widen it for publication or ACK.
- `RuntimePublicationController.publishRetainedInitialNative` already publishes one fixed C2 artifact under its active loan.
  It checks the derived eight-file set, exact path/access/bytes, protected destinations and retained material reference.
  A11 needs a custody-owning facade, not another publisher or an arbitrary path API.
- A10d's runtime scope carries a snapshot, material and artifact, but not C2's actual selection scope.
  Its native publisher therefore needs an explicit scoped bridge to the original C2 loan.
  Do not reconstruct a selection from optional import arguments, published tunables or a later journal read.
- `RuntimePublishedArtifactValidation.nativeRead` already selects the required private, public or service-private read.
  C2 also needs an optional missing-leaf read. The existing optional public reader does not establish private-file permissions.
  Add only typed missing-leaf support where needed. Do not catch every `ENOENT` or treat missing ancestors as absence.
- A10c already owns the held machine writer lock, actual import inputs and the single conditional ACK advance.
  Its native provider must use the borrowed frame. It must not reopen the machine or the held import journal from a callback.
- A10e currently checks the material callback's value but does not call an outer host verifier during that loan.
  Add a mandatory typed material-host verifier. Keep the existing entry-host verifier for the other stages.
  A10e also uses `transactionActive` when its capture cap is exhausted. Use `JournalLeaseError.invalidated` for that case.

## Proposed implementation order

Every estimate includes changed production lines across all paths, including helpers, guards, adapters and deletions.
The hard cap is 200 changed production lines per cut. Tests and documentation do not count toward that cap.
Measure the complete diff before adding tests. If a complete responsibility exceeds the cap, revise this plan before implementation.
No cut introduces a temporary success stub, a permissive default or a reference to an absent concrete provider.
The names below are proposed source files under `macos/core/Sources/RemozioCore/`.

| Cut | Responsibility and production files | Estimate | Evidence that remains attended |
| --- | --- | --- | --- |
| A11a | Material-host callback and capture-cap classification: `MachineUpdateRetainedSetupRuntimeSequence.swift` | 35–80 | Actual installed host changes during the material loan |
| A11b | Borrowed host-verification contract: new `MachineUpdateRetainedSetupRuntimeNativeContext.swift` | 110–180 | Native custody, code identity, account and service checks |
| A11c | Real native custody factory: additions to `MachineUpdateRetainedSetupRuntimeNativeContext.swift` | 140–195 | Root, signatures, installed placement, admission and lease lifetime |
| A11d | Current-authority and target-pair scopes: new `MachineUpdateRetainedSetupRuntimeNativeAuthority.swift`; narrow reuse adapters only in the existing policy native entry | 90–175 | Real authority busy state and active-service contention |
| A11e | Protected material/artifact readers: new `MachineUpdateRetainedSetupRuntimeNativeFiles.swift`; narrow typed additions to `ProtectedServiceConfiguration.swift` | 90–175 | Root/private/service ownership and protected installed paths |
| A11f | Native material provider: new `MachineUpdateRetainedSetupRuntimeNativeMaterial.swift`; reuse the existing material entry | 75–145 | Native material/key custody, service identities and activity |
| A11g | Deferred A09c native facade: new `MachineUpdateRetainedSetupInitialPublicationNative.swift` | 80–165 | Real eight-file publication, modes and partial publication |
| A11h | Deferred A09d native facade: new `MachineUpdateRetainedSetupInitialCompletionNative.swift` | 80–165 | Real completion, crash recovery and protected-file refusal |
| A11i | Native A10d provider and C2 loan bridge: new `MachineUpdateRetainedSetupInitialRuntimeNative.swift`; `MachineUpdateRetainedSetupInitialRuntime.swift` | 100–190 | Real publication-to-marker order and installed recovery |
| A11j | Native ACK provider: new `MachineUpdateRetainedSetupImportAcknowledgementNative.swift` | 90–175 | Actual shared-import locking, contention and uncertain commit |
| A11k | Scoped provider assembly: new `MachineUpdateRetainedSetupRuntimeNativeEntry.swift`; narrow context adapters only if required | 80–170 | Installed full sequence, host changes and recovery between stages |

The deferred facades are complete library entries. They do not expose authenticated Setup dispatch.
A11g and A11h reuse the same context, pair and file adapters as A11i; they must not duplicate those checks.
If typed access across files requires a helper, charge every changed line to its owning cut.
A public or broadly constructible native token is not an acceptable way to fit the cap.

## A11a: mandatory host verification during material loans

Add a required `(MachineUpdateRetainedSetupMaterialSnapshot) throws -> Void` host verifier to the sequence contract.
Call it on the actual borrowed material value after the material comparison, with lifetime checks before and after it.
A thrown host error poisons the provider invocation even if the provider catches it.
A verifier cannot mint an Entry or fabricate a policy snapshot when the material reference is absent.
The owner still proves machine rows and exact material transitions. The host verifier checks external identity and custody only.
Update all sequence call sites and the owned tests in the same cut. Add no default no-op verifier.

Separate the exhausted capture cap from the existing `providing` guard.
A seventh capture refuses with `JournalLeaseError.invalidated` before opening the provider or reading storage.
Keep the provider re-entry refusal and its existing classification unless a separate defect requires a change.
Keep six outer captures, six input captures, the per-capture counters and zero callback queries unchanged.
Test the cap through a private test seam if needed. Do not expose a caller-selected cap or weaken an existing limit.

## A11b and A11c: context and real custody

A11b provides a complete owned verification context with expiring process/thread loans and re-entry refusal.
Its typed adapters accept actual Material, Policy or Entry/Inputs frames from their owning operations.
Each adapter applies the existing equality or operation-specific comparison before updating its approved value.
Allow only material retention, P04's policy transitions, the publication bit change and the exact A10b ACK transition.
Do not add a general changed-source flag or a new state writer.
Keep P04's native context policy-only. Do not cast a published entry to an unpublished material snapshot.

Host callbacks perform no public machine transaction, policy writer call, import capture or relay capture.
Pass the borrowed actual frame through the verifier. Do not wrap a full observer around every loan.
Separate cheap loan/admission checks from the explicit external identity and file checks required by the owner.
Keep external verification linear. Count each class of read rather than hiding it inside a generic verification closure.
Owned controls prove comparison, ordering and expiry. They cannot construct the native token added in A11c.

A11c alone constructs the native token from actual Root resources.
Require real/effective UID 0, the fixed machine directory, protected installed placement and stable copy identity.
Open actual admission and placement leases. Close them on every return and error.
Inspect the signed release, candidate, inventory, installed epoch and seal.
Validate the executing Setup code and fixed executable path against the current authority's approved policy.
Check the app and Setup identities, generations and code hashes. Reuse existing leaf validators where their contracts match.
Check the actual account and service directory identities. Never accept a synthetic success Boolean as native custody.
Absent material is valid only for the unpublished material stage; it does not permit skipping host or admission checks.
Established material and service activity remain exact. A material change never authorizes a new authority identity.
Fresh machine captures belong outside callback loans, before lending the context or after the owner closes its store.
The native token remains nonconstructible from owned controls. No GUI or Root execution occurs during source qualification.

## A11d: two distinct policy roles

Select the current authority through `PolicyNativeEntry.publishedAuthority` and the published command-host bytes.
Reuse `withCurrentPolicy`, typed read-only journal access and the existing protected journal/continuity leases.
Hold and revalidate the actual current authority pair while checking app and Setup code custody.
Refuse a changed published host, policy, checkpoint, account or lease. Close the pair on every exit.
An account selected from inventory is not an authenticated peer; the later caller must prove that identity separately.

Open the historical target pair read-only for publication, completion and ACK.
Derive its paths from the exact target initialization, never from caller paths or environment variables.
Keep its recorded startup policy separate from the current authority policy.
Only the recorded target policy feeds initial file bytes. The current authority policy gates executing code.
Never hold the target read-only pair across P04's startup write or reuse it after that stage closes.
Do not initialize, migrate, repair, reset or replay a journal through these helpers.
Source tests prove pair separation and expiry. They do not prove live authority contention or successful native startup.

## A11e: protected file reads

Reuse `RuntimePublishedArtifactValidation` for the exact derived artifact set and access kind.
Reuse `RuntimePreparationPaths` and fixed publication file names. No caller can select an arbitrary native path or anchor.
Read retained material through the existing protected runtime-record path and validate its exact reference and service plan.
Use `RuntimeMaterialPreparation.validateServiceActivity` for the actual activity reference, with an active host verifier.
Do not obtain expected presence, relay, gateway or client values from already-published files.

C2 may observe an absent leaf before its owner publishes that artifact.
If private optional reads are missing, add narrow Root-private and service-private variants through the existing checked reader.
Keep private modes, service UID, Root-owned ancestors, ACL, identity, size and change checks.
An absent leaf can return nil only after the checked ancestor walk. A missing or changed ancestor still refuses.
The material stage must establish required destinations; an observer never creates them.
Published recovery treats every missing artifact as an error and never repairs it.
Keep the general 65,536-byte reader bound and ordinary readers unchanged.
Test missing leaves separately from missing ancestors, symlinks, metadata changes and wrong access kinds.

## A11f: material provider

Open one actual machine under the scoped native resources and validate its lease.
Call the existing `MaterialPreparation.prepareNative` with the actual Material frame and mandatory material-host verifier.
Supply the fresh current-authority code policy from A11d, not the target's historical policy or a free policy argument.
Accept no file-custody Boolean from an external caller; the real scope must establish that precondition.
Keep the existing writer exclusion, missing-reference retention and existing-reference refusal behavior.
Close the machine on success and failure before returning the owner's actual state.
The outer sequence compares that state with a new actual capture; the callback must not perform that capture itself.
A false publication result or a changed established identity refuses. There is no automatic retry after a native error.
Key and hardware checks remain mandatory but unexecuted outside their attended gate.

## A11g, A11h and A11i: A09 facades and the publication provider

A11g exposes native C1-inside-C2 publication with real custody, the held target pair and fixed native file callbacks.
Keep the original C2 scope active when calling `publishRetainedInitialNative`.
Verify material, activity and all eight derived artifacts through their typed scopes.
This facade publishes files only. It cannot complete the marker, acknowledge an import or register jobs.
An exact existing file stays untouched. Partial publication may continue from fresh actual state; conflicting bytes refuse.

A11h supplies native D2 completion with the same read-only target pair and protected file readers.
Call the existing completion owner and retained writer. Do not call the ordinary publication-completion API.
Keep borrowed transaction frames inside their writer lease. Do not open a second public machine reader from a callback.
Eight correct files with `complete = 0` permit one marker UPDATE and no file writes.
Already-published recovery verifies exact bytes, material and pair without another UPDATE or repair.
Lost acknowledgement ends the invocation; a later invocation reads actual state before choosing recovery.

A11i makes the A10d publication provider concrete without duplicating C2-to-D2 sequencing.
Add a narrowly scoped bridge from the A10d publication callback to its original active C2 publication scope.
The bridge must expire with that callback and preserve process, thread, poison and recursion guards.
It may not leak a selection across C2 return, D2 completion or import acknowledgement.
Do not reconstruct C2 inputs from A10d's snapshot/material/artifact fields; those fields omit the actual selection.
Reuse A11g/A11h's callback adapters, then call the existing `InitialRuntime.prepare` for the sequence.
Keep the confirmed 63 normal pair reads and eight published-recovery pair reads unless a reviewed safety requirement changes them.
The C2 final binding comparison and C1 post-body recorded-pair check remain intact.
Each provider-created machine closes before its result returns to A10e.

## A11j: acknowledgement provider

Call `MachineUpdateRetainedSetupImportAcknowledgement.acknowledge` under real native custody and a fresh target read-only pair.
Read native material/activity and all eight derived artifacts through A11e, using A10c's borrowed actual frames.
Keep the same machine open and its writer lock held across read, journal advance and final read.
Do not use P04's close-before-journal-write pattern here; A10b deliberately owns a different interval.
Do not reopen the held import journal, query the machine inside a callback or accept expected import choices from the caller.
Only A10b performs the conditional retained-to-runtimePublished advance. No machine row or catalog changes.
The outer sequence skips actual absent or empty journals. Direct ACK entry still refuses incomplete inputs.
Already-acknowledged input verifies the same files and pair, returning `advanced = false` without writing.
An uncertain commit ends the invocation and closes affected handles. Recover only through a new actual capture.
The exact unchanged retained record can support one fresh conditional attempt; an exact committed result recovers without another advance.
Every other phase, revision, scope, proposal or relay change refuses.
Measure ACK invocation and contention separately. Do not label an invocation upper bound as BEGIN/COMMIT timing.

## A11k: native provider assembly

Assemble the completed native material, P04, A10d and ACK providers for `RuntimeSequence.prepare`.
Supply mandatory Entry and Material host verifiers from the real context.
Use fresh actual entry captures for stage decisions. Preserve writing-before-material, published-material skip and absent/empty ACK skip.
Keep all existing exact result comparisons, capture caps, read counters and closed-provider boundaries.
Lend current authority custody only for the active invocation. Do not cache a pair or native token across requests.
Return the internal actual frame and inputs. It grants no enrollment, activation, ordinary-ready, consent or request authority.
No authenticated dispatch, command registration, request decoding or caller-selected authority ID enters this cut.

## Tests, source qualification and attended evidence

Each cut receives a source-pinned build and focused tests for every new or changed class, after Toni grants the native slot.
Use owned controls and protected temporary files for ordering, equality, expiry, rollback and refusal tests.
They prove those contracts only. They never prove installed Root custody, signatures, key hardware or service identity semantics.
No test may disable a native guard, substitute true for a mandatory verifier or count a parser result as runtime evidence.
Retain actual per-case outcomes, environment, source hashes, commands and consumed terminals. Failed runs remain failed.

Keep six outer captures and zero public machine queries in provider callbacks.
Count native metadata, pair, material and artifact reads separately from the owners' internal reads.
Add refusal tests for host changes during a material loan, an exhausted capture cap, expired C2 bridges and foreign-thread use.
Keep actual absent/empty, partial publication, published missing/conflicting files, lost marker acknowledgement and lost ACK recovery cases.
Use shared owned fixtures where isolation permits. Do not reset SQL rows or copy databases to conceal fixture cost.
A10e measured 353.936 XCTest seconds for six new methods; the maximum case was 80.317 seconds and command 89.067 seconds.
Issue 737 owns profiling and the remaining timing margin. Toni owns its scheduling and CI weights.
Keep the existing 120-second command limit and 1800-second local allocation. Replan with Toni if the measured scope cannot fit.

| Attended live gate | Required observation | State in this plan |
| --- | --- | --- |
| Native custody | Real Root caller, signed installed bundle, fixed Setup path, admission/placement leases, actual account and service identities | Not run; required for A11c and native providers |
| Material | Missing reference through real native preparation; existing material/key/activity remains exact; every custody failure refuses | Not run; required for A11f |
| Publication | Real protected destinations, all eight modes/owners/bytes, exact-file retention and partial-publication recovery | Not run; required for A11g/A11i |
| Completion | Correct files before the single marker update; lost acknowledgement and published damaged-file refusal without repair | Not run; required for A11h/A11i |
| ACK | Real held machine lock and shared journal, contention, no machine-row change, committed and unchanged uncertain outcomes | Not run; required for A11j |
| Installed sequence | Material, recorded policy, files, marker and ACK under actual native custody; fresh recovery between stages | Not run; required for A11k |
| First authenticated caller | Verified peer-derived authority identity, live authority busy refusal, end-to-end commit/inspection timing under issue 725 | Outside A11; required before that caller is written |

These are explicit attended obligations, as in issue 725. Source completion cannot mark them passed.
Toni selects the final qualified artifact before the exact interactive handoff is prepared.
No unattended Root/sudo, secret access, signing identity, service restart, hardware experiment or GUI operation is authorized by this plan.
The provider semantic adapters, installed approval flow, hardware and platform gates remain separate and unqualified.
Keep the existing Setup UX, admission closure, durable manifest/floors and restart-health contract unchanged.
The full Remozio objective remains incomplete.
