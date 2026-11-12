# E01 retained enrollment: accepted inventory image v2

Status: source-based design for Toni's review. Assignments: Telegram 1759 and revision 1766. No implementation or native validation occurs here.

V1 remains immutable. V2 adds release succession as open point 6 and updates one source range. No policy option is selected.

Pinned source: `63e7b317baabb92a7f56e27bc538d75163b60850`, tree `9b154ed74836b191ba08596de85e5504f0c6d1d9`.
The source index retains the paths and SHA-256 values used for this note.
The checked-out source remains `0a86037c`; the prepared source above is a separate local commit.

This note covers the inventory projection for retained enrollment. The earlier E01 v3 note covers promotion ownership.
Toni retains review, native validation, publication and merge ownership.

## Decision proposed

Keep the installed archive and stable seal immutable.
Accept a changed live inventory only when a private reader reconstructs its complete account and service content from checked retained plans.
Keep the actual live inventory in every returned snapshot. Never return the sealed inventory as if it were current.

The reconstruction validates metadata. It grants no enrollment, registration, health, floor, startup or file-publication authority.
A separate private writer must prove its authority and the permitted database change.

Do not implement this by deleting the current inventory equality checks.
Replace their stable-state use with two explicit checks: the unchanged sealed image and the precisely reconstructed live image.
Keep the finishing path strict.

## Current producer and reader path

All paths below start at `macos/core/Sources/RemozioCore/` unless stated otherwise.

| Source | Observed behavior |
| --- | --- |
| `RuntimeRetainedSetupActivationPlan.swift:124-165` | The proposal captures the actual inventory before enrollment, together with the retained binding and selected files. |
| `RuntimeRetainedSetupActivationArchive.swift:44-75` | The v6 archive excludes its own account ID and owner UID from that captured inventory. |
| `RuntimeRetainedSetupActivationPlan.swift:90-116` | `enrolledInventory` preserves the namespace and adds the exact account plus authority and transport declarations. It detects conflicts and preserves the revision. |
| `MachineUpdateRetainedSetupActivationSnapshot.swift:70-110` | The retained plan joins the recorded policy intent, preparation, initialization, provenance, release and captured inventory digest. |
| `MachineUpdateRetainedSetupActivationSnapshot.swift:134-158` | The value comparison permits one inventory addition with a new revision. It does not protect every other database row. |
| `PreparationIntentStore.swift:4030-4047` | The retained reader checks the actual activation row's account, material, digest, canonical v6 bytes and registration flag. |
| `PreparationIntentStore.swift:3639-3657` | The snapshot reads the runtime, retained plan and policy intent in one transaction and checks them again. |

The ordinary writer accepts `RuntimeActivationPlan`, not the retained plan.
`retainRuntimeActivation`, `enrollRuntimeActivation` and `markRuntimeJobsRegistered` remain ordinary operations (`PreparationIntentStore.swift:459-510`).
The transaction guard rejects ordinary writes at schema 24 or later (`5349-5394`).
The existing promotion authorization does not authorize retained enrollment.

There is no production retained enrollment writer in this pinned source.
The existing enrollment test constructs changed snapshot values without enrolling the actual store.
See `MachineUpdateReplacementTests.swift:4482-4494` and `4649-4667` under `macos/core/Tests/RemozioCoreTests/`.
These controls establish value comparisons, not a successful read after a production inventory commit.

## Why the actual reader needs this design

`loadStableMachineUpdateFrame` calls `requireFinishingActivation` with the live inventory (`PreparationIntentStore.swift:4266`).
That helper requires the live revision and bytes to match the installed header, completion target and installed inventory artifact (`3523-3526`).
The reader then requires `installed.inventory() == inventory` (`4269`).
A legitimate retained addition changes the bytes and revision, so this path rejects it.

`MachineUpdateStableReleaseRecord.requireCurrentInventory` checks namespace, release and bundle path (`70-76`).
It does not authenticate the current account or service membership.
Calling that method alone is insufficient to replace the strict reader checks.

`recordedScopeDigest` permits the captured inventory's accounts and services to remain present in the current inventory.
It also binds the complete captured inventory bytes into the policy source digest (`MachineUpdateRetainedSetupActivationSource.swift:90-121`).
That subset check supports an earlier capture. It does not establish that every additional current member is permitted.
The accepted-image check must supply that missing exactness.

## Three inventories with separate meanings

1. **Sealed image S:** the installed archive's inventory at update completion. Its bytes and revision remain fixed by the stable seal.
2. **Observed image O:** a retained plan's inventory before its account enrollment. Its complete bytes remain fixed in the v6 archive and source digest.
3. **Live image L:** the actual inventory row read from the current protected store. Its exact bytes remain part of the returned snapshot.

Keep the old provisioning inventory separate from all three.
It identifies the preparation's original release and scope; it is not the current membership image.

Validate the installed header, archive artifacts, completion target, finishing activation and initial inventory digest against S.
Validate L against the accepted-image reconstruction described below.
Never replace an installed artifact, seal digest, historical provisioning operand or retained plan to make L equal S.

`installedCurrentSourceProjection` already substitutes historical inventory operands for its historical digest (`PreparationIntentStore.swift:3434-3460`).
That digest is not a proof of L's membership.
Keep its historical meaning. Separately compare L's exact bytes and the complete actual transaction frame.

## Proposed accepted-image contract

Read all operands through one protected connection and one read transaction.
Use bounded private raw records during reconstruction. Expose no partly checked stable snapshot or caller-supplied acceptance flag.
Do not recursively call the public stable reader while constructing its acceptance proof.

Keep schema 24 on its exact sealed-image path. Admit a retained delta only at supported schemas 25 through 28 with all required declarations.
First validate the sealed archive and S through the existing archive and seal checks.
Keep activation, admission, candidate, retirement tables, schema declarations and the installed archive exact.
Read the actual preparation, initialization, service, runtime, policy and activation rows needed for each retained account.
Check their real SQL keys, material identifiers, canonical bytes, digests and cross-row bindings.

Determine the delta from S to L. The only admitted additions are retained accounts absent from S and their two exact plan declarations.
No account, service or machine field from S can disappear or change.
No extra frontend, GUI agent, gateway, role, label, plist, domain, execution UID or account assignment is implied by those additions.
Use `enrolledInventory` to derive declarations. Add no second namespace or job rule.

For every delta account, require one actual retained v6 plan and its matching recorded policy intent.
Require the original unconfigured retained account, exact owner, preparation, completed initialization, service plan and published runtime reference.
Preserve every existing release, provenance, source-account and recorded-policy binding.
A current-release reservation from A01a/A02a is not a retained enrollment operand.
An ordinary plan or a preparation row alone cannot justify an addition.

Check each plan's observed image O as an accepted earlier membership image.
S is the initial anchor. An O may contain only S plus additions already justified by other checked retained plans.
Its own target remains absent, as the archive requires.
Resolve these dependencies in bounded passes, with at most the existing 64 account operands.
Each admitted dependency must reduce the unresolved set. Reject a cycle, missing anchor, unresolved operand or conflicting declaration.
Two plans may both observe S; this does not require a fictitious chronological order between them.

Every observed addition must remain present in L. A pending plan cannot justify membership for its absent target.
A pending plan's own O must still resolve from the same checked operands.
Do not select an arbitrary decoded inventory or accept an unproved subset as an anchor.

Apply all admitted delta plans to S through the existing checked derivation.
Reconstruct the final canonical inventory with L's actual revision.
Require complete equality with L: all namespace fields, format, accounts, declarations and bytes.
Multiple dependency orders are harmless only if they yield the same exact membership and declarations.
Any conflicting result refuses; the reader does not choose one or repair the store.

Keep revision checks explicit. When L equals S, require S's exact revision too.
For a nonempty delta, require a different valid revision and compare L's exact revision on every subsequent frame check.
A revision is an opaque identifier, not a sortable counter or evidence that a particular writer minted it.
The writer must separately prove the CAS and its returned committed revision.

This algorithm is a proposed contract, not an implemented proof.
The future implementation must demonstrate that all cross-row checks can run without accepting a provisional snapshot as authority.
If the current APIs cannot do that, extract private validation primitives first. Do not weaken their conditions to avoid the dependency.

## Authenticated operands and comparison operands

Here, "authenticated" means observed under the required protected store or native custody and validated for this operation.
It does not mean the release signature signs each mutable database row.
It does not claim protection against arbitrary privileged modification of the entire store.

| Operand | Required source and limit |
| --- | --- |
| Candidate release | The owner obtains fresh signed evidence and checks the required reader/writer declarations. Decoded manifest bytes alone do not suffice. |
| S, seal and installed archive | The actual protected rows must pass their existing canonical, digest, namespace and completion checks. They establish the immutable release anchor. |
| Plan, policy intent and related rows | The reader checks actual rows and all bindings. Hash self-consistency alone does not prove who wrote them. |
| Owner identity | The owner resolves and checks the actual caller, UID and directory identity. A UID stored in a plan is only a claim. |
| L and expected snapshots | Exact comparison operands from actual reads. Their values carry no writer permission. |
| O and a proposed enrolled inventory | Captured and derived operands. They need the accepted-image proof and cannot authorize their own admission. |
| Journal and continuity boundary | The native owner observes the actual pair. A stored startup receipt is historical evidence, not a current pair observation. |
| Files and registration | The native owner checks actual protected files and both registrations. The inventory declaration and registered flag alone prove neither. |

Keep the E01 v3 pair-availability prerequisite open.
No idle flag, activity-file identity check or accepted inventory proves that the actual authority stores released their locks.
This design requests no service stop, restart, drain, floor change or reopen.

## Writer and replay requirements

A future private writer must retain the checked connection and required owner capabilities.
It must pin the actual before frame, the accepted-image proof and the exact retained plan before SQL mutation.
Extend no ordinary writer or promotion permit by implication.

For enrollment, derive exactly one target addition from the actual before inventory.
Check the old inventory revision in SQL and retain a new actual committed revision.
Protect every other row with the writer's complete row and catalog checks.
Validate the actual after frame, including `requireInventoryEnrollment`, before commit and in a separate read after commit.
Keep material publication, native registration and historical registration marking as separate checked steps.

A retry must read actual durable state first:

- No retained plan: verify and retain one exact plan through its separate owner operation.
- The exact plan exists, but its account is absent: enrollment remains pending. Do not infer registration or health.
- The exact plan and full derived account declarations exist: return the observed accepted image without another inventory write or revision change.
- Registration remains unmarked: independently inspect both native registrations before any marker operation.
- The marker is present: validate its scope again. It grants no floor or ordinary startup authority.
- A partial declaration, changed plan, foreign member or uncertain state: refuse without cleanup or replacement.

An unknown commit result makes the connection unavailable under the existing transaction contract.
Do not retry the body. Close, reacquire through the authorized owner and read the actual state.
A reopen result is evidence of current rows, not evidence that the earlier call returned success.

The existing rows do not retain a separate enrollment receipt for an unregistered plan.
Thus a reader cannot distinguish a never-enrolled pending plan from an exact restoration of that earlier pending image.
The private writer must prohibit rollback. Do not claim the reader independently proves that enrollment history.
A stronger durable-history requirement needs a separately reviewed record and compatibility design.

## Completion and multi-account boundary

`MachineUpdateRetainedSetupCompletionIntentRecord.requireSnapshot` pins the digest of the entire live inventory (`55-64`).
Its transitions preserve that digest (`112-119`).
Enrollment of another account changes that inventory, even if the first account's own data stays fixed.
The old completion snapshot can then fail before any promotion or health action.

Do not replace the completion inventory digest with a namespace check or recalculate the old receipt.
Do not present this inventory projection as a solution for completion across later enrollment.
The completion reader needs a separate accepted historical-image design if those later additions must remain compatible.
That design must bind the original image and prove only permitted additions; it cannot treat any earlier subset as valid.

Until that design exists, a private enrollment implementation must detect conflicts with existing completion records before mutation.
Do not ship a successful enrollment that silently makes another account's completion unreadable.
The refusal, scheduling or compatibility policy remains a lead decision before a product entry point is enabled.
This note adds no user-visible pause and does not select that policy.

The reconstruction must also cover two retained accounts before completion.
Plans captured before either enrollment and plans captured after an earlier enrollment need separate controls.
Do not label a single-account proof as complete multi-account support.

## Release succession: open point 6

Every retained plan used in reconstruction must belong to S's release.
`enrolledInventory` requires `inventory.releaseDigest == retainedSetupBinding.installedReleaseDigest` (`RuntimeRetainedSetupActivationPlan.swift:90-95`).
The exact guard is at line 93 of the pinned source. The peer review cited line 91.
The archive also binds its captured inventory to that release (`RuntimeRetainedSetupActivationArchive.swift:49-57`).
The rule applies to pending and enrolled plans. A missing registration marker does not remove the release binding.

Suppose an update installs a different release and produces a new sealed image S2.
The old retained plan still names S1's release. Applying it to S2 must refuse.
Do not change its binding, replace its observed image, skip its row or treat it as an ordinary activation plan.
Reading its bytes as historical evidence is separate from admitting it into S2's live reconstruction.

Toni must select a policy before an affected update or product entry point is enabled:

| Option | Consequences and required contract |
| --- | --- |
| Close retained plans before the update | Update preflight refuses while any relevant pending or enrolled retained plan remains. Existing release bindings stay intact. Closure must have a defined durable outcome and preserve completion and enrollment evidence. Pending work may require completion before an update can proceed. No closure or retirement procedure is supplied here; without one, this rule could block later updates indefinitely. Deleting a row is not an approved closure operation. |
| Permit the update and refuse the stable reader | If the update retains old plans under S2, reconstruction refuses on their release mismatch. Affected stable reads and operations that require them cannot report success. The owner needs an explicit recovery or migration contract before exposing this behavior. The reader must not fall back, omit the plans or grant startup authority. This is not permission to ship an unreadable stable state. |

These are policy alternatives, not two implemented paths.
Existing update compatibility and readiness checks may already refuse before installation. This note does not claim that such an update succeeds today.
Keeping old plans as an explicitly classified historical epoch would require a separate reviewed design, not an exception to the guard.

This decision is linked to open point 3.
An additional enrollment can change the inventory digest within one release; a later update can also change the release itself.
The completion receipt remains immutable in both cases.
Closing a plan must not erase or silently invalidate that receipt, and reader refusal must not reinterpret it as success.
Toni owns the decision and any required compatibility design.
If it changes visible Setup or update behavior, Toni takes that product choice to Seb.
This revision selects no refusal message, service pause, automatic completion, cleanup or update-blocking behavior.

Required controls cover both pending and enrolled plans across a release change.
A same-release control must first pass. The different-release reconstruction must refuse without changing either plan or seal.
Test the selected preflight policy before an irreversible update, plus restart and recovery under its separately approved contract.
No such tests or update operations ran for this note.

## Required validation before implementation can qualify

Every refusal control starts from a valid accepted image and changes one operand.
Name actual test selectors only after those tests exist.

| Control | Required observation |
| --- | --- |
| Exact S with no delta | Existing stable read succeeds with unchanged archive, seal and bytes. |
| One retained addition | A real private writer commits L; close and reopen; the real stable and retained readers accept L. |
| Two accounts | Both shared-preimage and later-preimage cases resolve without changing earlier plans. |
| Pending plans | They grant no target membership, registration, health or startup authority. |
| Content changes | Removal, foreign additions, partial jobs and each changed service field refuse. |
| Row substitution | Foreign owner, material, plan, intent, initialization, provenance, reference or digest refuses. |
| Dependency failures | Cycles, unanchored images, unknown observed members and conflicting additions refuse within the bound. |
| Revision and replay | Stale CAS refuses; a successful retry preserves actual bytes and revision; no write body is replayed after uncertainty. |
| Other rows and catalog | Every unrelated table and schema operand stays exact; unknown tables or changed rows refuse. |
| Completion collision | A later enrollment cannot commit an image that silently invalidates an existing completion record. |
| Reader separation | Ordinary state still rejects v6 execution; compatibility reads remain descriptive. |
| Native boundaries | The owner separately proves actual pair, file, identity, admission and registration conditions. |

The existing synthetic enrollment values do not replace the real-store positive control.
No parse, type check, build, XCTest, native adapter or service operation was run for this document.

## Open points for review

1. Confirm the private reconstruction boundary and extract shared validation without a recursive stable read.
2. Prove bounded multi-account reconstruction, including pending plans and all unrelated rows.
3. Decide the completion compatibility contract before enabling later enrollment through a product endpoint.
4. Decide whether durable unregistered enrollment history requires a new receipt. No new format is assumed here.
5. Close the existing pair-availability and native owner obligations through their separate review and attended gates.
6. Choose the release-succession policy for pending and enrolled retained plans before a later update. Preserve the completion contract from point 3.

This note changes no source, schema, release declaration, provider contract or product entry point.
It prepares E01 review. It is not a completed E01 implementation or a qualification receipt.
