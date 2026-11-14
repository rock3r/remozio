# Attended retained policy validation for issue 725

## Chosen prerequisite and evidence goals

Toni selected stopped-service maintenance in message 2740 and requested these revisions in 2742/2754.
Fetched main is `b899e1ad34836b37745f9099db8d2594ea384150`, tree `3117e2d9c6460a2c52bea8a55c25dd80f8328f3a`; A11k #753 is merged.
This is a plan only. No runner, installed operation, build or service action ran for this revision.
Toni selects artifacts, implementation order, native slots, publication and merges.

The [source analysis](725-busy-analysis.md) establishes the structural busy cause: AuthorityA retains its exclusive journal while healthy.
Drop the former E01/E02 discovery probe work. Do not spend new cuts polling for an idle gap that the source does not provide.
Implement and qualify the [maintenance owner](maintenance-window-plan.md) first, including visible recovery and the attended restoration-only exit.
Then validate its actual installed composition. P05 remains a separate action under the same window, never a remedy for structural contention.

[Issue 725](https://github.com/rock3r/remozio/issues/725) still requires three distinct installed observations:

1. The current authority lock is busy while its service is healthy, then obtainable after the exact stop and proven exit.
2. One actual native P04 policy commit from the fixed installed Setup executable under the typed closed-maintenance loan.
3. Measured end-to-end cost, signature inspections, transaction intervals, full pair-loan duration and actual approver outage.

Source analysis and owned fixtures cannot mark these live gates passed. A failed or skipped gate remains explicit.
Use the approved caller plan at plans-branch commit `0327d091` for current peer, distinct retained target and real administrator rights.
No temporary unauthenticated Root endpoint, new account resolver or relaxed native guard is acceptable.

## Existing harnesses and remaining gaps

Reuse the [experiment index](../docs/experiments/README.md) and existing procedures where their contracts fit.

| Existing harness | Reuse | Limit |
| --- | --- | --- |
| [Service lifecycle](../docs/experiments/service-lifecycle.md), `scripts/check-service-lifecycle.py` | Manifest/placement inspection, explicit intent, actual job/process observation and owned cleanup | Disposable SMAppService register/unregister is not the production exact-job launchctl stop or installed recovery proof |
| [Authority journal](../docs/experiments/macos-authority-journal.md), `experiments/authority-journal` | Separate journal/checkpoint evidence, exclusion, bounded children and crash classification | Ordinary-user disposable stores; the executable refuses Root and cannot substitute for the installed path |
| [Portable import XPC](../docs/experiments/macos-portable-import-xpc.md) | Peer/channel identity, cancellation and reply settlement | Synthetic ordinary-user fixture services and injected administrator checks do not prove real Root/rights |
| [Release signing](../docs/experiments/macos-release-signing.md) | Actual signed bytes, `SignedReleaseInspection.inspect`, deadlines and sanitized evidence | Inspection results do not measure the native retained operation or approver outage |
| P04/A11 owned tests | Scope, frame, phase, refusal and conservation contracts | No installed caller, real administrator approval or launchd recovery proof |

`SetupMain` has no attended policy command on this source. P04 is an internal API, not an operator command.
The current ordinary-admission native facade cannot run unchanged inside a closed exclusive drain.
The new runner and maintenance-aware installed adapter are proposals. Their exact invocation and recovery procedure do not exist today.
The runbook remains **NO-GO** until those dependencies, signed artifact and exact command receipts qualify.
No guessed flags, generic `sudo`, test filter or moved experiment binary can clear that gate.

## Targeted installed validation

Use one real current authority A and a distinct genuine retained target B with existing choices and consent.
Derive A from the verified app peer and protected state. Resolve B through the approved unique retained-operation predicate and directory identity.
B can be outside current inventory membership. Never accept caller-provided account IDs, policy, paths or release requirements as authority.
Do not provision an account or synthesize a stuck marker during the operator session.

Keep at most one bounded healthy-service busy control, using the real primitive and immediate normal close if unexpectedly acquired.
It opens no SQL store, initializes no file and mutates no marker. An unexpected acquisition requires investigation of exact identity/continuity.
This is a control within the prepared maintenance validation, not a standalone discovery implementation or permission to chase transient gaps.

Enter the explicit reviewed window through its actual owner. Persist intent/drain before stopping only AuthorityA.
Wait for actual command/child settlement, exact registration removal, process exit and required lock exclusion.
Acquire and pin the full read-only current A policy/checkpoint pair through the real typed maintenance context.
Keep unchanged transport/gateway jobs registered. No dynamic cohort expansion, forced lock takeover or kill-to-idle is allowed.
Verify the stopped pair can be acquired; record busy, refusal, pending and timeout honestly if it cannot.

Import real administrator rights at the authenticated invocation and retain the owner reservation until operation, reply and cleanup settle.
The private installed experiment facade must run in the fixed Setup executable with original Root/code/placement/release guards.
Its only mutation is one P04 `resumeNative` call on the existing selected target operation.
Do not automatically run material preparation, C2, D2, ACK, P05 or the full A11 sequence as part of this experiment.
An unresolved unchanged `writing` source still refuses. No catch block resets it or retries the body.

After the body, retain separate operation and restoration outcomes. Join all work and close every borrowed frame, pair and store.
The maintenance owner restores/adopts A, verifies live readiness and applicable floors, then releases the original closed gate.
Registration success alone is not service health. B's unknown result does not require withholding A if independent restoration is proved safe.
Recovery never repeats the policy action. A lost reply requires fresh observation, not a second commit.

## Timing and evidence contract

Use a bounded internal recorder, not caller-injected verification callbacks.
Record native entry, each actual signature inspection, transaction/storage stages, current pair acquisition and its actual release.
Also record drain start, actual approver loss, stop/exit, restart/adoption, verified readiness, admission reopen and final response.
Approver outage is not the same interval as the journal loan or the P04 owner phase.
Retain monotonic clocks and units, reported event sources, counts and incomplete/overflow status.
Instrumentation cannot alter transaction order, query protected machine state from a borrowed callback or record payload bytes.
Include failure/cleanup time. Never reconstruct missing stage events by subtracting unrelated totals.

The private #737 fixture measured 38.489 seconds total and 6.970 seconds in C2's owner phase.
Those are fixture measurements, not installed P04 timing, full A11 duration or an approver availability bound.
Apply Seb's selected acceptance bound to end-to-end delay and actual approver outage; report the pair-loan interval separately.
An overrun fails acceptance. It does not permit forced release, rollback of committed state or automatic replay.

For each gate retain source commit/tree, tracked-input hashes, selected runner/bundle hashes, public signing IDs and environment.
Bind the installed Setup path and exact loaded job to the selected signed artifact before and after the action.
Use sanitized A/B labels and equality/digest results; do not commit raw private account or policy data.
Record exact old/new marker phases, actual policy/checkpoint comparisons and protected readback without claiming an unknown result committed.
Retain command arrays, child ownership, log hashes and consumed terminals. A timeout, JSON file or display message alone proves no completion.
Never log authorization forms, keys, credentials, raw journal records or signing identities.

## Focused experiment cuts after the maintenance prerequisites

Every changed production/experiment/runner line counts, including helpers and deletions. Tests and prose are additional.
Keep each complete PR at or below 200 lines, measure before tests and replan if necessary. Merge each ready cut before the next.

| Cut | Responsibility | Estimate | Required proof |
| --- | --- | ---: | --- |
| E01 | Private installed experiment request/authentication integration using the approved caller owners | 90–180 | Real peer/rights, distinct protected target, decline/expiry; no dispatch until the complete adapter qualifies |
| E02 | One P04 dispatch under the actual maintenance loan, with a bounded busy control and final readback | 100–190 | Fixed Setup/native guards, stop/exit ownership, one body, exact pair and separate restoration result |
| E03 | Internal timing recorder and narrow native inspection/storage events | 100–190 | Complete intervals/counts without payloads, injected verification or extra callback queries |
| E04 | Bounded coordinator, evidence validation and exact attended procedure | 110–195 | Real terminal/cleanup/recovery, sanitized source-bound command receipts and explicit incomplete results |

These E01/E02 replace the retired busy-discovery cuts; their responsibilities differ from the original plan.
Share maintenance/caller integration rather than adding a second service, resolver, drain or rights owner.
All required builds/tests use exact-source ATC plans, the native coordination lock and Toni's assigned slot.
Keep the existing 120-second command limit and 1800-second native allocation unless Toni explicitly replans them.
Source qualification runs no signing, installed service, GUI or Root operation.

## Preflight outside Seb's session

- Complete the required maintenance recovery/status/attended-exit cuts and E01–E04; retain source-bound qualification.
- Select the exact compatible signed artifact and verified installation path. No builds, signing, installation or provisioning wait for Seb.
- Verify protected machine compatibility and genuine retained state. Never reset initialized state, restore a database or regenerate keys to fit a test.
- Verify the exact Root Setup daemon, enabled autonomous recovery, fixed A-only cohort and current authority health.
- Prepare exact invocation/cleanup/status/restoration-only/repair procedures and unused evidence paths. Missing recovery is NO-GO.
- Complete the installed real administrator approve/decline/expiry gate before any policy write; fixtures cannot substitute.
- Confirm source, artifact and actual UI operation match. Record consent-age and outage bounds without inventing values.

These existing read-only commands inspect inputs; they do not run the live gates or prove enabled recovery:

```sh
cd /Users/rock3r/src/remozio-bepi
git status --porcelain=v1
git rev-parse HEAD 'HEAD^{tree}'
/usr/bin/sw_vers
/usr/bin/codesign --verify --strict '/Library/Application Support/Remozio/Applications/Remozio.app'
/usr/bin/codesign --verify --strict '/Library/Application Support/Remozio/Applications/Remozio.app/Contents/Library/LaunchServices/RemozioSetup'
/usr/bin/shasum -a 256 '/Library/Application Support/Remozio/Applications/Remozio.app/Contents/Library/LaunchServices/RemozioSetup'
```

Compare against the selected artifact, not this planning branch. Native custody checks remain mandatory.
There is no exact new live command today. E04 must supply and verify it before scheduling the action.

## Initial attended session after preflight

Target operator time is 28 minutes, with two minutes reserved for interruption. These are allowances, not measured durations or outage promises.
Do not start with incomplete readiness. Crash, reboot and repair exercises need their own prepared attended slots.

| Time | Operator and prepared owner | Evidence/stop rule |
| --- | --- | --- |
| 0–4 min | Confirm source/artifact, distinct A/B, outage bound, exact command and recovery exit | Any mismatch: `notRun`; no stop |
| 4–8 min | Run the single healthy-service control, then explicitly approve the maintenance window | Record control and actual rights; refusal/expiry causes no policy write |
| 8–17 min | Drain, stop exact A, prove exit, pin pair and run one native P04 action | Actual commit/refusal/unknown and all timing intervals; no body replay |
| 17–23 min | Observe protected readback and restoration/adoption of A | Separate operation outcome from readiness/floors/admission restoration |
| 23–28 min | Review outcomes and product answers; confirm no owned live work remains | Report failed acceptance/unfinished recovery explicitly; use the prepared attended exit |

Committed plus restart failure stays committed plus restart failure. Never present it as an operation failure that the operator should repeat.
Normal cleanup restores owned service availability; it does not erase product data, reset `writing`, undo policy or replay retained work.
If recovery is uncertain, expose the durable status and exact next attended step. Do not abandon an unavailable approver silently.

## Interpretation and product questions

The busy/acquire observation validates this selected artifact's real lock/lifecycle composition, not all future service states.
One successful native P04 call proves that invocation only. Timing does not establish tail latency or full A11 completion.
P05, full A11, interrupted recovery, installed activation, provider semantics and physical hardware remain separate gates.
Installed approve/decline/expiry comes first; the provider and later lock/logout/restart/CRD/screen-sharing handoff remains separately required.

1. May valid retained setup consent remain usable indefinitely, or should C01 enforce an explicit age limit?
   Current planning assumes no age-based expiry. Do not invent a limit or refresh consent automatically.
2. What maximum approver outage and end-to-end delay is acceptable for this explicit maintenance action?
   Include stop, all native work and cleanup, restart/readiness and admission restoration. No existing fixture sets that product bound.

Record the answers for Toni's implementation decisions. A timing limit never authorizes unsafe forced cleanup.
The full Remozio objective remains incomplete.
