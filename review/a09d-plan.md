# A09d completion and recovery cuts

Source: 824673d001c2749b86a4d76912e6f22ae08ff922
Tree: dd9d32cf37e864429d976b2587550e61700943b8
Lead: Toni messages 2261 and 2264.

This proposal applies no source and runs no build or test. Toni currently owns native validation.
The prior A09c2 local build and 29 cases passed. Its wider validation and publication remain Toni's responsibility.

## Current source constraints

C1 accepts only unpublished metadata. Its scope also pins the original snapshot.
It cannot verify a published recovery frame or the writer's changed bit without refusing or querying the active machine transaction.
RuntimeConfigurationBundle.retainedSetupInitial and its private stableInitial helper also require the unpublished bit.
RuntimeRetainedSetupPublishedSelection reads all eight files, but stableCompleted preserves actual tunables instead of deriving them from the durable import selection.
Therefore that value alone cannot prove that every actual byte matches the recorded initial selection.
MachineUpdateRetainedSetupRuntimeInputs already reads actual journal presence, intent and relay evidence.
Open its actual journal and relay directory before the machine transaction. Keep their scope through the owned operation.
PreparationIntentStore.completeRetainedSetupRuntimePublication already lends actual beforeTransaction, inTransaction, afterMutation and afterCommit snapshots.
Its exact published recovery path lends beforeTransaction only and makes no UPDATE.
Do not call public machine snapshot or import-opening wrappers from those callbacks.
The existing RuntimeRetainedSetupCompletionPublication handles later six-file replacement. It does not own these initial eight files.
The private donor completion uses the ordinary writer and unavailable native helpers. It is not a safe implementation to copy.

## Proposed order

Each cut has a complete responsibility and a 200-line production cap, including helper changes and deletions.
Measure the complete production diff before adding tests. Retain each original history and receipt.
Do not apply the next cut before Toni's preceding merge and reconciliation direction.

### A09d1: exact initial-publication observation

Create a read-only observation for both actual publication-bit states.
Derive the deterministic eight-file selection from the actual recorded pair, actual import journal and actual relay evidence.
Use a narrow retained-only value constructor for publication observation. Preserve every ordinary initial and completed guard.
Do not fake an unpublished snapshot, change the actual row, or accept caller-supplied absence or free tunable overrides.
Keep material bytes, service activity, admission, recorded pair and the exact source fixed around each artifact read.
Keep actual input observations fixed across the invocation. A published import acknowledgement must not silently change the selected evidence.
Use the caller's checked actual frame, including a synchronous writer-borrowed frame, without another public machine query.
Keep callback loans limited to process, thread, lifetime, admission and re-entry checks. Avoid recursive full verification.
Validate all eight actual artifacts against derived bytes. Missing or conflicting files refuse; no file operation can create or replace data.
Return an observation result only. It grants no write, native custody, startup, job or ready-state authority.

Expected paths: a new initial-publication observation file, RuntimeConfigurationBundle.swift, and a narrow retained value helper if needed.
Estimate: 150–195 changed production lines. No SQL or native facade.
Tests: both bits with exact eight files; missing or changed files; actual import/relay changes; wrong pair/material/source;
loan expiry, recursion and foreign thread; borrowed writer-frame use with public machine queries forbidden; bounded query counts.
Preserve ordinary initial-published refusal and existing ordinary completed behavior.

### A09d2: owned completion and recovery

Use A09d1 before the writer, around every actual writer callback, and after the final actual machine read.
Invoke only completeRetainedSetupRuntimePublication with the exact reference and recorded intent.
For complete=0 with exact files, perform exactly one UPDATE and zero file writes.
For fresh complete=1 with exact files and pair, observe recovery with zero UPDATEs and zero file writes.
Compare unpublished frames exactly and accept only the typed A09a false-to-true transition. Pin every other source operand.
Never query the public machine reader from a writer callback. Expire each borrowed frame when its callback returns or throws.
An error ends the invocation. A later attempt reopens and resolves actual state. Do not reuse an advanced frame after rollback.
An uncertain commit retains the existing writer shutdown. A fresh published read still verifies material, pair and all eight files.
Do not publish missing files during completion. A fresh publication operation remains a separate responsibility.

Expected path: new MachineUpdateRetainedSetupInitialCompletion.swift, plus the two review nits if the full diff fits.
Estimate: 145–190 lines, plus the nits and any required call-site changes.
Tests: one update without writes; already-published no-op; failures at each writer stage; rollback then fresh invocation;
lost commit acknowledgement then fresh recovery; exact pair/material/files checks; expired and re-entered borrowed scopes.
Retain ordinary writer refusal, all protected-row/catalog checks and exact per-case outcomes.

## Review nits from 2263 and 2264

Remove relayPlan's default from RuntimeRetainedSetupInitialConfiguration.init and requireSourceForPublication.
Count both declarations and every required production call-site change in the chosen cut.
Add final global and Services directory validation in publishRetainedInitialNative, matching the ordinary publisher.
These changes go in A09d2 only if its full production diff stays within 200 lines.
Otherwise send the measured excess to Toni for a separate follow-up. Do not drop a guard to fit.

## Boundaries

A11 still owns native custody, authenticated callers and provider closure. A09d adds none.
No Root, installed placement, real services, physical devices, signing identities or provider validation runs here.
Bepi runs only the assigned local gate after Toni releases native ownership. Toni owns wider validation, publication and merge.
The full Remozio objective remains incomplete.
