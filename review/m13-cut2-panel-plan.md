# M13 cut 2 — Show Setup recovery in the Mac app

This plan is based on main at `c07d678cc70936a4db054f5e718660e8798013fa`, the merge of PR #872. The merge tree matches the tree qualified on `c560bf9b`. Toni reviews the plan first and reviews the Swift diff, compiled test selection and revised forecast before the gate.

## Contract

- Add a **Setup recovery…** sheet next to **Audit history setup…** in the main window’s Setup section. Use the existing enabled Setup registration to expose the entry. Registration only controls access to the entry. The panel reads status through the verified, separate status connection.
- Present a short status and action reason. Distinguish an unread or failed status, no saved recovery work, an active or busy operation, unavailable applicability, and an explicit no-action result. An older verified release can display v1 facts. Only an authenticated v3 `.restore` result for a bound orphan with a captured window can offer **Restore…**. Adopt and Release stay out of the panel.
- Present a confirmation for the exact selection. Explain that Restore works on the saved setup and requires administrator approval. A refresh or a changed target invalidates the selection. Only a fresh confirmation can open the recovery connection and prompt. Preserve exact action and target checks in the endpoint.
- Keep **Refresh status** and **Check recovery progress** separate. The first reads redacted facts on a new status connection. The second reads the recorded attempt on its original connection. `requestRecorded` means pending. A progress result can confirm restoration of the saved setup. Service health stays unconfirmed in this panel.
- Close dismisses the sheet. The app owns the attempt and connection while the sheet is closed, so reopening can show the same attempt. A lost connection leaves the outcome unconfirmed. An explicit **Stop tracking** may release that connection after an uncertain outcome. Explain that it cannot cancel or undo the operation. Require a new status read and confirmation before another attempt. Relaunch starts with a fresh read and has no persisted attempt lookup.
- Keep the panel keyboard navigable. Use standard SwiftUI controls, a readable label for each state and progress, and a non-mutating default for confirmation. Keep identifiers, paths, authorization data and raw errors out of the view and its accessibility labels.

## Proposed source diff

| Area | Change |
| --- | --- |
| `macos/app/App/RemozioApp.swift` | Own one controller at app scope. Pass it into `SetupOverview` and present the sheet from the Setup section. |
| `macos/app/App/SetupRecoverySheet.swift`, `en.lproj/Localizable.strings`, `macos/app/Remozio.xcodeproj/project.pbxproj` | Add the sheet and localized copy. Render typed, redacted states. Confirm a selection already issued by the controller. Keep close, refresh and progress controls distinct. Register the source in the app target. |
| `macos/core/Sources/RemozioCore/MacSetupRecoveryControls.swift` | Expose a small typed presentation surface for the app. Keep the status wire type, request identity and recovery channel internal. Replace the production initializer’s disabled eligibility and authorization with the Restore-only policy and one native grant per explicit attempt. Reuse the existing operation and selection checks. |
| `macos/core/Sources/RemozioCore/SetupAdministratorAuthorization.swift` and the existing audit authorization path | Reuse `SetupAdministratorSession` and its executor pattern. Share only the grant wrapper if required to avoid duplicating its lifetime and concurrency rules. Verify the recovery hello and current peer before prompting. Prompt off the UI executor. Recheck selection after the prompt and keep the existing peer checks immediately before export and dispatch. |
| `macos/core/Tests/RemozioCoreTests/MacSetupRecoveryControlsTests.swift`, `MacSetupRecoveryChannelTests.swift` | Exercise the production policy and attempt wiring using injected status, peer and grant drivers. Test the grant lifetime and loss cases. |
| `macos/app/Package.swift`, `macos/app/Snapshots/Render.swift` | Add inert panel states to the existing synthetic renderer. Use fixture states and inert actions so rendering never contacts Setup or opens a prompt. |

The endpoint acknowledges recording before it imports rights. The grant must survive that acknowledgement. Keep one session with the original attempt until a terminal result, a proven pre-dispatch failure, or explicit tracking or connection teardown. Track uncertain sends as unconfirmed and never replay them. Destroy the grant at cleanup. Keep the external form inside the existing channel export closure. Do not log, persist, or expose it to SwiftUI.

## Outside this cut

No daemon, wire, selector, proof publication, signing policy, or endpoint changes. A v3 failure remains unavailable. A v1-only verified release can still read v1. No speculative downgrade, action probing, automatic restoration, Adopt, Release, Android or iOS changes.

**Issue #875 item 1 belongs in a focused owner follow-up.** `publishRetainedQuiescence` can mark a refresh while the task is active. At the fifth failed join, `stopRetainedQuiescence` clears that refresh. The current test delivers its next event after the task exits. Add a deterministic owner test that delivers the event while the fifth join is in flight and verifies that it triggers a new sampling pass. Keep retries stopped when there is no new event, and drop pending work on shutdown or reservation replacement. This affects when Restore becomes available. While evidence remains absent the panel explains that no action can be offered. The **Refresh status** button only reads status and cannot recover the lost event. Keep the other #875 follow-ups separate too. Retain the existing changed-row and claim invalidation tests as baseline coverage. The specific publication races in item 3 need their own tests.

## Proposed test closure

Start with the 713 Core cases and 18 built-app cases from #872. Include the complete changed test classes and preserve status-wire, first-orphan owner, authorization, endpoint, and CI smoke coverage. Reserve 16 deterministic methods for the following cases. Replace the reservation with compiled test names after the diff.

| Area | Proposed cases |
| --- | --- |
| Eligibility and presentation, 6 | First bound orphan offers Restore. V1 and unavailable applicability never offer an action. Explicit no-action renders separately. Incompatible or unreadable status cannot authorize. An unsupported action, missing window or non-orphan result stays disabled. Presentation carries no protected identifier or raw error. |
| Confirmation and rights, 5 | Refresh invalidates an open confirmation. A changed target or peer during the prompt prevents export and dispatch. Cancelling the prompt closes the grant. Duplicate actions open only one connection and prompt. Record acknowledgement leaves the grant alive and terminal progress closes it. |
| Lifetime and results, 5 | Sheet dismissal and reopening retain the original attempt. Refresh cannot replace progress or clear a pending attempt. Reply loss and connection loss never replay a start or use a new connection for progress. Stop tracking and relaunch require fresh status. A restored or uncertain outcome leaves health unconfirmed. |

Run the synthetic renderer for unavailable, no action, Restore available, pending, and unconfirmed states. Check the app target and localization resources in both Debug and Release. Run the built-app tests after the builds. Verify 18 arm64 artifacts and keep the manifest and CI selector checks. Attended validation remains separate and must cover the installed peer, the system prompt, a real first orphan, sheet close and reopen, and VoiceOver and keyboard navigation. A synthetic preview cannot validate the installed path.

## Forecast for review

The fresh #872 gate took 585.124 seconds end to end. Core took 265.877 seconds. Debug and Release took 53.739 and 216.785 seconds. Start with its conservative planning estimate of 3,524.839 seconds. Keep its allowances for optimized discovery, a conditional baseline comparison, runner overhead and app builds. Reserve 32 seconds for 16 deterministic cases and 180 seconds for the synthetic renderer. The provisional estimate is **3,736.839 seconds** with a proposed **4,200-second cap** and 463.161 seconds of margin. This assumes the app targets use the existing ATC profile and the three optimized arm64 shards. Recalculate from the actual diff and compiled inventory and obtain Toni’s approval before executing tests.
