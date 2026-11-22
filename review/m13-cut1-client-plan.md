# M13 cut 1: Mac status and recovery client

Review proposal for main `dc1a9cb65e4b13706074c63f59f06a40cd1b5a77`, after #824. The approved design has SHA-256 `e40640283d3b51be78ef1af24c8cb7ed2eb2111ed954f7ac208aadc9cbe82481`. This review diff proposes the client and deterministic tests. The source diff and its gate admission follow the decision below.

## Decision before the source diff

The exported status reply provides captured facts but no action applicability. `SetupRetainedStatusWire.reply` encodes the reservation, identity, optional row, and worker, cleanup and supervisor observations. `SetupRetainedInvocationReservation.recoveryApplicability` determines whether completion can be adopted or a window-free reservation released only after a protected claim joins. The status reply omits those joined facts. A null row can mean unavailable capture. It cannot prove a window-free reservation. An observed orphan with a row cannot prove there is no unsettled completion.

Use the existing typed recovery transport and deterministic presentation model in cut 1. Keep real action controls unavailable until an approved producer supplies the missing evidence. In particular, keep the nil-identity release request out of the client controller. In the endpoint it selects the current uncaptured target, so an earlier status observation cannot bind that command to an exact reservation. Do not send Restore to probe applicability or use its refusal to choose adoption. Ask Toni to confirm this boundary or specify the producer amendment before the Swift diff. Cut 2 owns the panel. Android and iOS remain outside this cut.

## Proposed source diff

| Path under `macos/core` | Change |
| --- | --- |
| `Sources/RemozioCore/SetupRetainedStatusWire.swift` | Add a bounded v1 reply decoder beside the encoder. Match the status request ID, exact keys, version and canonical bytes. Decode only redacted facts. Represent null and explicit absence separately. The result has no protected scope or authorization capability. |
| `Sources/RemozioCore/MacSetupRecoveryChannel.swift` | Add typed status and mutation clients on separate connections. Use the existing XPC peer policy and bounded request/reply machinery as in `AuditUpgradeSetupChannel`. Apply the existing installed release verification and `SetupOrphanRecoveryWire.requireFormats` to the recovery connection. Reject a refused hello and any version other than 13. Keep authorization within the current invocation and verify the same Root peer before obtaining a form, before sending and on each reply. |
| `Sources/RemozioCore/MacSetupRecoveryControls.swift` | Add controller state for redacted observations, one explicit attempt, request progress and separate health. Keep a request and its original recovery connection together. A generation token rejects late refresh callbacks and stale selections. Reserve the attempt before awaiting rights. Each new attempt requires fresh target evidence and fresh rights. |
| `Tests/RemozioCoreTests/SetupRetainedStatusV1GoldenTests.swift` | Add decoder compatibility coverage against the existing golden bytes. |
| `Tests/RemozioCoreTests/MacSetupRecoveryChannelTests.swift` | Exercise connection routing, reply validation and bounded failure with deterministic drivers. |
| `Tests/RemozioCoreTests/MacSetupRecoveryControlsTests.swift` | Exercise action availability, request ownership and readback across interruptions and refreshes. |

The status client calls `retainedInvocationStatus` as its first call. It cannot negotiate normal Setup or recovery on that connection. The recovery client calls only `recoveryHello`, `startRecovery` and `recoveryProgress`. The facade routes those calls to the recovery lane, with a new hello returning zero when unavailable. Status v2 is library-only at this base.

Reserve and encode one request before the send. The endpoint saves one canonical request per connection and replies `requestRecorded` before rights import. Treat `requestRecorded` as pending. A matching progress result can report recorded restoration or release. It cannot establish current service health. Start and progress validate the exact request ID and the allowed reply phase. Duplicate or late callbacks cannot complete a different operation.

After a lost start reply, read progress only if the original connection remains usable. A dropped connection does not have a persistent request lookup. Refresh public status using a separate status connection and retain an unconfirmed outcome. On relaunch, obtain fresh status before offering an action. Panel dismissal must leave the controller and existing connection alive. The endpoint can abandon its claim when the actual connection closes, so closure is not a cancellation or a completion receipt. Keep the server's 120-second deadline.

## Proposed test closure

The list below comes from test declarations and main's weights at `dc1a9cb6`. It is the proposed local selection. Compiled discovery and the actual diff must confirm it before the gate. The first eight entries are the fixed CI smoke closure. The remaining entries exercise the status, recovery and existing client patterns used by the cut. Include the full changed golden test class and all tests in both new classes.

| Existing class | Methods |
| --- | ---: |
| ApprovalRelayCoordinatorTests | 6 |
| AuthorityJournalTests | 12 |
| AuthorityPairingSetupTests | 44 |
| AuthorityServiceRunnerTests | 14 |
| CheckpointedJournalTests | 67 |
| CommandStreamSourceTests | 5 |
| DirectApprovalRequestDeliveryTests | 62 |
| GatewayDatabaseTests | 89 |
| AdministrativeSetupChannelTests | 12 |
| AdministrativeSetupStatusLaneTests | 35 |
| AuditUpgradeSetupChannelTests | 15 |
| MacAuditUpgradeControlsTests | 20 |
| SetupOrphanRecoveryAnonymousXPCTests | 3 |
| SetupOrphanRecoveryEndpointTests | 12 |
| SetupOrphanRecoveryWireTests | 10 |
| SetupRecoverySessionShutdownTests | 10 |
| SetupRetainedInvocationStatusTests | 27 |
| SetupRetainedStatusV1GoldenTests | 1 |
| SetupRetainedStatusV2WireTests | 5 |
| SignedReleaseInspectionTests | 10 |
| **Total** | **459** |

Reserve 24 proposed new methods. The v1 decoder needs five cases for golden round trip, null versus absent, wrong request ID, unsupported version, and invalid or oversized shape. The channel needs nine cases for separate selectors, manifest mismatch, refused hello, old version, peer change before export, peer change before dispatch, mismatched reply, stale callback, and interrupted progress. The controller needs ten cases for refresh with no rights request, changing target, changing incarnation, unavailable eligibility, duplicate clicks, recorded versus terminal progress, loss before acknowledgement, connection loss after acknowledgement, close/relaunch readback, and completion versus independent health. Replace these provisional numbers with the actual test names after review.

## Forecast for review

The existing class weights sum to 269.600 seconds. Applying the 1.3 factor gives 350.480 seconds. Reserve 60 seconds for each of the 24 proposed new methods, or 1,440 seconds. Allow 1,200 seconds for ten groups, 600 for compile/discovery, 735 for Debug and Release builds and inspections, 300 for Python and evidence audit, and 600 for a conditional baseline comparison. The sum is 5,225.480 seconds with no concurrency discount. A proposed cap of 6,500 seconds gives 1,274.520 seconds of margin. This is a planning estimate. Inspect heavy method weights, assign exact groups, and recalculate after the Swift diff. Capture separate evidence for any native or attended checks.

Use ATC with the existing native lock and build cache after admission. Compile with the CI optimization and discover the full inventory. Run the selected tests with the existing method, class and command guards, then verify the app builds and inspect their arm64 executables. Unit tests can verify client policy and states. They cannot qualify the installed Root path, service health, signing or the panel.
