# Keep the proof-link receipt fixture open until the send finishes

[Issue #1009](https://github.com/rock3r/remozio/issues/1009). Source reviewed on main at `9ca2f1817e8e46ff346cfb60c526a88ca5de655c`.

## Failure and timing

The Mac core job for #983 reported `served == 0` instead of 1 after 3.581 seconds. The job log confirms the assertion. The source explains an ordering that can produce it. The CI log contains no handler error, so the exact order remains unconfirmed. [Failed CI job](https://github.com/rock3r/remozio/actions/runs/45684785320/job/139454486073)

- The handler increments `served` after `sendReceipt` returns. The client verifies the receipt and immediately closes its channel. The test calls `listener.closeAndWait` after the client returns. [Proof-link test](https://github.com/rock3r/remozio/blob/9ca2f1817e8e46ff346cfb60c526a88ca5de655c/macos/core/Tests/RemozioCoreTests/AuthorityPairingProofLinkTests.swift#L513-L569), [Client fixture](https://github.com/rock3r/remozio/blob/9ca2f1817e8e46ff346cfb60c526a88ca5de655c/macos/core/Tests/RemozioCoreTests/AndroidPairingMacLoopbackTests.swift#L211-L219)
- The server checks that the session is active after the awaited write. Client EOF can close the session during that await. Listener teardown can also cancel the handler before the check runs. `closeAndWait` cancels before it joins. A verified client receipt and a failed server send can therefore occur in the same fixture run. [Receipt and reader](https://github.com/rock3r/remozio/blob/9ca2f1817e8e46ff346cfb60c526a88ca5de655c/macos/core/Sources/RemozioCore/PairingSetupNetworkSession.swift#L169-L205), [Post-write check](https://github.com/rock3r/remozio/blob/9ca2f1817e8e46ff346cfb60c526a88ca5de655c/macos/core/Sources/RemozioCore/PairingSetupNetworkSession.swift#L216-L231), [Listener shutdown](https://github.com/rock3r/remozio/blob/9ca2f1817e8e46ff346cfb60c526a88ca5de655c/macos/core/Sources/RemozioCore/PairingSetupListener.swift#L206-L215)

## Test change

Add an optional hook to the native phone fixture. Call it after the phone checks the receipt ID, digest and signature and before it closes the connection. In the dedicated-link fixture, that hook waits for the result of the server's send with a bounded XCTest wait. Report a handler error or an absent completion at that point.

Keep the successful send count after `sendReceipt` and preserve the count of one. Use the hook in each caller of `pairUsingDedicatedLink`, including the winning peer in the 16-peer case. Preserve the rejection at the registration limit, proof and receipt checks, joined listener teardown and Authority retirement check. The production listener, XPC link and session stay outside the diff.

## Proposed validation

Use one native ATC slot. Build the Core test bundle and record exact discovery for both affected test classes. Run both complete classes once. Then run 200 serial repetitions of the failing method with fresh fixture state per invocation. Require a passing case for every invocation with zero skips, failures or timeouts. Retain the repetition count and timing distribution. Propose the exact selection, forecast and cap after patch review.
