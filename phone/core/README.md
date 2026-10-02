# Phone request core

This Kotlin/JVM module owns authenticated command sessions and signed status tracking. The Android app uses these classes directly. They contain no Android platform APIs, network client, approval controls, or private signing keys. The audit core owns encrypted storage through caller-supplied adapters.

A session verifies a command against caller-supplied trusted enrollment identity. It retains the typed capture until a verified terminal status clears it. The status tracker preserves request bindings, revision ordering, outcome continuity, and elapsed-time bounds. The caller still owns enrollment invalidation and clock sampling.

Run `:phone-core:test` for the portable unit tests. They reuse the invented command fixture from the Android debug source set. The fixture is a declared test input, not a runtime dependency or production resource.

## Swift/Kotlin flow checks

On a Mac, run `python3 scripts/build-approval-flow.py` and then `:phone-core:approvalFlowTest`. The latter is a separate Gradle test task. It starts the compiled synthetic Swift peer and exchanges canonical signed payloads over child-process pipes. Missing native build output fails the task; it does not silently skip integration checks.

The [approval-flow experiment](../../docs/experiments/approval-flow.md) describes its trust setup, tested cases, and limits. The [audit-flow experiment](../../docs/experiments/audit-flow.md) also exercises signed history sync and encrypted cache reload. The portable test task excludes both integration classes, so Linux can run the shared state tests without Mac peers.

## Enrollment ownership

`CommandRequestInbox` accepts trusted enrollment identities and pinned authority keys from local setup. Each enrollment incarnation owns a bounded in-memory request window. Delivery uses that existing handle; request data cannot install trust. Replacing a trusted key explicitly closes the old incarnation and its sessions. Removing one Mac/account does not affect another.

Request keys contain Mac, account, and request IDs. Every delivery authenticates before lookup. Exact duplicate bodies return the existing session, preserving timing and terminal state. Conflicting signed bodies under the same request identity fail. A refreshed authorization uses a new request ID and challenge while preserving target observation and age through the existing status contract.

Closed sessions clear their capture, expose a local closed signal, and reject later status input. This is not a fabricated signed expiry or action outcome. Android removes the inspection and dismisses it when that signal arrives. Already copied snapshots cannot be erased by closing the owner.

Limits are explicit caller-supplied window bounds, not selected product defaults. Terminal handles remain as tombstones during the window. Capacity fails explicitly; it never silently evicts a visible request or forgets a terminal result. Durable history, authenticated reconnect-window rotation, enrollment persistence, and product retention settings remain to be implemented. This layer provides neither freshness nor durable replay protection and exposes no approval control.

The [wake router](PUSH.md) coalesces opaque hints per trusted enrollment and tracks bounded fetch demand.
