# Audit page receipt

`AuditPageReceiver` owns bounded, one-use history queries for one enrolled Mac/account. Construct it with trusted enrollment identities and the authority public key. The enrollment owner must close it when enrollment is revoked or the authority key changes.

Begin a query with an authenticated journal epoch, its immutable creation generation, and the exclusive sequence cursor. These values must come from trusted history state. Do not derive them from the page being checked. Epoch-header authentication and migration remain separate work.

The receiver generates a fresh 32-byte nonce and retains each query by object identity. Use the query fields in the authenticated history request. The caller supplies a query lifetime and a maximum pending count; these are resource controls, not retention settings.

The elapsed clock must include sleep and use a new epoch whenever its origin changes. An expired query, a changed clock epoch, or observed clock regression invalidates the query permanently. Beginning another query releases expired slots. The receiver rechecks the clock after signature and schema validation.

Receipt checks the audit signature, batch schema, enrolled Mac/account, epoch, creation generation, cursor and query nonce. Failed signatures and bindings do not consume a live query. Successful receipt consumes it exactly once under the same lock. Cancellation and enrollment closure invalidate pending handles. Concurrent responses cannot both succeed.

`ReceivedAuditPage` retains immutable copies of the canonical bytes, signature and local receipt instant. It does not establish global freshness or update a cache. The cache must still compare overlapping records, generations and boundaries, preserve conflicting evidence, and reconcile epochs. A last-sync label must follow successful cache reconciliation, not signature verification alone.

The receiver does not authenticate a transport or grant history access on the Mac. Revoked-phone checks on the server, durable encrypted caching, epoch transitions, retention policy and the history UI remain pending. No history operation can authorize an approval.

Tests use disposable software keys and an injected elapsed clock. They cover altered bindings, wrong keys, domain substitution, replay, deadline boundaries, clock changes, validation delay, cancellation, closure, capacity, immutable evidence and concurrent receipt. No phone or live service is required.
