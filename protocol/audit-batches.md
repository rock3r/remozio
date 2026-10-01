# Audit batch contract, version 1

An audit batch describes one contiguous page from one Mac/account journal epoch. It cannot authorize an action or change trust.

The codec preserves the original canonical record bytes. Parsing proves structure only. The signature verifier proves a signature under the caller's selected key.

## Signing domain

Use P-256, SHA-256 once, a 65-byte uncompressed public point, and a 64-byte raw R||S signature. Both valid S forms are accepted, as for approval signatures.

Sign the deterministic CBOR map below. The payload is the original canonical batch map, embedded as bytes, without normalization.

| Key | Value |
| --- | --- |
| 0 | Text `dev.remozio.audit` |
| 1 | Audit wire version `1` |
| 2 | Message type `1`: batch |
| 3 | Purpose `1`: history page |
| 4 | Canonical batch payload bytes |

`AuditBatchSigningInput` constructs this context. `AuditBatchSignature` verifies it. These APIs cannot select the approval domain. Unsupported versions fail. Future audit message types need their own defined context; no transition purpose exists yet.

## Payload

All keys are required. Unknown keys, tags and schema versions fail. Integers are unsigned 64-bit values.

| Key | Field | Contract |
| --- | --- | --- |
| 0 | Schema | `1` |
| 1 | Mac ID | 16 bytes |
| 2 | Account ID | 16 bytes |
| 3 | Journal epoch | 16 bytes |
| 4 | Epoch-creation generation | Immutable combined trust generation when the epoch began |
| 5 | Requested after | Exclusive sequence cursor from the page query; zero starts history |
| 6 | Retained after | Exclusive lower boundary of retained records; zero means no prefix was pruned |
| 7 | Head | Highest allocated sequence in this epoch; zero for a new empty epoch |
| 8 | Query nonce | 32 random bytes from the pending phone query |
| 9 | Records | Array of canonical [audit metadata](audit-metadata.md) byte strings |

The generation is descriptive history, not current trust. It may be zero. Revocations and policy updates must not rewrite this field in an existing epoch.

`pageAfter = max(requestedAfter, retainedAfter)`. Records must cover exactly `pageAfter + 1` through `pageAfter + count`, in ascending order. Every record must match the batch Mac, account and epoch. Event IDs must be unique within the page. The range must not exceed the head.

The next cursor is `pageAfter + count`. A page has more records when that cursor is below the head. Empty pages are valid only at the head. Both the requested cursor and retained boundary must be at or below the head.

The exclusive retained boundary supports a fully pruned epoch even at the maximum sequence value. A cursor below that boundary produces an explicit retention gap. This contract does not select a retention policy or permit pruning.

An ahead-of-head cursor fails this page contract. Unavailable epochs and conflicting cursors need a separate authenticated reconciliation response. They must never select records from another epoch. This PR does not implement that response or epoch transitions.

## Receiver obligations

Before accepting a page, select the authority key from current trusted enrollment. Verify the signature and decode the payload under explicit byte, depth, item and record-count limits. Check the expected Mac/account, epoch, query nonce and requested cursor against the pending query.

Consume each pending query once. A valid signature alone does not establish freshness. An unsolicited or replayed page must not advance the displayed last-sync time.

Compare the immutable generation and records against retained evidence. Preserve conflicts and cached old epochs for read-only reconciliation. A valid page cannot overwrite conflicting history or establish a new authority key.

The channel must authenticate the phone and reject revoked enrollment before serving history. None of these codec APIs performs channel authorization, cursor tracking, cache updates or trust migration.

## Bounds and evidence

Callers supply separate limits for the batch and each record, plus a positive maximum record count. Limits do not define product retention settings. The codec rejects sequence overflow, malformed embedded records and trailing bytes. Kotlin values own their mutable inputs and expose immutable record lists.

Eight shared fixtures cover complete and partial pages, empty histories, retention gaps, full pruning, and maximum sequence values. Thirty-nine negative fixtures cover malformed fields, mixed identities, holes, duplicate IDs and invalid boundaries. Swift and Kotlin verify the same synthetic signatures. Tests alter signed fields and reject cross-domain signatures.

This is a protocol foundation. It does not provide durable storage, encrypted caching, history UI, epoch reconciliation or proof against journal rollback. Device-dependent tests remain pending.
