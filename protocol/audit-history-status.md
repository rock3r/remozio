# Audit history status, version 1

This read-only response authenticates the current journal epoch and answers discovery or old-cursor queries. It does not change trust, rewrite history or authorize actions.

## Signing context

Use the same P-256/SHA-256 representation as audit batches. The deterministic signing map has domain `dev.remozio.audit` at key 0, version `1` at key 1, type `2` at key 2, purpose `2` at key 3, and the original canonical status bytes at key 4.

Type 2 and purpose 2 mean history status. `AuditHistoryStatusSigningInput` and `AuditHistoryStatusSignature` fix that context. Batch signatures and approval signatures cannot substitute for it. Versions other than 1 fail.

Select the key from current trusted enrollment. Authority migration or recovery must finish before accepting a different key. A descriptor never supplies a verification key or lowers a security floor.

## Immutable epoch descriptor

The status embeds canonical descriptor bytes. The enclosing status signature authenticates them; a decoded descriptor alone is not authenticated. All keys are required. IDs are opaque 16-byte values. Unknown keys, causes and versions fail.

| Key | Field | Value |
| --- | --- | --- |
| 0 | Schema | Unsigned `1` |
| 1 | Mac ID | 16 bytes |
| 2 | Account ID | 16 bytes |
| 3 | Epoch | 16 bytes |
| 4 | Creation generation | Unsigned combined trust generation when the epoch began |
| 5 | Cause | Initial 0, restart 1, replacement 2, recovery 3, confirmed restoration 4, unknown 5 |
| 6 | Previous epoch | 16 bytes or null |
| 7 | Previous sequence | Unsigned known prior boundary or null |
| 8 | Previous event digest | SHA-256 of the canonical metadata record at that boundary, or null |

The previous epoch and sequence appear together. A positive previous sequence requires a 32-byte digest. A known empty prior epoch uses sequence zero and a null digest. An unknown prior boundary uses null for all three fields. The previous epoch cannot equal this epoch. Initial creation cannot claim a prior boundary.

Compute the digest over the exact canonical [audit metadata](audit-metadata.md) bytes. Check that record's Mac/account, epoch and sequence before creating or verifying the link. The codec checks shape, not the existence or truth of the prior record.

The descriptor remains immutable across batches and ordinary trust updates. Creation generation is descriptive history, not current authority. The cache must reject descriptor conflicts for the same scoped epoch.

A known prior boundary does not prove that no later records existed. Missing prior evidence never establishes a continuous chain. Normal restart alone is not evidence of rollback. Only a confirmed restoration permits that cause; use unknown when the cause is unavailable.

## Status payload

All keys are required, including null fields. Integers are unsigned 64-bit values.

| Key | Field | Value |
| --- | --- | --- |
| 0 | Schema | `1` |
| 1 | Mac ID | 16 bytes |
| 2 | Account ID | 16 bytes |
| 3 | Query nonce | 32 bytes from the phone's pending query |
| 4 | Requested epoch | 16 bytes or null for discovery |
| 5 | Requested after | Exclusive sequence cursor or null for discovery |
| 6 | Disposition | Discovery 0, available 1, unavailable 2, cursor ahead 3 |
| 7 | Current descriptor | Canonical descriptor bytes |
| 8 | Current retained after | Exclusive retained boundary |
| 9 | Current head | Highest allocated sequence; zero for an empty epoch |
| 10 | Queried descriptor | Canonical descriptor bytes or null |
| 11 | Queried retained after | Exclusive retained boundary or null |
| 12 | Queried head | Highest allocated sequence or null |

Each descriptor must match the outer Mac/account. Every retained boundary must be at or below its corresponding head. Read all status fields from one consistent authority snapshot.

- Discovery requires null requested epoch/cursor and null queried fields.
- Available requires the queried descriptor to match the requested epoch and the cursor to be at or below its head.
- Unavailable requires an explicit requested epoch/cursor, null queried fields, and a requested epoch different from the current epoch.
- Cursor ahead requires the queried descriptor to match the requested epoch and the cursor to exceed its head.

Queried descriptor, boundary and head are either all present or all absent. When queried and current epochs match, descriptor bytes and both boundaries must match exactly. A status cannot describe two versions of the same epoch.

A cursor below retention is still available; show the missing prefix explicitly when fetching from the retained boundary. A cursor beyond the head requires read-only reconciliation. Neither state permits substituting another epoch's records under the old cursor.

## Phone integration and evidence

`AuditPageReceiver.beginHistory` creates bounded one-use queries. `receiveHistory` verifies the signature, schema, expected enrollment scope, nonce, requested epoch and cursor. It rechecks elapsed time after validation. Both history and page queries share capacity and invalidation rules.

Preserve the returned signed evidence. Compare descriptors, prior record digests, overlapping records and boundaries against the cache before advancing history state. Retain conflicts as possible loss evidence. A valid response cannot overwrite old records or prove that missing intermediate epochs never existed.

The response reports authenticated observations, not timeless current state. The channel must enforce enrollment authorization, including revoked-phone rejection. Encrypted caching, durable reconciliation, server integration and history UI remain pending.

Fifteen shared fixtures cover every cause, empty or missing prior boundaries, discovery, old/current epochs, unavailable history, cursor conflicts and full pruning. Sixty-one negative fixtures reject malformed or inconsistent states. Swift and Kotlin verify the same signatures and reject cross-domain substitutions. Phone tests exercise query binding, shared limits and handoff to an explicitly selected page epoch. Real-device E2E remains deferred.
