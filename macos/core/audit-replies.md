# Native audit replies

`AuditReplyBuilder` creates signed page and history-status replies for one fixed Mac/account. The service supplies that scope and the authority public key from local trusted state. Request data cannot select a different account or signing domain.

```mermaid
flowchart LR
    A[Authorize enrolled phone and account] --> R[Read bounded journal data in one transaction]
    R --> V[Validate scope, continuity and resource bounds]
    V --> S[Sign fixed audit context]
    S --> C[Verify signer output against authority public key]
    C --> D[Return canonical reply]
```

The caller performs the first two steps. This builder has no channel, enrollment database, journal reader or authority-recovery policy. A signature cannot replace those checks.

## Read and build

Obtain all `AuditEpochRead` values and canonical records for a reply from one coherent journal transaction. A read contains the immutable epoch descriptor, retained boundary and head. These are descriptive history fields; they do not establish current authority or policy.

A page request binds its nonce, epoch, creation generation and exclusive cursor. Supply only one bounded page, beginning after the greater of the requested cursor and retained boundary. The builder checks contiguous sequence numbers, scope, event IDs and canonical metadata through the shared protocol codec. Empty pages are valid only at the head. An ahead cursor requires reconciliation instead of a fabricated page.

For history discovery, omit the requested epoch and cursor. For a known old epoch, provide its read. An absent old read produces `unavailable`; it does not reuse current-epoch records. The builder derives `available` or `cursorAhead` from the queried head. Requests for the current epoch use the current read. A separately supplied current read must match its descriptor and boundaries exactly.

Supply independent limits for page, record, history, descriptor and signing input, plus a positive record count. Oversized or malformed input fails before the signer is called. The reader must enforce these bounds before loading data; the builder cannot undo allocation by its caller. Count and total record bytes are checked before encoding a page.

## Sign and return

The injected signer receives the fixed audit-domain signing input. It signs with P-256 and SHA-256 once and returns raw 64-byte R||S. Production must use the established non-exportable authority key. Tests use disposable software keys.

The builder verifies the returned signature under the expected authority public key before returning `SignedAuditReply`. Wrong keys, DER signatures, malformed signatures and accidental double hashing fail. Page and history-status purposes remain separate from each other and from approval signatures.

Nine native tests cover scope confusion, inconsistent reads, record gaps, duplicate IDs, retention, maximum sequence values, resource bounds and signer errors. They also reproduce every shared valid page and history payload and its signing input exactly. The fixtures are independently consumed by the Kotlin protocol tests.

A production journal reader, authenticated transport, revocation checks and device integration remain pending. This component neither writes the consumption ledger nor certifies its crash or rollback behavior.
