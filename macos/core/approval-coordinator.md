# Approval request owner

`ApprovalRequestCoordinator` owns the live request states for one Mac/account. Signed phone decisions select an owned request by ID; they cannot supply its retained payload, phase, deadline, or trust snapshot.

```mermaid
sequenceDiagram
    participant Adapter as Trusted capture adapter
    participant Owner as Request coordinator
    participant Journal as Protected journal
    participant Phone as Authenticated phone channel
    Adapter->>Owner: Validated draft and original observation times
    Owner->>Owner: Fresh random request ID and challenge
    Owner->>Journal: Commit creation metadata
    Journal-->>Owner: Commit succeeds
    Owner-->>Adapter: Issued payload
    Phone->>Owner: Signed decision and authenticated enrollment epoch
    Owner->>Owner: Load current owned request and check deadline
    Owner->>Journal: Recheck stored enrollment, consume, and append audit event
    Journal-->>Owner: Committed winner
    Owner->>Owner: Advance live phase
    Owner-->>Phone: Historical receipt, not a dispatch permit
    Note over Owner: Checkpoint, target checks, and execution gate remain separate
```

## Service contract

The coordinator is deliberately non-Sendable. The root service must isolate it and its journal on one executor. Serialize admission, adapter observations, enrollment changes, routing, consumption, and outcome recording there. Do not consume or transition its requests through a second journal caller.

Construct it only after protected writer ownership, authority continuity, startup recovery, and admission storage reserves are established. It does not establish those gates. Its memory limits and the ledger count limit do not reserve physical disk space or guarantee a complete lifecycle budget.

A draft is trusted, validated adapter output, not a decoded remote submission. The adapter checks capture semantics and target identity. The owner uses the journal's Mac/account identity, generates random IDs and challenges, and preserves the draft's original observation times. The caller supplies time from the configured sleep-inclusive authority clock, never from phone messages.

Before consuming a phone decision, the service rechecks the target under the same serialization boundary. A known timeout or disappearance must retire the request first. The channel supplies its authenticated phone identity and enrollment epoch independently of the decision bytes. The owner checks that identity and epoch against current durable enrollment in the consumption transaction.

Invalid signatures, unknown requests, and wrong channels do not allocate audit events. Rejection aggregation and its rate limits remain separate work. Creation, pending retirement, consumption, and post-consumption outcomes use the existing journal.

## State and capture lifetime

Admission publishes the payload only after creation metadata commits. It does not publish a provisional in-memory entry on a write failure. Consumption and outcomes update memory only after their journal transaction succeeds. A failed retirement keeps the prior state and reports an error; it cannot claim a result that was not recorded.

`pendingRequest` returns only a current queued or presented request. It checks the storage lease and expires an elapsed authorization deadline before returning. `markPresented` is idempotent. Dismissing a phone sheet does not call retirement or change the request.

`consumedRequest` retains the original binding while the phase is Authorized or Executing. It is data for the executor's separate target and checkpoint checks, never permission to dispatch. Expiry cannot rewrite an already consumed action. Terminal transitions release the coordinator's capture reference. The host must also release any copies held by adapters or transport queues.

`state` returns local observed metadata. It is not a signed status message or a freshness guarantee. The host drives deadline evaluation even without phone traffic, reconciles terminal state to all devices, and withdraws queued work. When using `PendingRequestDelivery`, obtain a fresh owned snapshot before its dispatch boundary; never reuse a pre-consumption snapshot.

The configured request count includes terminal metadata until `forgetTerminal` removes it. The capture byte limit includes Authorized and Executing requests until their terminal outcome. Forgetting cannot remove a live request or its durable consumption receipt. New admission always creates a new ID and challenge.

## Unknown, expiry, and restart

Pending retirement uses distinct reasons:

| Observation | Result |
| --- | --- |
| Local request cancellation | Cancelled; no target action |
| Authorization deadline has elapsed | Expired; the owner verifies the deadline |
| Adapter establishes an actual target timeout | Expired with target-timeout metadata |
| Target disappears without an established result | Unknown with target-disappearance metadata |
| Authority restarts before consumption | Cancelled; fresh submission or recapture required |

A 1Password expiry estimate alone is not an observed timeout. The shared `loseTarget` transition permits Unknown only for queued or presented requests. Consumed actions use the existing outcome transitions. Unknown stays terminal, even if late evidence arrives.

Clock regression or an epoch change retires the live coordinator and drops its captures. The host closes delivery and performs the normal recovery path. Storage closure blocks live snapshots. Errors are not authenticated no-admission responses and must never trigger automatic action replay.

A new coordinator starts empty. Journal history and old consumption receipts cannot reconstruct a live request or execution binding. `historicalOutcome` supplies retained winner evidence for Already handled responses. Startup recovery must still classify unresolved historical actions; this component does not retry them or invent outcomes.

## Evidence and remaining gates

Thirteen normal-user tests use the real protected journal and disposable P-256 keys. They cover fresh bindings, metadata privacy, presentation, first-decision ownership, current enrollment, decline, deadline enforcement, target loss, journal failures, outcome retention, memory limits, and restart.

Swift and Kotlin test every lifecycle state/event pair against the same fixture, including pending target loss. No action is executed and no real credential, provider, or phone is used.

Protected service hosting, authenticated transport, actual adapter validation, checkpoint and witness recovery, lifecycle storage reservations, deadline scheduling, and physical-device checks remain required before production admission or dispatch.
