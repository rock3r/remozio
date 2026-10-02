# Approval wake delivery

`GatewayDeliveryCoordinator` schedules opaque FCM wakes for root-owned `PhoneRequestDelivery` entries.
A wake tells a phone to fetch current requests. It carries no approval, command, credential, or request identifier.
Provider acceptance does not prove phone receipt, notification display, request fetch, or consent.

```mermaid
sequenceDiagram
    participant Root as Root request owner
    participant Gateway as Gateway coordinator
    participant OAuth
    participant FCM
    participant Phone
    Root->>Gateway: Current delivery identity and original deadline
    Root->>Gateway: Enable phone routing from presence state
    Root->>Gateway: Drain this phone and enrollment
    Gateway->>Gateway: Freeze queued members into one opaque batch
    Gateway->>OAuth: Obtain a current access token
    Gateway->>Gateway: Recheck trust, mapping, presence, deadline, and pacing
    Gateway->>FCM: Opaque wake with bounded TTL
    FCM-->>Gateway: Provider result
    FCM-->>Phone: Best-effort wake
    Phone->>Phone: Generic notification, then authenticated fetch
    Note over Root,Phone: Only the root's current request state can authorize an action
```

## Host contract

These methods are trusted local APIs. They are not authenticated wire endpoints.
The host must authenticate the root, retain the correct registration scope, and submit only current authorized deliveries.
A `PhoneRequestDelivery` value alone is not proof of authority.
The root and gateway use the same fresh monotonic clock epoch for these local deadlines.

The host supplies `GatewayWakePolicy` settings. Without that policy, wake scheduling is unavailable.
Routing starts locally until the host supplies its current presence decision through `setPhoneRouting`.
This startup state is not a product setting that disables push.
The host drains each enrollment with `deliverWakeBatch` and retries capacity or preparation failures.
It must cancel deliveries when their root request resolves, expires, or is withdrawn.

The queue is bounded and lives in memory. It does not restore pending requests from historical gateway receipts.
After restart, the root must resupply only requests that remain authorized and pending, with their original deadlines.
The durable root owner must preserve delivery identity and never reuse an identity for a different request.
A retained duplicate returns its current progress. Conflicting contents cannot extend a retained identity's deadline.
Expired entries become reclaimable when no flight references them.

## Coalescing and retries

One batch freezes all currently queued entries for a phone and enrollment epoch.
Entries retain separate identities, deadlines, and terminal states.
Arrivals after that point wait for the next batch. They cannot enlarge a retry's request set.
Every retry keeps the same opaque identifier and shared attempt budget.
A terminal accepted batch is not sent again by this coordinator.

Probe and wake tasks share the global flight limit and send spacing.
Wake batches also obey per-enrollment spacing, including across different batches.
Waiting for OAuth, a provider reply, or a retry retains a flight slot.
Settings bound queue size, attempts, request lifetime, and provider TTL.
These are process-local limits, not a provider-account quota across multiple Macs.

Network loss and retryable provider errors use bounded exponential backoff with jitter.
Provider delays remain lower bounds. A 401 refreshes the matching OAuth grant without renewing the batch budget.
Retries stop at the attempt limit or each entry's original deadline.
The sender uses high priority. The Android receiver must display the generic notification before fetching verified details.

Immediately before each provider handoff, the coordinator rechecks the current mapping and all live member deadlines.
TTL is the smaller of the configured cap and the shortest remaining lifetime, rounded down to seconds.
A subsecond remainder uses TTL zero for immediate delivery only.
Network delay and provider delivery remain outside this clock boundary.
The phone must fetch authoritative state and must not treat a late wake as a still-pending request.

## Presence, cancellation, and token changes

```mermaid
stateDiagram-v2
    [*] --> Queued: Authorized root delivery
    Queued --> Dispatching: Phone routing and current mapping
    Dispatching --> Accepted: Provider accepted
    Dispatching --> Queued: Retry or presence pause
    Queued --> Expired: Original deadline
    Dispatching --> Expired: Original deadline
    Queued --> Withdrawn: Root cancellation or trust change
    Dispatching --> Withdrawn: Root cancellation or trust change
    Dispatching --> Rejected: Permanent provider rejection
    Queued --> Exhausted: Attempt limit
```

Local presence cancels current wake work but preserves queued deliveries, frozen batch identities, deadlines, and attempt counts.
Resuming phone routing requires another host drain. It grants no approval authority and does not cancel a phone biometric prompt.
A resolved member is withdrawn without discarding other live members in its batch.
When no live members remain, root cancellation also cancels outstanding provider work, even if progress already reports expiry.
Already transmitted bytes cannot be recalled.

Enrollment changes and committed signed revocations withdraw affected entries and cancel their flights.
An unrelated phone remains independent. Late callbacks cannot restore a cancelled delivery.
A token rotated during OAuth is reread before sending.
An FCM `UNREGISTERED` response removes only the mapping operation used by that send.
A newer activation survives a late rejection for the old token.
This deletion retains enrollment keys, signed history, and control counters. Restoring delivery requires a fresh activation.

Shutdown rejects new work, cancels both probes and wakes, waits for their tasks, and releases the store.
Clock regression stops the owner. The host must not resume its queue under another clock epoch.

## Evidence and integration limits

Synthetic tests cover coalescing, late arrivals, retry timing, expiry, presence pause, queue bounds, and conflicting identities.
They also cover resolution, revocation, token rotation, late invalid-token responses, OAuth refresh, shared capacity, and shutdown.
An HTTP interceptor runs the real FCM sender without contacting Google.

The installed service, authenticated root channel, root drain scheduler, presence source, and phone notification flow remain integration work.
This component has no autonomous root-expiry timer; the root owner must deliver cancellation events during long network waits.
No live FCM request, real credential, device installation, or phone end-to-end test is part of these checks.
