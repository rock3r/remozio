# Request state and decision exchange

The authority exchange accepts a request ID and an optional signed phone decision. It returns the current authority-signed status. It never executes a command or clicks a prompt.

```mermaid
sequenceDiagram
    participant Phone
    participant Transport as Dedicated transport
    participant Root as Root authority
    participant Journal as Protected journal
    Phone->>Transport: Status query or signed decision
    Transport->>Root: Current binding and bounded exchange query
    Root->>Journal: Recheck transport code and enrollment under the shared lock
    opt Phone submitted a decision
        Root->>Root: Check digest, challenge, phone, action, key class and signature
        alt Request remains pending
            Root->>Journal: Commit first valid consumption and audit
        else Request already handled
            Root->>Root: Retain the existing winner
        end
    end
    Root->>Root: Sign current status; recheck time after signing
    Root-->>Transport: Signed status or explicit absence
    Transport->>Transport: Recheck live channel generation
    Transport-->>Phone: Status delivery remains network integration work
```

## Local IPC contract

After common hello, negotiate `requestExchangeVersion`. Version one enables `exchangeRequest(binding, query)`. Zero or unknown versions send no binding or decision and leave common operations available. An older server without the selector can retire the connection before query dispatch.

The canonical query has three fields: key zero is schema one, key one is the 16-byte request ID, and key two is a signed decision carrier or null. The complete decision carrier is at most 4096 bytes. The query is at most 4352 bytes. Empty decision bytes are invalid.

A nonempty reply is a status carrier of at most 4096 bytes. Both IPC ends check its type, status structure, Mac/account scope, and request ID. The phone must verify its authority signature and retained digest/challenge. Empty Data means no retained live state. Nil, malformed bytes, or wrong scope retires the connection. Absence never proves expiry or a terminal result.

The endpoint uses the existing OS identity guard and shared work budget. The standard listener rechecks current transport code policy and enrollment inside the shared authority lock. The feed keeps its bounded ordered queue and refresh priority. The service rejects replies after channel replacement, closure, or cancellation. It never retries a decision automatically.

## Root ownership

`ApprovalRequestCoordinator.exchangeRequest` signs retained state. The trusted provider supplies the authority key, signer, and service clock. Use a status body budget no larger than both `configuration.maximumRequestBodyBytes` and 3968 bytes. No provider is installed by default.

Admission retains a stable observation ID, lifetime estimate, and late-observation flag. Adapters can supply the original observation ID when issuing a new challenge for the same target. The default creates a new random observation ID. Status revisions increase on every signing attempt, including failed attempts. They remain separate from lifecycle revisions.

A refresh keeps the original age origin, estimate, challenge, digest, and terminal transition age. Crossing the deadline during signing discards the pending snapshot. The authority commits expiry and signs its terminal state. Present does not suppress status reconciliation or consume an already reviewed request.

Every submitted decision must match the retained request and authenticated phone. Its captured action determines the required key class and signing purpose. Even an already handled request checks the decision signature. Only a still-pending request reaches durable consumption. Later valid decisions return the original winner without another consumption or dispatch.

Consumption can commit before signing fails or the reply is lost. Reconcile with a read-only status query. A returned Authorized state grants no separate execution permit. The existing executor checks remain required.

Terminal capture bytes are released. Bounded status metadata remains until the owner forgets that terminal request. It is not reconstructed after restart. Durable consumption history stays in the journal; live request restart reconciliation remains separate assembly work.

## Evidence and remaining work

Native tests cover signed age/revision progression, expiry during signing, decline without biometrics, two-phone contention, repeated decisions, lost replies, invalid signatures and bindings, output bounds, stale transport policy, and channel cancellation. Software keys and disposable journals provide these fixtures.

The [live XPC evidence](experiments/evidence/2026-10-06-request-exchange-xpc.json) records 19 passing cases and removal of the temporary service. The probe uses synthetic bytes and ad-hoc identifiers. It proves selector/Data bridging and rejection before dispatch for mismatched identifiers. It does not prove root installation, Developer ID policy, phone keys, or approval execution.

The default network handler still sends a request snapshot and closes. A bidirectional network loop, Android decision sending, production signer/providers, terminal restart reconciliation, push scheduling, and protected app installation remain required. No service or device approval is enabled by this change.
