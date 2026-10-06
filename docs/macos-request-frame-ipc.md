# Request-frame IPC

The transport can fetch a signed request frame through the authenticated root connection. It cannot submit arbitrary bytes for signing through this interface.

```mermaid
sequenceDiagram
    participant T as Transport
    participant R as Root endpoint
    participant O as Request owner
    T->>R: hello (common IPC version 1)
    R-->>T: 1
    T->>R: requestDeliveryVersion (no scope data)
    R-->>T: 1 when a frame handler is installed
    T->>R: requestFrame(binding, request ID)
    R->>O: Check current transport policy and enrollment under owner lock
    O-->>R: Eligible signed frame, or no frame
    R-->>T: Bounded frame with matching scope and request ID
```

The existing hello, trust snapshot, and peer-validation calls retain their version-one behavior. Request delivery is an optional extension with its own version. The current extension supports version one only. Zero means disabled. Unknown versions send no binding or request ID. A server that lacks the extension selector can close the attempted connection; the client sends no request material before negotiation succeeds.

Each invocation retains OS peer validation and the shared work budget. The standard listener checks the current transport policy revision and enrollment binding under the same root lock as request access. The handler cannot reenter that owner. A changed policy or stale enrollment fails before the handler runs.

A nonempty reply is an approval request carrier with matching Mac, account, and request IDs. Both IPC ends bound and check this routing envelope. This is not signature or capture validation; Android must still verify the authority endorsement. An empty reply means no currently eligible frame. It does not mean denied, expired, or completed. Nil indicates failure and retires the connection.

The installed root handler must source frames from authority-owned requests, retain queue ownership across an uncertain IPC reply, and recheck current delivery eligibility. Frame retrieval is not a dequeue acknowledgment or action approval. The signed handoff API supplies exact retained bytes and checks expiry, presence, request state, and enrollment before queue acceptance.

The service supplies its own monotonic clock to the provider. Use that clock for request checks and resample it after signing.

`maximumPayloadBytes` bounds the complete signed carrier inside a session envelope. Production request admission reserves `ApprovalMessage.overheadBytes` within that budget. Frame providers must use `configuration.maximumRequestBodyBytes` for `retainedDeliveryFrame` or `handoffSignedDelivery`, rather than passing the full channel budget as a body limit. This derived limit does not change version-one or version-two configuration bytes. Tiny budgets cannot admit a complete issued request. A regression admits an exact-boundary body and rejects a body that would use the reserved wrapper space; channel tests send the resulting carrier within the original payload budget.

The service does not install a frame handler by default. Production queue ownership, the selected non-exportable signer, connection routing, and decision submission still need integration. Unit tests exercise the IPC adapter and root access guard.

The [live XPC evidence](experiments/evidence/2026-10-05-request-frame-xpc.json) records 11 passing cases on macOS 27.0.1. The two-process probe imports the production protocol declaration. It verifies version negotiation and the nonempty, empty, and nil Data reply forms. Wrong client and server identifiers prevent frame dispatch. The temporary per-user LaunchAgent was removed.

This probe uses synthetic bytes and ad-hoc identifiers. It does not exercise the production root endpoint, protected service routing, Developer ID policy, or device E2E. Those release integration checks remain pending; the probe does not establish them.

## Transport integration

`DirectApprovalTransportService.requestFrame` takes a live phone session and request ID. It checks that session before retrieval and after the reply. Session replacement, closure, or cancellation prevents return to the caller.

The trust feed serializes retrieval with validation and refresh on its existing authority connection. Its bounded wait queue and refresh priority also apply to fetches. Cancelling queued work does not cancel another active operation. A disconnected authority rejects late replies and retires its listener. Explicitly unsupported request delivery leaves common trust operations available.

This API returns a frame to the transport handler. It does not write to the phone, acknowledge delivery, install a root signer, or submit a decision. The network handler must retain its channel checks before sending.

## Root retry retention

`ApprovalRequestCoordinator.retainedDeliveryFrame` owns one in-memory frame per pending request and tracks eligible recipients through `PendingRequestDelivery`. Install it through the service's trusted frame provider, using the supplied service clock and the selected authority signer. Callbacks must not mutate or reenter the authority.

A first fetch checks current enrollment, contract support, presence, deadline, and request state. Signing uses the retained request bytes. It checks deadline and presence again after signing. A lost IPC reply does not dequeue or consume the request. A retry returns the retained frame after fresh authority checks. A changed signing key fails instead of releasing a frame under the previous key.

Present suppresses first delivery to a recipient. A recipient already handed a frame can retry while the request remains valid, as required for phone review across presence changes. This handoff is not proof of phone receipt. The provider does not mark the request presented or approved.

The cache releases frames when requests leave queued/presented state, including authorization, cancellation, and expiry. It dies with the coordinator. Frame storage is bounded separately by the retained-payload budget plus one carrier overhead per request; recipients share a frame. Existing request and recipient limits also apply. This does not persist sensitive payloads or implement FCM scheduling, pending-set discovery, or decision submission.

## Pending discovery owner

`ApprovalRequestCoordinator.pendingDeliveryRequestIDs` returns the complete current set of eligible IDs for one validated enrollment. The set is bounded by the coordinator's request limit (at most 4096), sorted by ID, and contains no capture bytes. It is a discovery hint, not proof that a later fetch will succeed.

Discovery omits elapsed requests without changing their lifecycle state. The maintenance path retains responsibility for expiry and cleanup. The owner selects the requesting enrollment once from current trust. Each request then checks only that recipient and its contract support. Discovery creates no queue entries or delivery identities. Present excludes new deliveries while retaining previously handed-off requests. Discovery does not accept notification queue ownership or mark a request dispatched, presented, or consumed, and repeated discovery creates no extra request audit events.

The separate discovery IPC extension exposes this root API to authenticated transport callers. Phone wire exposure remains pending. Callers must negotiate discovery support and fetch each result through the existing frame checks. They must not treat an empty discovery result as a signed terminal status for a previously known request.

## Discovery IPC

Discovery has a separate optional version-one extension. After common hello, the transport calls `requestDiscoveryVersion`. Zero disables discovery. The client sends no binding until the result is exactly one. Unknown versions leave common trust calls and frame retrieval available. A server without the selector can retire the attempted connection before any binding is sent.

`pendingRequestIDs(binding)` returns canonical CBOR with exactly three fields: key zero is schema version one, key one is the exact encoded peer binding, and key two is the sorted request-ID array. The response contains at most 4096 unique 16-byte IDs and is bounded to 128 KiB. Both ends validate the response. An encoded empty list means no current discovery hints; nil, empty Data, malformed bytes, or a mismatched binding retires the connection.

The endpoint uses its existing OS identity guard and shared operation budget. The standard listener rechecks current transport code policy and the peer binding under the same authority lock as request discovery. The service passes its own clock to an optional trusted discovery provider. That provider calls the root discovery API using current local presence; no provider is installed by default.

Discovery and frame retrieval negotiate independently. Existing frame-version-one clients keep their existing behavior. Discovery creates no approval, queue acknowledgment, lifecycle transition, or terminal status. Phone network dispatch, notification scheduling, production provider installation, and decision submission remain separate integration work.

The [discovery live evidence](experiments/evidence/2026-10-06-discovery-xpc.json) records 14 passing synthetic cases, including discovery selector bridging and rejection before discovery dispatch for wrong client/server identifiers. The temporary service was removed. This probe does not establish protected root installation, Developer ID policy, or device E2E.

## Session discovery

`DirectApprovalTransportService.pendingRequestIDs` validates the live phone session before discovery and after the authority reply. Session replacement, service closure, or cancellation prevents return of IDs to the caller.

Discovery uses the trust feed's existing authority connection, bounded wait queue, and refresh priority. Cancelling queued discovery leaves the active operation running. An explicitly unsupported discovery extension preserves common trust operations and frame retrieval. Authority disconnection rejects late replies and retires the listener.

This API returns discovery hints to a transport handler. It does not send them to the phone, mark requests handled, or schedule notifications. The network handler must retain its channel checks before sending and fetch each frame through the existing request checks.

## Outbound channel delivery

The transport service now has a default fetch handler. It discovers one bounded snapshot and sends available signed frames through `NegotiatedNetworkChannel`. It preserves each carrier byte and signature. Discovery IDs stay on the Mac. Missing frames and unsupported contracts or required features produce no unsigned status or approval.

```mermaid
sequenceDiagram
    participant P as Enrolled phone channel
    participant T as Transport service
    participant A as Root authority
    P->>T: Confirm enrollment-bound negotiation
    T->>A: Validate and discover pending IDs
    A-->>T: Bound discovery hints
    loop Each ID, one frame at a time
        T->>A: Validate and fetch retained signed frame
        A-->>T: Exact frame or no frame
        T->>T: Check channel scope, contract, features and size
        T->>A: Revalidate current session
        T-->>P: Original signed frame in session envelope
    end
    T->>P: Close completed fetch connection
```

The phone must verify the authority signature and capture semantics. A transport write does not establish phone receipt, presentation, consent, or execution. The existing Android receiver keeps retained request owners on EOF and authenticates duplicates before reusing them.

The default handler returns after the snapshot. The listener closes its fetch connection. An explicit custom handler remains in control and can call `deliverPendingRequests` without closing a successful channel. No live polling or decision handling is added here.

The write deadline defaults to 30 seconds and has a constructor setting. No new write starts after that deadline; a blocked write closes the channel. Authority operations retain their separate bounded IPC deadlines and ordered queue. Cancellation, stale-session checks, invalid frames, and failed writes close the channel. A failed write stops the scan before fetching another frame.

Tests use synthetic authority IPC and a negotiated in-memory phone stream. They verify exact signed bytes and sequences, absent requests, runtime features, wrong scopes, changed sessions, service closure, payload bounds, write failure, timeout, cancellation, and custom-handler ownership. These tests do not exercise native TLS sockets, Android hardware, protected installation, production key custody, push, or relay delivery. Production root providers and bidirectional decision/status assembly remain required.

The [state and decision exchange](macos-request-exchange-ipc.md) adds a separately negotiated IPC extension for signed status and consumption. The default network fetch handler is unchanged.
