# Phone wake routing

Push data selects a locally enrolled Mac/account through its opaque notification tag. It cannot install an endpoint, key, enrollment, or request.

```mermaid
sequenceDiagram
    participant Provider
    participant Router
    participant Android
    participant Fetch
    Provider->>Router: Opaque wake and enrollment tag
    Router->>Router: Strict decoding and local tag lookup
    Router->>Android: Post generic notification
    Android-->>Router: Posted, disabled, denied, or failed
    Router->>Router: Retain complete-set fetch demand
    Fetch->>Router: Reserve this enrollment
    Fetch->>Fetch: Authenticate Mac with retained pins
    Fetch->>Router: Recheck reservation and finish
```

`PushWakeRouter` owns one process window. Trusted setup supplies all enrollment identities and fresh random tags. Removal invalidates the exact handle and outstanding fetch reservations. Retired tags cannot select replacements. Other Macs and accounts remain independent.

Each enrollment permits one fetch reservation. Wakes before that reservation coalesce. A new wake during a fetch retains demand for another complete pending-set fetch. Failure retains demand. Old completions cannot clear a replacement reservation. The host must recheck reservations around awaits and deliver verified results through the current authenticated request owner.

A bounded cache suppresses duplicate hints. Cache eviction and expiry may permit another generic notification and fetch. They never remove pending fetch demand. This cache is not durable replay protection or request authority. Notification alert spacing applies independently to each enrollment. Failed posts do not advance that spacing.

Enrollment capacity, remembered tags, duplicate lifetime, hint capacity, alert spacing, and notification timeout are explicit configuration inputs. This change selects no product defaults. Exhausted enrollment/tag capacity rejects registration rather than evicting trusted state. The future persistent enrollment owner must manage restoration and retired tags across process windows.

The router samples the supplied clock under the same lock as receipt processing. Concurrent callbacks cannot reverse clock observations. Clock regression or an epoch change closes this process owner and invalidates reservations. It does not delete persistent pairing. Restore a fresh owner from trusted enrollment records. Callbacks are synchronous and must not reenter the router or perform network work under its lock.

## Android adapter

`AndroidPushWakeReceiver` samples elapsed realtime and posts through `AndroidWakeNotifications` before returning fetch demand. Notifications contain generic text only. An immutable explicit intent opens the app without request details or actions. One notification per enrollment replaces earlier hints. Silent updates do not alert again inside the configured interval.

The adapter reports missing permission, disabled notifications, disabled channels, and platform failures. `POSTED` means Android accepted the call; it does not prove visibility or reading. Notification timeout is not request expiry. Removing an enrollment cancels its generic notification.

The manifest declares notification permission. There is no startup permission prompt. The launcher, Firebase listener, enrollment persistence, token-challenge proof flow, authenticated fetch transport, and bounded background scheduling are not connected yet. This backend does not claim working push delivery. Device notification appearance, channel behavior, and background lifecycle remain for the Pixel session.

References: [Android notification permission](https://developer.android.com/develop/ui/compose/notifications/notification-permission), [notification channels](https://developer.android.com/develop/ui/compose/notifications/channels), and [FCM processing priority](https://firebase.google.com/docs/cloud-messaging/android-message-priority).
