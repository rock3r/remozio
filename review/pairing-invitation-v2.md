# Pairing invitation v2

Design review for [#852](https://github.com/rock3r/remozio/issues/852). Source baseline `096ab468` on main. This proposal changes initial enrollment and explicit re-pair. Existing approvers keep their keys, trust and approval channels.

## Invitation and proof

The signed Mac app opens a window through the authenticated local Authority channel when the user chooses **Pair a phone** or **Re-pair**. The Authority generates a random 16-byte window ID and a separate random 32-byte secret. It retains the window and its monotonic deadline in memory. Closing or replacing the window invalidates its secret and any uncommitted candidate.

QR and copied text carry the same `remozio-pairing:v2:` payload. Use unpadded base64url and deterministic CBOR. The map has exactly seven fields.

| Key | Field |
| --- | --- |
| 0 | Version 2 |
| 1 | Canonical public invitation v1 bytes, with the existing 512-byte limit |
| 2 | 16-byte window ID |
| 3 | 32-byte invitation secret |
| 4 | Use tag 0 for initial enrollment or 1 for re-pair |
| 5 | Predecessor scope as the existing array of Mac ID, account ID, phone ID, and epoch, or null |
| 6 | Window lifetime in milliseconds for display |

The Authority’s elapsed clock determines expiry. Allow at most 768 bytes of CBOR and 1,043 ASCII characters including the prefix. Check that the predecessor scope agrees with the invitation scope. Reject unknown fields, inconsistent use and predecessor claims, noncanonical encodings, invalid lengths and trailing bytes.

Treat the QR and copied text as credentials. On macOS, use `NSPasteboard.prepareForNewContents(with: .currentHostOnly)` before writing the text. Record the pasteboard change count. When the window closes or changes, clear the entry only if both the count and the text still match. Keep QR as the primary transfer path. [AppKit documentation](https://developer.apple.com/documentation/appkit/nspasteboard/contentsoptions/currenthostonly)

On Android, read pasted invitations only after the user chooses Paste. Keep the text in transient state and clear it on success or cancel. If Remozio writes invitation text to an Android clipboard, set `ClipDescription.EXTRA_IS_SENSITIVE` on that clip before publishing it. Android applies this flag when the source writes the clip; the paste reader does not rewrite another app’s clipboard. [Android clipboard documentation](https://developer.android.com/develop/ui/views/touch-and-input/copy-paste)

Carry the secret only in those local exports and in the app’s authenticated exchange with the Authority. Keep it out of network messages, Bonjour, logs and durable state. Keep it in memory only while needed. Do not put the secret, the derived key, or the exporter in audit records or crash diagnostics.

Use TLS 1.3 with server pinning and the application protocol `remozio-pairing/2`. Use the TLS exporter for the negotiated connection, with label `EXPORTER-dev.remozio.pairing.invitation/2`, empty context, and 32 output bytes. Reject missing exporter material. Use no early data or setup resumption. [RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5)

After the handshake, Transport sends a fresh 32-byte challenge held for that connection. The phone responds with the proposal and a 32-byte HMAC-SHA256 tag. Derive the tag key with HKDF-SHA256 from the invitation secret, using the window ID as salt and `dev.remozio.pairing.invitation-key/2` as info. The MAC input is a canonical CBOR array with the following values in order. [RFC 5869 §2](https://www.rfc-editor.org/rfc/rfc5869.html#section-2)

1. Domain `dev.remozio.pairing.invitation-proof/2`.
2. SHA-256 of a canonical six-key map. Remove key 3 and canonically re-encode the complete map with a six-entry map header.
3. The connection challenge and the connection’s exporter as separate byte strings.
4. SHA-256 of the exact canonical phone proposal.

The public invitation digest binds the public pins, scope, mode, predecessor, window ID, version and advertised lifetime. Transport verifies that the proposal’s transport key matches the authenticated TLS key. Transport generates the challenge and obtains the exporter from its TLS session. It sends both through the same authenticated local call that identifies the connection, together with the proposal and tag. The Authority uses only these Transport-supplied challenge and exporter values. The phone supplies neither value in its response. Use constant-time tag comparison.

The proof covers the pre-enrollment exchange. The Authority cannot issue the full comparison transcript until the user selects the candidate and provides administrator authorization. Keep the random challenge, all current pins and the exact candidate claims in that final transcript. Bind staging to the previously verified proposal and its window. Keep receipt signing and the existing transcript comparison.

## Candidate state and resource limits

Verify the proof before displaying a candidate or staging a request. The Authority atomically reserves an open window for one proved candidate. Bind the reservation to the window ID, proposal digest, peer key, connection and mode. A second connection cannot reuse a consumed invitation. On disconnect or cancellation, retire the reservation. Starting again generates a new invitation. Continue the existing commit checks for candidate, transcript, administrator authorization, biometric proof and current trust revision.

Start with a 120-second window. Close the listener on expiry, cancel, sheet close, or a replacement window. Limit the unauthenticated pool to four simultaneous connections. Start the three-second proof deadline when Transport accepts the socket. TLS must complete within that same budget. When the pool is full, a newly admitted connection evicts the oldest connection that has not proved possession. Hold at most one verified candidate separately. Use the existing bounded frame decoder. An invalid attempt releases its slot and leaves the 256-bit invitation available. The window has no failure-count limit. Use bounded per-source admission throttles and retain the global cap. Validate the proposed timings on supported devices before shipping.

[#846](https://github.com/rock3r/remozio/issues/846) remains the availability check. Unauthenticated traffic uses a separate short-lived budget and cannot consume the verified candidate slot. Sustained connection churn can still delay a valid attempt. Test with controlled synthetic connection churn that continues while the valid phone connects. Verify the concurrency cap, FIFO eviction of unproved connections, the accept-to-proof deadline, and retention of a proved candidate during churn. Record the legitimate completion rate and verify prompt recovery after churn stops.

## Platform behavior and compatibility

| Platform | Proposed behavior |
| --- | --- |
| macOS | Explicit window with QR and copy text. Display only the proved candidate. Keep administrator authorization and the full comparison. |
| Android | Scan or paste v2, pin the Mac, submit proof, compare the full code, and sign with biometrics. Activate the prepared record only after a verified receipt. Validate the exporter on the Android TLS provider used for enrollment. |
| iOS | Keep the scan and paste preview. Show that this build cannot complete secure pairing. Defer the v2 connection test until an exporter-backed diagnostic can operate without consuming an enrollment invitation or staging a candidate. |
| Linux peer | Implement v2 in the experimental peer and use the negotiated OpenSSL exporter. Preserve the peer’s existing typed transcript comparison. Keep legacy fixtures available offline for protocol coverage. |

A new client that sees v1 during enrollment shows “Update Remozio on your computer to pair securely.” A new Mac serves v2 setup only. The current version of an older client may show its generic invalid-invitation or connection error; the new Mac sheet tells the user to update the phone app. Enrollment closes on an unsupported version or exporter. Keep the existing approval protocol and receipt-recovery version.

Typed entry on the Mac can remain out of the first change. Proof of the one-use invitation makes the candidate list reflect receipt of the local QR or copied text. Keep the full comparison on both sides. Revisit typed entry if user testing shows recurring confusion about copied invitations.

## Re-pair and receipt recovery

Re-pair uses a fresh v2 invitation bound to the retained phone, predecessor epoch and current eligible revoked state. Check these before reservation, staging and commit. Proof creates only a reservation. Create the re-pair stage after the user selects that proved candidate and the Authority verifies administrator authorization. An expired window creates no stage and leaves prior stages intact. Keep the existing replay rules, durable retention and trust revision rules.

[#901](https://github.com/rock3r/remozio/issues/901) remains the receipt-recovery contract. Keep its separate ALPN, recovery exporter domain, signed commit and signed expired-without-commit answers. An expired invitation closes new admission. It does not clear a phone’s existing PREPARED record or prove the outcome of a commit. Recovery of a previously prepared v1 or v2 attempt uses its retained keys and the existing authenticated receipt checks. Add recovery and signed expiry receipt vectors using a transcript produced through setup v2. Keep existing v1 vectors to check compatibility.

## Validation matrix

| Layer | Cases |
| --- | --- |
| Swift and Kotlin wire vectors | Round-trip v2 QR and text, exact field and length checks, unknown versions, canonical transcript bytes, shared HKDF and MAC vectors, malformed input, redaction |
| Setup session | Valid proof, wrong or absent secret, altered proposal or scope, wrong exporter or challenge, missing exporter, expired or closed window, replay, simultaneous reservation, connection replacement |
| Listener and Authority | Candidate hidden before proof, accept-to-proof timeout, eviction order, sustained synthetic churn during a valid attempt, close and drain, proved candidate retention, commit against the selected proposal only |
| Platform integration | Android scan and paste, supported TLS exporter and positive path, explicit legacy error, Linux/macOS v2 interoperability, iOS preview with no enrollment side effects |
| Trust, recovery and UX | Existing approval works, re-pair with revoked predecessor and stale-state rejection, lost receipt and signed expiry vectors for v2, prior PREPARED retention, no stage before administrator authorization, expiry before staging, clipboard ownership and cleanup, accessible QR alternative and clear comparison |

Use synthetic invitations and peer keys in logs and vectors. Confirm exporter availability and tests on the supported platform matrix before enabling v2. Keep the final installed Mac–phone exercise separate from source and CI fixtures.

## Proposed PR order

1. **Protocol and vectors.** Add v2 invitation encoding, canonical proof input and Swift/Kotlin vectors. Cover recovery and expiry receipts from v2 setup. Leave the installed setup path as it is.
2. **Mac.** Add the Authority window, verified candidate reservation, Transport limits, and the signed app’s QR and clipboard behavior. Exercise the v2 path through test wiring.
3. **Android.** Add v2 QR and paste enrollment, the live TLS exporter, comparison, biometric proof, and receipt activation. Qualify the Mac–Android path before making v2 the default enrollment path. When v2 is enabled, require it for that window.
4. **Linux peer.** Add the v2 exporter and proof to the experimental peer. Run the Mac/Android protocol vectors and the Linux interoperability fixture. Keep the peer’s typed comparison.
5. **iOS preview.** Add the v2 preview and update message. Keep connections to enrollment disabled from preview until a separate diagnostic is approved.

Keep each step reviewable and qualify any enabled path before publication. The Mac and Android PRs may land before the production switch; keep the switch explicit until both sides pass together.
