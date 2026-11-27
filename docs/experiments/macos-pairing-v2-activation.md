# Attended validation for pairing v2 activation

The production default stays disabled. Use an approved signed Mac and Android build with a disposable account and pairing window. Record the exact artifact digests and installed service roles before the test.

- [ ] Verify that the signed Mac app, Root Authority and Transport use the same protected pairing policy and pinned key. Verify that a different signed process cannot use the proof endpoint.
- [ ] Restart Transport through the approved fixture while a proof slot is reserved. Verify that the Authority releases the slot and that the next invitation works without an Authority restart.
- [ ] On the approved LAN, use the updated Android app to discover the exact window and negotiate `remozio-pairing/3`. Verify both proofs, the comparison, the administrator consent, and one durable receipt.
- [ ] Verify listener closure and expiry. Use the approved capacity and shared-address fixtures to measure legitimate pairing under sustained load. Retain the measured acceptance rate and accept-to-candidate latency.
- [ ] Cold-disable the disposable account through Setup. Verify that both jobs restart on the disabled record, the LAN listener is gone, and fresh v1 setup remains closed. Confirm that the enrolled phone and its existing receipt still work.

Record installed and LAN results separately. Exclude invitation text, codes, key material, and network addresses. Obtain the release decision after both sets of checks pass. [Pairing activation criteria](https://github.com/rock3r/remozio/issues/852#issuecomment-7148272028)
