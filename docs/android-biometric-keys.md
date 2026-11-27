# Android biometric key custody

The Android app creates and inspects a separate P-256 biometric key for each enrollment.
The authorized enrollment flow must save and register the returned key reference.
Creating a key does not enroll a phone or approve a request.

Keys require strong biometrics for each operation, hardware-enforced authentication, and an unlocked device. Creation requests StrongBox first. Only explicit StrongBox unavailability permits a TEE retry, and only while the alias remains absent. Existing aliases are never overwritten. If generation succeeds but validation fails, the unpublished key is deleted under the creation lock. A generation failure has uncertain ownership and does not trigger deletion. Provider cleanup failures and process crashes can still leave orphaned keys; there is no automatic retry loop.

Inspection checks the key origin, curve, signing purpose, digest, authentication policy, alias, and enrolled public key. A disposable signing initialization checks for operation-level invalidation, then switches to verification to release the operation. It supplies no data and requests no signature or prompt. Missing or invalid keys require explicit recovery. Inspection never replaces a key. Per-use metadata values of -1 and 0 are accepted; authentication windows are rejected.

Production keys ask Android to invalidate the biometric approval key after a new biometric enrollment. This prevents a person who knows the phone PIN from adding their own fingerprint or face and then using the existing key to approve requests. The PIN alone cannot unlock that key because each use requires a strong biometric.

## Pair again after a change

If Android invalidates the key after a change to fingerprints or faces, the phone stops approving requests for that pairing. It explains the cause and shows **Pair again**. On the phone, select **Pair again** for the affected Mac. Follow the Mac pairing prompts and compare the codes before confirming. Repeat for each paired Mac you still use. The new pairing has a new approval key and enrollment epoch.

After upgrading from an older key policy, the first approval attempt on each Mac also asks you to pair again. This is a one-time migration per Mac. Existing keys keep their original Android policy until they are replaced, so the app refuses to approve with a legacy key. You can still decline a request with the separate decision key.

When the current approval connection supports repair notices, the phone sends a signed advisory. The Mac shows it under **Paired phones** in Setup. An offline Mac or a Mac without support may show no notice. The phone keeps its **Pair again** prompt and you can still complete pairing. Only the regular pairing flow changes trust.

JVM tests cover policy rejection, alias collisions, and fallback behavior. These tests do not prove Android Keystore behavior on a device. The debug probe key remains separate and unchanged.
