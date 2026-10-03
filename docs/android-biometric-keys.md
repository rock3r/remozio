# Android biometric key custody

The Android app can create and inspect a distinct P-256 biometric key for an enrollment. Creation returns a reference for the authorized enrollment flow to persist and register. It does not enroll a phone or approve a request.

Keys require strong biometrics for each operation, hardware-enforced authentication, and an unlocked device. Creation requests StrongBox first. Only explicit StrongBox unavailability permits a TEE retry, and only while the alias remains absent. Existing aliases are never overwritten. If generation succeeds but validation fails, the unpublished key is deleted under the creation lock. A generation failure has uncertain ownership and does not trigger deletion. Provider cleanup failures and process crashes can still leave orphaned keys; there is no automatic retry loop.

Inspection checks the key origin, curve, signing purpose, digest, authentication policy, alias, and enrolled public key. A disposable signing initialization checks for operation-level invalidation, then switches to verification to release the operation. It supplies no data and requests no signature or prompt. Missing or invalid keys require explicit recovery. Inspection never replaces a key. Per-use metadata values of -1 and 0 are accepted; authentication windows are rejected.

Creation requests retention across biometric enrollment changes. The platform invalidation flag is diagnostic only. The Pixel experiment has not established actual retention. This component offers no generic signing operation and has no production UI integration yet. Request-bound CryptoObject signing and enrollment recovery remain separate work.

JVM tests cover policy rejection, alias collisions, and fallback behavior. These tests do not prove Android Keystore behavior on a device. The debug probe key remains separate and unchanged.
