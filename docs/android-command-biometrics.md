# Android command biometric authorization

`AndroidCommandBiometrics` owns one enrolled biometric key and one authenticated command session. The native `CommandBiometricPrompt` owns that identity for the screen. The integration must create it for the exact session whose command is displayed, then invoke it only from that command's execute control.

Preparation builds a decision from retained Mac, account, request, digest, challenge, phone, and key identities. The only action is execute for the current request. Preparation requires a signed pending status, a usable elapsed clock, and nonzero remaining authorization time. These checks do not prove delivery freshness. The Mac remains authoritative for expiry, first-arrival selection, enrollment validity, and the final target check.

The native prompt requests strong biometrics with the prepared Signature as its CryptoObject. It accepts only the same Signature and a biometric success result. Before signing, it checks pending status and the retained decision again under the session monitor. The resulting protocol signature is verified against the enrolled public key before returning a carrier. No raw signing function or replaceable callback payload is exposed.

Attempt tickets cover asynchronous preparation. Cancelled tickets cannot start late operations. Stop, destruction, explicit close, and request replacement cancel the prompt. The caller must close on enrollment changes and Compose disposal. A 250 ms check dismisses the prompt when the request is no longer actionable; completion also checks synchronously. Late, repeated, substituted, closed, expired, and terminal callbacks cannot produce a carrier. Cancellation releases the local operation without signing.

This component does not send the decision, connect the launcher to live enrollment, or release a credential. Ordinary decline remains on the separate decision-key path without biometrics. Enrollment retention and the single-prompt credential-release gate remain unproven.

JVM tests use software keys to verify exact bindings, signature domains, substituted keys and operations, inactive enrollment, cancellation, request closure, terminal status, and elapsed-clock changes. They do not establish device biometric enforcement or native dialog behavior. Native prompt and lifecycle checks remain for the interactive Pixel session.
