# Pairing comparison code, format 1

The phone displays four groups for the complete Root-returned pairing transcript. The Mac displays the first three groups.
Compare the first three groups on the Remozio setup screens you opened on both devices. Then enter the last group from the phone in the masked field on the Mac.
The Mac checks the entered group against the current transcript. A missing or incorrect group leaves enrollment unconfirmed. After three mismatches, the Mac closes the setup. Start a new pairing to try again.

Use the existing full transcript digest: SHA-256 over the canonical phone-biometric signing input.
Read its first 100 bits from most significant to least significant. Encode consecutive five-bit groups with this alphabet:

```text
23456789ABCDEFGHJKLMNPQRSTUVWXYZ
```

Display the 20 symbols as four groups of five, separated by spaces.
The alphabet excludes zero, one, I and O. Both implementations use the same shared vectors.
The format changes no transcript bytes, signing purpose, wire frame, invitation or receipt.

The full comparison code carries 100 bits. The Mac checks only the last group, which carries 25 bits.
With at most three blind guesses at an unpredictable group, the probability of guessing it is at most 3 × 2⁻²⁵ per session.
The first three groups carry 75 bits for the visual comparison. The Mac cannot verify that the user compared them.

Root checks the full 256-bit digest at commit. Phone signatures and commit receipts bind the complete canonical transcript.
The invitation's diagnostic fingerprint remains separate and unchanged.

The code binds both devices' keys, identities, protocol choice, fresh challenge, setup ID, trust revision and expiry.
Changing setup cancels previous human confirmation and any pending biometric operation.
A matching code never replaces local administrator authorization, fresh biometric signing, current trust checks or receipt verification.

Physical comparison, native administrator prompts and hardware enrollment remain interactive integration checks.

The signed Mac release declares `pairing.invitation` and `pairing.transcript` version 1 for their consuming roles.
The transport declares `pairing.setup-frame`, `transport.pairing-config`, and the local pairing control formats at version 1.
The Root declares its pairing setup configuration and local IPC at version 1.
Its presence startup format declares versions 1 and 2. Version 2 includes the optional pairing configuration.
These declarations do not grant enrollment or enable service installation.
