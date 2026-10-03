# Encrypted setup files

`SetupFileEncryption` implements the encrypted container for portable setup exports. It does not export configuration, read credentials, install services, or apply imported settings. The protected setup host must supply an allowed payload and validate its schema before preview or import.

## Version 1 container

The file uses [JWE compact serialization](https://www.rfc-editor.org/rfc/rfc7516.html). Its fixed algorithms are `PBES2-HS512+A256KW` and `A256GCM`, as specified in [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8). JOSESwift 3.0.0 supplies the cryptographic implementation; the package version and resolved revision are pinned.

| Field | Contract |
| --- | --- |
| `typ` | `remozio-setup-v1+jwe` |
| `alg` / `enc` | The fixed algorithms above; no negotiation |
| `p2s` | Fresh random 32-byte salt |
| `p2c` | Export: 220,000; import: 220,000 through 1,000,000 |
| Content key / nonce | Fresh random 256-bit key and 96-bit GCM nonce |
| Payload | 1 through 1,048,576 bytes |
| Encoded file | At most 1,400,000 bytes |
| Password | 1 through 1,024 UTF-8 bytes; no normalization or truncation |

The work factor follows the current [OWASP PBKDF2-HMAC-SHA512 guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). It replaces the library's 1,000-round default. Password strength still matters against offline guessing. The setup UI must explain this and offer a strong password; this codec does not estimate entropy.

The profile accepts exactly the five protected header fields above, with compact sorted-key JSON and canonical unpadded base64url. Canonical reserialization rejects duplicate keys and alternative representations before the library parses them. Compression, extra headers, other algorithms, and unknown type versions are rejected. This is a restricted setup-file profile, not a general JWE importer.

All lengths and the iteration range are checked before password derivation. Authentication must succeed before plaintext is returned. Errors contain no input, password, decrypted content, or provider error details. No plaintext staging file is created. Swift and provider copies cannot be reliably erased; callers must avoid retaining or logging secrets. Derivation is synchronous and belongs off the UI thread. The host must serialize imports to bound concurrent resource use.

## Integration boundary

The future payload schema must explicitly allow shared FCM/provider configuration, shared settings, and credentials for provisioning independent Mac resources. It must exclude authority keys, device keys, pairings, ADB keys and grants, approval credentials, audit history, pending requests, and another Mac's tunnel run identity. A valid password or container does not make a payload safe to apply.

File selection, category preview, protected import, independent identity creation, and credential provisioning remain pending. This component never mutates live state. Copies of exported credentials remain usable until those credentials are revoked; deleting an export does not revoke them.

## Evidence

The tests cover wrong passwords, altered encrypted parts and headers, duplicate fields, unsupported algorithms, excessive derivation work, and size limits. They also open a fixture generated independently with Node's crypto provider. Reproduce the public synthetic fixture with:

```sh
node scripts/generate-setup-encryption-fixture.mjs
```

The fixed keys in that generator are test data only. Tests also verify fresh export randomness, exact Unicode password handling, and a maximum-size payload. No real provider credentials or device keys are used.
