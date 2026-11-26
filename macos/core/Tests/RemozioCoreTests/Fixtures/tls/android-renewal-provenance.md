# Android transport leaf fixtures

These files contain only public certificate data. Their P-256 keys were generated in memory for the fixtures. No private key was saved.

The Android issuer and renewal selection came from `TransportLeafRenewal.kt`, commit `f89ea203ec9658af46e3966f55f83b853bba9519`. Its source SHA-256 is `223343c9c821718e9b94a91bf9a304b1393fbd75edbfd6eaaa1a23b5f7d21a47`. The issuer signed the original leaf on 2026-01-12 at 12:00 UTC. The renewal ran 350 days later using the same software key.

| File | SHA-256 |
| --- | --- |
| `android-renewal.spki` | `a9171107c4dc8000610d898330724a94f0ce3c695b1dfb5337d65424e9d70cd9` |
| `android-original.der` | `9a69858b571a3fab83288e84b5de6657fd6d551ca9d0eea4584053da1783cb38` |
| `android-renewed.der` | `b2e4bf45bff10db803ab56594de14dcaef5ed90fe4758fb7741997b7ca51a1b2` |

The Android test resources use a separate software key. The same issuer generated the original leaf and the base for its replacement. The fixture generator added the noncritical documentation OID `1.3.6.1.4.1.32473.1` to the replacement and signed it again with that same key. [RFC 5612](https://www.rfc-editor.org/rfc/rfc5612.html)

| Android resource | SHA-256 |
| --- | --- |
| `transport-leaf/original.der` | `41bceb771eae01a3b27830676a9bddcc833266df295daee5dfd62ef14164d303` |
| `transport-leaf/extra.der` | `dd3b670563a9e9436b42c2687cd0a256ead4c8c442acd38e3ba34188290f410e` |
