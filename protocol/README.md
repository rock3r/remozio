# Protocol foundations

This directory contains the deterministic encoding subset and shared conformance vectors. The Swift library is the first implementation. Kotlin conformance, signed schemas, negotiation, action policy, and durable consumption are separate deliverables. A parsed value does not authorize an action.

## Deterministic CBOR subset 1

The encoding follows the [RFC 8949 core deterministic rules](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1). Arguments use their shortest encoding. Containers have definite lengths. Map keys are sorted by their encoded bytes; for the supported unsigned keys, numeric order produces this order.

| Supported value | Representation |
| --- | --- |
| Unsigned integer | Major type 0, full UInt64 range |
| Arbitrary bytes | Major type 2 |
| UTF-8 text | Major type 3, valid UTF-8 only |
| Ordered array | Major type 4 |
| Field map | Major type 5, unique unsigned integer keys |
| False, true, null | `f4`, `f5`, `f6` |

Reject every other CBOR type, negative integer, tag, float, indefinite length, reserved argument, non-minimal argument, unordered or duplicate map key, invalid UTF-8 sequence, truncation, or trailing byte. A message contains exactly one value.

Text retains its exact UTF-8 spelling. There is no normalization or replacement of malformed input. The Swift value type also compares text by UTF-8 bytes. Opaque identity, command argument, and credential bytes must use byte strings where the eventual schema requires them. Map field numbers do not define action semantics by themselves.

## Resource bounds

Every encode and decode call requires explicit byte, depth, and item limits. These are local resource guards, not negotiated values from an untrusted peer. No payload is truncated. Byte, depth, and item failures are distinct errors. The caller must map a legitimate oversized capture to the design's `Request too large` result.

The root has depth zero. Each array member, map key, and map value adds one depth level. Every value, container, and map key counts as one item. The configured depth cannot exceed 64, to bound recursive stack use. Limits apply to encoding as well as decoding.

The codec checks the total input size before making its parser copy. It checks lengths before converting them to machine integers or slicing storage. It bounds collection counts before allocating parsed elements. The encoder bounds map counts before sorting keys.

The test harness uses 1 MiB, depth 32, and 65,536 items. These are test budgets only. Production capture limits still require argv/environment measurements and realistic UI fixtures; this change does not set a product payload cap.

## Conformance and use

`vectors/cbor-subset-v1.json` is language-neutral. Valid vectors must decode and re-encode to identical bytes. Invalid vectors must fail. Separate semantic tests check decoded values, integer boundaries, text byte preservation, resource limits, and sliced input. A deterministic malformed-input corpus checks that accepted inputs re-encode identically. It is a regression check, not a substitute for coverage-guided fuzzing.

```sh
swift test --package-path protocol/swift --triple arm64-apple-macosx26.0
```

The macOS local gate and CI run these tests. The encoding subset number is not an authenticated wire version. Release compatibility claims wait for the signed contract and cross-language conformance.

## Next security layers

Message schemas must reject unknown critical fields, enums, purposes, and versions. Declared optional fields must remain in the signed bytes. Verifiers must bind both the immutable request and the exact action contract, with separate signature domains and enrolled key purposes. Encoding success alone must never select a key class, infer consent, or permit dispatch.
