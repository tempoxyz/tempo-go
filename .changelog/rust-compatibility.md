---
github.com/tempoxyz/tempo-go: minor
---

Add Tempo EIP-7702 authorization lists, explicit zero-address fee-token selection,
and decoding for keychain V1/V2 signatures with P256/WebAuthn inner signatures.
Expose all 19 precompile interfaces from the pinned Rust contracts revision.

Serialize secp256k1 recovery IDs canonically as 27/28, matching Rust, while
retaining 0/1 in the public YParity model and accepting both on decode. This
changes serialized bytes and transaction hashes compared with prior SDK output.
Applications persisting signed bytes or locally computed transaction hashes
should account for this change. Sender signing hashes without authorizations
are unchanged.
