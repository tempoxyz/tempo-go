---
github.com/tempoxyz/tempo-go: patch
---

Accept legacy Ethereum recovery ID values `{27, 28}` in 65-byte secp256k1 signature envelopes during transaction deserialization, normalizing them to internal `yParity` `{0, 1}`. Structured RLP signature tuples remain strict and serialization continues to emit canonical `yParity` only.
