---
github.com/tempoxyz/tempo-go: patch
---

Reject non-canonical secp256k1 signatures during transaction deserialization and address recovery, preventing transaction hash malleability via legacy `V` values and high-S signatures.
