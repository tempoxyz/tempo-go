---
github.com/tempoxyz/tempo-go: patch
---

Reject non-canonical (leading-zero) RLP integer encodings during transaction deserialization, preventing hash malleability and round-trip divergence.
