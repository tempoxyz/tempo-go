---
github.com/tempoxyz/tempo-go: patch
---

`ComputeHash` now decodes its input strictly as hex (0x prefix optional) instead of silently hashing a non-prefixed string as raw bytes.
