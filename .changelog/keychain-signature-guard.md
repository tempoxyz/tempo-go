---
github.com/tempoxyz/tempo-go: minor
---

`BuildKeychainSignature` now returns `([]byte, error)` and rejects nil or over-32-byte R/S components instead of panicking or silently corrupting the signature.
