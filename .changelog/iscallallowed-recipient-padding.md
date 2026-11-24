---
github.com/tempoxyz/tempo-go: patch
---

Fixed `KeyRestrictions.IsCallAllowed` accepting a recipient argument with non-zero upper padding bytes. It now rejects them like the AccountKeychain precompile does, instead of reporting a call as allowed that the chain would refuse.
