---
github.com/tempoxyz/tempo-go: patch
---

Validate token amounts in `KeyRestrictions.Validate` and `UpdateSpendingLimit` so nil, negative, or over-uint256 values return an error instead of panicking inside ABI packing.
