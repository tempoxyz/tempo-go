---
github.com/tempoxyz/tempo-go: patch
---

`Serialize` now returns an error instead of panicking when a transaction's sender or fee-payer signature has a nil R or S component.
