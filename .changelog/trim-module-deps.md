---
github.com/tempoxyz/tempo-go: patch
---

Trimmed the module's dependencies: go-cmp is no longer compiled into `pkg/transaction`, and the integration tests (`tests/`) and the `parallel-nonces` example moved into their own modules, so go-ethereum's KZG and BLS packages (gnark-crypto, go-eth-kzg, c-kzg-4844, blst) and godotenv no longer appear in the root `go.mod`.
