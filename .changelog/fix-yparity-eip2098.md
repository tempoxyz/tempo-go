---
github.com/tempoxyz/tempo-go: patch
---

Accept legacy `yParity` values `{27, 28}` during transaction deserialization and normalize to `{0, 1}` per EIP-2098. Signers using the pre-EIP-155 recovery-id convention (raw secp256k1, viem `serializeSignature`, AgentCash-style EVM signers) no longer need to wrap their signatures before submitting. Serialization remains strict (only `{0, 1}` accepted on the encode path).
