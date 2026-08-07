---
github.com/tempoxyz/tempo-go: patch
---

`SendBatch` now surfaces a top-level JSON-RPC error object (returned when a whole batch is rejected) as a `*JSONRPCError`, instead of masking it behind a generic unmarshal error.
