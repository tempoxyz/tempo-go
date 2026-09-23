---
github.com/tempoxyz/tempo-go: patch
---

Make client construction robust: `WithHTTPClient(nil)` is ignored instead of causing a panic, and `WithTimeout` is applied regardless of option order so a later `WithHTTPClient` no longer discards it.
