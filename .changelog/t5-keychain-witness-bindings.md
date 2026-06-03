---
github.com/tempoxyz/tempo-go: minor
---

- Add T5 AccountKeychain TIP-1053 witness bindings: `AuthorizeKeyWithWitness()`, `BurnKeyAuthorizationWitness()`, `IsKeyAuthorizationWitnessBurned()`, and matching selector constants.
- Add T5 integration coverage for key-authorization witness burn, read, and authorize flows gated by `TEMPO_HARDFORK=T5`.
