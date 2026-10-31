---
github.com/tempoxyz/tempo-go: minor
---

Removed support for the legacy tempo.ts fee-payer trailer (`<rlp> || <sender> || 0xfeefeefeefee`) in `Deserialize`. The node rejects that format, so `Deserialize` now returns an error for it instead of stripping the trailer. `keychain.DecodeKeyAuthorization` again rejects an explicit trailing `0x80` and an explicit zero token-limit period, which the node fails to decode.
