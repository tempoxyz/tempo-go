---
github.com/tempoxyz/tempo-go: patch
---

Fixed decoding of keychain envelopes with P256 or WebAuthn inner signatures, which were rejected with an invalid recovery id since the 27/28 normalization. `SignWithAccessKeyEnvelope` now writes a secp256k1 inner recovery id as 27/28, as `SignWithAccessKey` does.
