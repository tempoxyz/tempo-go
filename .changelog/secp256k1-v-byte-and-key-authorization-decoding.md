---
github.com/tempoxyz/tempo-go: minor
---

Changed secp256k1 sender signatures and keychain inner signatures to encode the recovery id as 27/28, matching the node, viem/ox and pytempo, so `Tx.Hash()` now returns the hash the node reports; transactions signed by earlier versions serialize and hash differently. `Deserialize` and `ParseKeychainSignature` accept both 27/28 and 0/1 and re-encode as 27/28. Added `keychain.DecodeKeyAuthorization` to decode a transaction's signed key authorization (`Tx.KeyAuthorization`) into a `KeyAuthorization` and its signature. `Tx.Validate` now rejects a `maxPriorityFeePerGas` above `maxFeePerGas`, and a `validBefore` at or before `validAfter` when both are set.
