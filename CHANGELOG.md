# Changelog

## `github.com/tempoxyz/tempo-go@0.7.0`

### Minor Changes

- Added P256 and WebAuthn signing and verification, matching viem's tempo Accounts byte for byte: `signer.P256Signer` and `signer.WebAuthnSigner` (headless, like `Account.fromP256` and `Account.fromHeadlessWebAuthn`), the `signer.EnvelopeSigner` interface (also implemented by `signer.Signer`), and `signer.RecoverEnvelope`, which verifies any Tempo signature envelope (parsing WebAuthn clientDataJSON as strictly as tempo-primitives) (secp256k1, P256, WebAuthn, Keychain V1 and V2 with any inner signature) as tempo-primitives does. Added `transaction.SignTransactionWith` and `transaction.RecoverSigner`; `transaction.VerifySignature` now verifies P256 and WebAuthn senders. Added `keychain.SignWithAccessKeyEnvelope` for P256 and WebAuthn access keys, `KeyAuthorization.SignWith` for any root key and `keychain.NewKeyAuthorizationFor`; `keychain.VerifyAccessKeySignature`, `IsKeychainSignature` and `ValidateAccessKeySignature` accept Keychain V2 envelopes with any inner signature; V1 envelopes, whose inner signature does not commit to the account, are rejected there and reported by `transaction.RecoverSigner`. Transactions now decode Keychain V1 envelopes and Keychain envelopes with P256 or WebAuthn inner signatures. (by @brendanjryan, [#133](https://github.com/tempoxyz/tempo-go/pull/133))
- Removed support for the legacy tempo.ts fee-payer trailer (`<rlp> || <sender> || 0xfeefeefeefee`) in `Deserialize`. The node rejects that format, so `Deserialize` now returns an error for it instead of stripping the trailer. `keychain.DecodeKeyAuthorization` again rejects an explicit trailing `0x80` and an explicit zero token-limit period, which the node fails to decode. (by @brendanjryan, [#136](https://github.com/tempoxyz/tempo-go/pull/136))
- Changed secp256k1 sender signatures and keychain inner signatures to encode the recovery id as 27/28, matching the node, viem/ox and pytempo, so `Tx.Hash()` now returns the hash the node reports; transactions signed by earlier versions serialize and hash differently. `Deserialize` and `ParseKeychainSignature` accept both 27/28 and 0/1 and re-encode as 27/28. Added `keychain.DecodeKeyAuthorization` to decode a transaction's signed key authorization (`Tx.KeyAuthorization`) into a `KeyAuthorization` and its signature. `Tx.Validate` now rejects a `maxPriorityFeePerGas` above `maxFeePerGas`, and a `validBefore` at or before `validAfter` when both are set. (by @brendanjryan, [#135](https://github.com/tempoxyz/tempo-go/pull/135))

### Patch Changes

- Required bearer authentication for the loopback-only fee-payer example and restricted sponsorship to bounded token transfers. (by @brendanjryan, [#123](https://github.com/tempoxyz/tempo-go/pull/123))
- Fixed decoding of keychain envelopes with P256 or WebAuthn inner signatures, which were rejected with an invalid recovery id since the 27/28 normalization. `SignWithAccessKeyEnvelope` now writes a secp256k1 inner recovery id as 27/28, as `SignWithAccessKey` does. (by @brendanjryan, [#137](https://github.com/tempoxyz/tempo-go/pull/137))

## `github.com/tempoxyz/tempo-go@0.6.1`

First published 0.6.x release. Version 0.6.0 was prepared but not published.

### Minor Changes

- `BuildKeychainSignature` now returns `([]byte, error)` and rejects nil or over-32-byte R/S components instead of panicking or silently corrupting the signature. (by @BrendanRyan, [#93](https://github.com/tempoxyz/tempo-go/pull/93))
- Add T12 support: `Builder.SetExpiringNonce`, `ExpiringNonceKey`, and `Tx.IsExpiringNonce` for TIP-1106 expiring nonce discriminators, plus `EncodeTIP20BurnAtData`, `TIP20BurnAtSelector`, and `TIP20BurnAtRole` for TIP-1006 `burnAt`. (by @DerekCofausper, [#119](https://github.com/tempoxyz/tempo-go/pull/119))
- Add the `storagecredits` package with T7 bindings for the TIP-1060 storage credits precompile (`setMode`, `setBudget`, `balanceOf`, `modeOf`, `budgetOf`) and the StablecoinDEX `storageCredits(address)` view (TIP-1064). Update example fees to sit above the T7 dynamic base-fee cap (TIP-1067) and clarify that fees are denominated in attodollars per gas. (by @stevencartavia, [#73](https://github.com/tempoxyz/tempo-go/pull/73))
- Add a typed client query for the T8 CurrentCommittee precompile. (by @stevencartavia, [#78](https://github.com/tempoxyz/tempo-go/pull/78))

### Patch Changes

- Fixed certificate verification for package-registry checks in the release workflow. (by @DerekCofausper, [#120](https://github.com/tempoxyz/tempo-go/pull/120))
- Prevent `Tx.Clone` from panicking when transaction or call `big.Int` fields are nil. (by @BrendanRyan, [#94](https://github.com/tempoxyz/tempo-go/pull/94))
- Restored live integration test compilation after switching keychain setup to transaction-embedded authorization. (by @DerekCofausper, [#101](https://github.com/tempoxyz/tempo-go/pull/101))
- Validate token amounts in `KeyRestrictions.Validate` and `UpdateSpendingLimit` so nil, negative, or over-uint256 values return an error instead of panicking inside ABI packing. (by @Alex, [#83](https://github.com/tempoxyz/tempo-go/pull/83))
- Refresh dependencies. (by @DerekCofausper, [#114](https://github.com/tempoxyz/tempo-go/pull/114))
- Restored live integration coverage for direct AccountKeychain authorization selectors. (by @DerekCofausper, [#103](https://github.com/tempoxyz/tempo-go/pull/103))
- `SendBatch` now surfaces a top-level JSON-RPC error object (returned when a whole batch is rejected) as a `*JSONRPCError`, instead of masking it behind a generic unmarshal error. (by @Salad, [#86](https://github.com/tempoxyz/tempo-go/pull/86))

## `github.com/tempoxyz/tempo-go@0.5.0`

### Minor Changes

- Add T5 AccountKeychain TIP-1053 witness bindings: `AuthorizeKeyWithWitness()`, `BurnKeyAuthorizationWitness()`, `IsKeyAuthorizationWitnessBurned()`, and matching selector constants.
- Add T5 integration coverage for key-authorization witness burn, read, and authorize flows gated by `TEMPO_HARDFORK=T5`. (by @figtracer, [#56](https://github.com/tempoxyz/tempo-go/pull/56))

### Patch Changes

- Accept legacy Ethereum recovery ID values `{27, 28}` in 65-byte secp256k1 signature envelopes during transaction deserialization, normalizing them to internal `yParity` `{0, 1}`. Structured RLP signature tuples remain strict and serialization continues to emit canonical `yParity` only. (by @BrendanRyan, [#57](https://github.com/tempoxyz/tempo-go/pull/57))
- Correlate JSON-RPC batch responses by request ID so reordered success and error responses remain associated with their requests. (by @BrendanRyan, [#75](https://github.com/tempoxyz/tempo-go/pull/75))
- Detect and remove only genuine fee-payer trailers, preserving transaction data that ends with the trailer marker. (by @BrendanRyan, [#76](https://github.com/tempoxyz/tempo-go/pull/76))
- Preserve the fee-payer sponsorship marker when cloning transactions so sender signing payloads remain valid. (by @BrendanRyan, [#77](https://github.com/tempoxyz/tempo-go/pull/77))
- Reject malformed fee-payer signature lists in transaction field 11 instead of accepting unsupported tuple shapes. (by @BrendanRyan, [#74](https://github.com/tempoxyz/tempo-go/pull/74))

## `github.com/tempoxyz/tempo-go@0.4.1`

### Patch Changes

- Reject non-canonical secp256k1 signatures during transaction deserialization and address recovery, preventing transaction hash malleability via legacy `V` values and high-S signatures. (by @BrendanRyan, [#49](https://github.com/tempoxyz/tempo-go/pull/49))

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.4.0] - 2026-04-10

### Added

- `CallScope`, `SelectorRule`, and `CallScopeBuilder` for scoping access keys to specific contracts, function selectors, and recipients
- `KeyRestrictions` builder with token spending limits, call scope allowlists, and `IsCallAllowed` validation
- `AuthorizeKey()`, `RevokeKey()`, `SetAllowedCalls()`, `RemoveAllowedCalls()`, and `UpdateSpendingLimit()` precompile call encoders
- `AuthorizeKeyT3Selector` constant for the T3+ `authorizeKey` ABI
- TIP-20 selector constants: `SelectorTransfer`, `SelectorApprove`, `SelectorTransferWithMemo`, `SelectorWildcard`
- Signature type constants: `SignatureTypeSecp256k1`, `SignatureTypeP256`, `SignatureTypeWebAuthn`

### Changed

- `client.GetNonce()` now accepts `*big.Int` instead of `uint64` for the nonce key parameter, enabling full 192-bit nonce key support as per the Tempo Transaction spec
- Integration tests use T3 `authorizeKey` ABI by default (set `TEMPO_HARDFORK=T2` for legacy)

## [0.2.0] - 2026-01-27

### Security

- Bumped go-ethereum from v1.13.5 to v1.16.8 to fix CVE-2026-22868 (GHSA-mq3p-rrmp-79jg), a high-severity DoS vulnerability via malicious p2p message

### Breaking Changes

- Minimum Go version is now 1.24 (previously 1.21). This is required by go-ethereum v1.16.8.

## [0.1.0] - 2025-06-15

- Initial release
