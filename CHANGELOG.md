# Changelog

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
