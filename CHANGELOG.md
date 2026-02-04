# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- `client.GetNonce()` now accepts `*big.Int` instead of `uint64` for the nonce key parameter, enabling full 192-bit nonce key support as per the Tempo Transaction spec.

## [0.2.0] - 2026-01-27

### Security

- Bumped go-ethereum from v1.13.5 to v1.16.8 to fix CVE-2026-22868 (GHSA-mq3p-rrmp-79jg), a high-severity DoS vulnerability via malicious p2p message

### Breaking Changes

- Minimum Go version is now 1.24 (previously 1.21). This is required by go-ethereum v1.16.8.

## [0.1.0] - 2025-06-15

- Initial release
