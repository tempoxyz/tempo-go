# Rust compatibility checks

The oracle imports `tempo-primitives` at `07761a78a4ac00988533aa8acbcb6667786b625d`;
both clients use `jtraglia/dff` at `4af8c4f10a4509e0c91780dca5aac8f53696feed`.
Cargo.lock and go.sum pin their transitive dependencies.

```sh
cd tests/differential
go build -o ../../bin/tempo-dff .
cargo +stable build --locked --manifest-path rust/Cargo.toml
cd ../..
uv run tests/differential/run.py --cases 1000 --seconds 12
```

The runner first compares a deterministic corpus, then starts DFF with Go and
Rust clients. It waits for both clients before supplying cases, fails on early
exit/disagreement, and requires evidence that both clients participated. Logs
and DFF findings remain in the printed temporary directory. Runs are serialized
because upstream DFF uses a fixed socket and shared-memory keys. Linux/macOS
shared-memory limits must support DFF's 100 MiB segments.
The method name is padded to 64 bytes to match the pinned Rust client's
handshake; the Go callback trims that padding. Clients register sequentially
before the input barrier opens.

Each comparison includes canonical signed transaction bytes, sender signing
hash, fee-payer signing hash, and every delegation signing hash. Cases vary
256-bit nonce keys (including expiring nonces), zero/max chain IDs, 128-bit
fees, validity windows, batched calls/creation, access lists, absent/zero/nonzero
fee tokens, fee-payer signatures, Tempo authorization lists, inline access-key
authorizations, and secp256k1/P256/WebAuthn/keychain V1/V2 envelope encodings.
Signature fixtures test encoding, not cryptographic validity or execution.

This does not establish exhaustive protocol compatibility: unsigned fee-payer
service formats, malformed-input acceptance, cryptographic verification,
stateful precompile execution, RPC behavior and hardfork activation need
separate coverage. No network RPCs or transaction broadcasts are performed.

## Regenerate precompile ABIs

```sh
cargo +stable run --locked --manifest-path tests/differential/rust/Cargo.toml -- --abis > pkg/precompiles/contracts.json
go test -v ./pkg/precompiles
```

The export contains all 19 precompile interfaces exposed by the pinned Rust
`tempo-contracts` source, including functions, events, errors, fixed addresses,
and Rust-computed selectors. The Go test compares every function selector.
