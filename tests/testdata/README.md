# Counter fixture

The integration tests deploy a fresh Counter from Go, using `Counter.hex` as
creation bytecode. No Solidity toolchain is required to run the tests.

Regenerate with Foundry from the repository root:

```sh
forge build tests/testdata/Counter.sol --use 0.8.30 --evm-version paris --optimize true --optimizer-runs 200 --no-metadata --out /tmp/tempo-go-counter-out --cache-path /tmp/tempo-go-counter-cache
jq -r .bytecode.object /tmp/tempo-go-counter-out/Counter.sol/Counter.json > tests/testdata/Counter.hex
```
