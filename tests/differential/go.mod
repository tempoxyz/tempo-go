module github.com/tempoxyz/tempo-go/tests/differential

go 1.25.9

require (
	github.com/ethereum/go-ethereum v1.17.4
	github.com/jtraglia/dff v0.1.13-0.20260227192951-4af8c4f10a45
	github.com/tempoxyz/tempo-go v0.0.0
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/gen2brain/shm v0.1.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/tempoxyz/tempo-go => ../..
