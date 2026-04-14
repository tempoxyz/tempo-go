module github.com/tempoxyz/tempo-go/examples/feepayer

go 1.25.9

require (
	github.com/ethereum/go-ethereum v1.17.0
	github.com/joho/godotenv v1.5.1
	github.com/tempoxyz/tempo-go v0.0.0
)

replace github.com/tempoxyz/tempo-go => ../..

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
