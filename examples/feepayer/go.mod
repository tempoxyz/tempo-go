module github.com/tempoxyz/tempo-go/examples/feepayer

go 1.21

require (
	github.com/joho/godotenv v1.5.1
	github.com/tempoxyz/tempo-go v0.0.0
)

replace github.com/tempoxyz/tempo-go => ../..

require (
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/ethereum/go-ethereum v1.13.5 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/holiman/uint256 v1.2.3 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)
