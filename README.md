<br>
<br>

<p align="center">
  <a href="https://tempo.xyz">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/tempoxyz/.github/refs/heads/main/assets/combomark-dark.svg">
      <img alt="tempo combomark" src="https://raw.githubusercontent.com/tempoxyz/.github/refs/heads/main/assets/combomark-bright.svg" width="auto" height="120">
    </picture>
  </a>
</p>

<br>
<br>

# tempo-go

Go SDK for building applications on [Tempo](https://tempo.xyz)

**Contents**

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Example Usage](#example-usage)
- [Packages](#packages)
- [Testing](#testing)
- [Development Setup](#development-setup)

## Installation

```bash
go get github.com/tempo/tempo-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "math/big"

    "github.com/ethereum/go-ethereum/common"
    "github.com/tempo/tempo-go/pkg/client"
    "github.com/tempo/tempo-go/pkg/signer"
    "github.com/tempo/tempo-go/pkg/transaction"
)

func main() {
    // Create RPC client
    c, _ := client.New("https://rpc.testnet.tempo.xyz")

    s, _ := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")

    recipient := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
    amount := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)) // 10 AlphaUSD (18 decimals)
    transferData := buildERC20TransferData(recipient, amount)

    tx := transaction.New()
    tx.ChainID = big.NewInt(42429) // Tempo testnet
    tx.MaxFeePerGas = big.NewInt(2000000000)
    tx.MaxPriorityFeePerGas = big.NewInt(1000000000)
    tx.Gas = 100000
    tx.Calls = []transaction.Call{{
        To:    &transaction.AlphaUSDAddress,
        Value: big.NewInt(0),
        Data:  transferData,
    }}

    transaction.SignTransaction(tx, s)
    hash, _ := c.SendTransaction(tx)
    fmt.Printf("Transaction hash: %s\n", hash.Hex())
}

// buildERC20TransferData creates calldata for ERC20 transfer(address,uint256)
func buildERC20TransferData(to common.Address, amount *big.Int) []byte {
    // transfer(address,uint256) selector: 0xa9059cbb
    data := make([]byte, 68)
    data[0], data[1], data[2], data[3] = 0xa9, 0x05, 0x9c, 0xbb
    copy(data[16:36], to.Bytes())              // address (32 bytes, left-padded)
    amount.FillBytes(data[36:68])              // uint256 (32 bytes)
    return data
}
```

## Example Usage

| Use Case            | Example                                                      |
| ------------------- | ------------------------------------------------------------ |
| **Basic Transfer**  | [examples/simple-send](examples/simple-send)                 |
| **Fee Sponsorship** | [examples/feepayer](examples/feepayer)                       |
| **Batch Calls**     | See [transaction tests](pkg/transaction/transaction_test.go) |

### Basic Transfer

```go
tx := transaction.NewDefault(42429)
tx.MaxFeePerGas = big.NewInt(2000000000)
tx.MaxPriorityFeePerGas = big.NewInt(1000000000)
tx.Gas = 100000
tx.Calls = []transaction.Call{{
    To:    &transaction.AlphaUSDAddress,
    Value: big.NewInt(0),
    Data:  transferData, // ERC20 transfer calldata
}}

transaction.SignTransaction(tx, signer)

client.SendTransaction(tx)
```

### Sponsored Transaction

```go
tx := transaction.NewDefault(42429)
transaction.SignTransaction(tx, userSigner)

transaction.AddFeePayerSignature(tx, feePayerSigner)

client.SendTransaction(tx)
```

### Batch Multiple Calls

```go
tx := transaction.NewDefault(42429) // Tempo testnet
tx.Gas = 150000
tx.Calls = []transaction.Call{
    {To: &addr1, Value: big.NewInt(0), Data: transfer1Data},
    {To: &addr2, Value: big.NewInt(0), Data: transfer2Data},
    {To: &addr3, Value: big.NewInt(0), Data: contractCallData},
}

transaction.SignTransaction(tx, signer)
client.SendTransaction(tx)
```

### Transaction with Validity Window

```go
tx := transaction.NewDefault(42429) // Tempo testnet
tx.ValidAfter = uint64(time.Now().Unix())
tx.ValidBefore = uint64(time.Now().Add(1 * time.Hour).Unix())

transaction.SignTransaction(tx, signer)
client.SendTransaction(tx)
```

## Packages

| Package       | Description                                        | Documentation                                                    |
| ------------- | -------------------------------------------------- | ---------------------------------------------------------------- |
| `transaction` | TempoTransaction encoding, signing, and validation | [README](pkg/transaction/README.md)                              |
| `client`      | RPC client for interacting with Tempo nodes        | [GoDoc](https://pkg.go.dev/github.com/tempo/tempo-go/pkg/client) |
| `signer`      | Key management and signature generation            | [GoDoc](https://pkg.go.dev/github.com/tempo/tempo-go/pkg/signer) |

## Testing

### Run Unit Tests

```bash
make test
```

### Run Tests with Coverage

```bash
make test-coverage
```

### Run All Checks (format, vet, tests)

```bash
make check
```

### Run Integration Tests

```bash
# Start local Tempo node
docker-compose up -d

# Run integration tests
make integration

# Stop node
docker-compose down
```

### External Resources

- [Tempo Documentation](https://docs.tempo.xyz)

### API Reference

View documentation locally:

```bash
make docs
# Opens at http://localhost:6060/pkg/github.com/tempo/tempo-go/
```

Full API documentation is also available on [pkg.go.dev](https://pkg.go.dev/github.com/tempo/tempo-go).

## Development Setup

### Prerequisites

- Go 1.21 or higher
- Make

### Building

```bash
git clone https://github.com/tempo/tempo-go.git
cd tempo-go

go mod download

make check
```

### Running Examples

```bash
# Build all examples
make build_examples

# Run the simple-send example
./bin/simple-send

# Run the fee payer server
./bin/feepayer
```

### Code Formatting

```bash
make fix
```

## Contributing

Our contributor guidelines can be found in [`CONTRIBUTING.md`](https://github.com/tempoxyz/tempo?tab=contributing-ov-file).

## Security

See [`SECURITY.md`](https://github.com/tempoxyz/tempo?tab=security-ov-file). Note: Tempo is still undergoing audit and does not have an active bug bounty. Submissions will not be eligible for a bounty until audits have concluded.

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
