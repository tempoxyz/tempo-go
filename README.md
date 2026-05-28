<br>
<br>

<p align="center">
  <a href="https://tempo.xyz">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/tempoxyz/tempo/refs/heads/main/.github/assets/tempo-wordmark-white.svg">
      <img alt="Tempo wordmark" src="https://raw.githubusercontent.com/tempoxyz/tempo/refs/heads/main/.github/assets/tempo-wordmark-black.svg" width="360">
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
go get github.com/tempoxyz/tempo-go
```

### Go Version Requirements

| tempo-go version | Go version | Notes |
|------------------|------------|-------|
| v0.2.0+          | 1.24+      | Security fix for CVE-2026-22868 |
| v0.1.0           | 1.21+      | Vulnerable to CVE-2026-22868 (go-ethereum DoS) |

If you need Go 1.21-1.23 support, pin to v0.1.0:
```bash
go get github.com/tempoxyz/tempo-go@v0.1.0
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "math/big"

    "github.com/ethereum/go-ethereum/common"
    "github.com/tempoxyz/tempo-go/pkg/client"
    "github.com/tempoxyz/tempo-go/pkg/signer"
    "github.com/tempoxyz/tempo-go/pkg/transaction"
)

func main() {
    // Create RPC client
    c := client.New(transaction.RpcUrlModerato)

    s, _ := signer.NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")

    recipient := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
    amount := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)) // 10 AlphaUSD (18 decimals)
    transferData := buildERC20TransferData(recipient, amount)

    tx := transaction.NewDefault(transaction.ChainIdModerato)
    tx.MaxFeePerGas = big.NewInt(2000000000)
    tx.MaxPriorityFeePerGas = big.NewInt(1000000000)
    tx.Gas = 100000
    tx.Calls = []transaction.Call{{
        To:    &transaction.AlphaUSDAddress,
        Value: big.NewInt(0),
        Data:  transferData,
    }}

    transaction.SignTransaction(tx, s)

    serialized, _ := transaction.Serialize(tx, nil)
    hash, _ := c.SendRawTransaction(context.Background(), serialized)
    fmt.Printf("Transaction hash: %s\n", hash)
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
tx := transaction.NewDefault(transaction.ChainIdMainnet)
tx.MaxFeePerGas = big.NewInt(2000000000)
tx.MaxPriorityFeePerGas = big.NewInt(1000000000)
tx.Gas = 100000
tx.Calls = []transaction.Call{{
    To:    &transaction.AlphaUSDAddress,
    Value: big.NewInt(0),
    Data:  transferData, // ERC20 transfer calldata
}}

transaction.SignTransaction(tx, signer)

serialized, _ := transaction.Serialize(tx, nil)
client.SendRawTransaction(context.Background(), serialized)
```

### Sponsored Transaction

```go
tx := transaction.NewDefault(transaction.ChainIdMainnet)
transaction.SignTransaction(tx, userSigner)

transaction.AddFeePayerSignature(tx, feePayerSigner)

serialized, _ := transaction.Serialize(tx, nil)
client.SendRawTransaction(context.Background(), serialized)
```

### Batch Multiple Calls

```go
tx := transaction.NewDefault(transaction.ChainIdMainnet)
tx.Gas = 150000
tx.Calls = []transaction.Call{
    {To: &addr1, Value: big.NewInt(0), Data: transfer1Data},
    {To: &addr2, Value: big.NewInt(0), Data: transfer2Data},
    {To: &addr3, Value: big.NewInt(0), Data: contractCallData},
}

transaction.SignTransaction(tx, signer)
serialized, _ := transaction.Serialize(tx, nil)
client.SendRawTransaction(context.Background(), serialized)
```

### Transaction with Validity Window

```go
tx := transaction.NewDefault(transaction.ChainIdMainnet)
tx.ValidAfter = uint64(time.Now().Unix())
tx.ValidBefore = uint64(time.Now().Add(1 * time.Hour).Unix())

transaction.SignTransaction(tx, signer)
serialized, _ := transaction.Serialize(tx, nil)
client.SendRawTransaction(context.Background(), serialized)
```

## Packages

| Package       | Description                                        | Documentation                                                            |
|---------------|----------------------------------------------------|--------------------------------------------------------------------------|
| `transaction` | TempoTransaction encoding, signing, and validation | [GoDoc](https://pkg.go.dev/github.com/tempoxyz/tempo-go/pkg/transaction) |
| `client`      | RPC client for interacting with Tempo nodes        | [GoDoc](https://pkg.go.dev/github.com/tempoxyz/tempo-go/pkg/client)      |
| `signer`      | Key management and signature generation            | [GoDoc](https://pkg.go.dev/github.com/tempoxyz/tempo-go/pkg/signer)      |
| `keychain`    | Keychain-based transaction signing                 | [GoDoc](https://pkg.go.dev/github.com/tempoxyz/tempo-go/pkg/keychain)    |

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
# Opens at http://localhost:6060/pkg/github.com/tempoxyz/tempo-go/
```

Full API documentation is also available on [pkg.go.dev](https://pkg.go.dev/github.com/tempoxyz/tempo-go).

## Development Setup

### Prerequisites

- Go 1.24 or higher (see [Go Version Requirements](#go-version-requirements))
- Make

### Building

```bash
git clone https://github.com/tempoxyz/tempo-go.git
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

See [`SECURITY.md`](https://github.com/tempoxyz/tempo-go?tab=security-ov-file). Note: Tempo is still undergoing audit and does not have an active bug bounty. Submissions will not be eligible for a bounty until audits have concluded.

## License

Licensed under either of [Apache License](./LICENSE-APACHE), Version
2.0 or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these packages by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
