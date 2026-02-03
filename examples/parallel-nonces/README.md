# Parallel Nonces

## Overview

Demonstrates how to send multiple transactions in parallel using Tempo's 2D nonce system.

Traditional Ethereum transactions require sequential nonces, forcing you to wait for each transaction to be included before sending the next. Tempo's 2D nonce system solves this by allowing each "nonce key" to have its own independent sequence counter.

## How It Works

Each transaction has two nonce-related fields:
- **NonceKey**: A 192-bit sequence key that identifies which nonce lane to use
- **Nonce**: The current value within that lane

By using different nonce keys, you can send multiple transactions in parallel without waiting for confirmations. Each nonce key maintains its own independent sequence.

```
NonceKey 0: tx(nonce=0) → tx(nonce=1) → tx(nonce=2)
NonceKey 1: tx(nonce=0) → tx(nonce=1)              ← runs in parallel with key 0
NonceKey 2: tx(nonce=0)                            ← runs in parallel with keys 0 and 1
```

## Running

1. Copy the environment file and configure your settings:

```bash
cp env.example .env
```

2. Edit `.env` with your values:

```bash
TEMPO_PRIVATE_KEY=0x...        # Your private key
TEMPO_RECIPIENT_ADDRESS=0x...  # Recipient address
```

3. Run the example:

```bash
go run main.go
```

## Use Cases

- **High-throughput applications**: Send many transactions without waiting for confirmations
- **Batch operations**: Process multiple independent operations concurrently
- **Time-sensitive transactions**: Submit parallel transactions to reduce latency
