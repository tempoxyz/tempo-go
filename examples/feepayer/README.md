# Fee Payer Relay

## Overview

Example fee payer relay server that enables gasless transactions on Tempo.

The server accepts user-signed Type 0x76 transactions, adds its own fee payer signature, and broadcasts the dual-signed transaction to the network. This follows the "sign-and-broadcast" pattern described in the [Tempo fee sponsorship docs](https://docs.tempo.xyz/guide/payments/sponsor-user-fees).

## How It Works

```
┌──────────────────┐   1. User signs tx    ┌─────────────────────┐
│  TypeScript      │ ───────────────────►  │  Go Fee Payer       │
│  Client (viem)   │   (fee_token=empty)   │  Server             │
│                  │                       │                     │
│  feePayer: true  │   2. Returns tx hash  │  - Verifies sender  │
│                  │ ◄─────────────────── │  - Sets fee_token   │
└──────────────────┘                       │  - Signs as payer   │
                                           │  - Broadcasts       │
                                           └─────────────────────┘
```

## Running the Server

1. Copy the environment file and configure your settings:

```bash
cd examples/feepayer
cp env.example .env
```

1. Edit `.env` with your values:

```env
FEE_PAYER_PORT=3000
TEMPO_RPC_URL=https://rpc.moderato.tempo.xyz
TEMPO_USERNAME=your-username
TEMPO_PASSWORD=your-password
TEMPO_FEE_PAYER_PRIVATE_KEY=0x...
ALPHAUSD_ADDRESS=0x20c0000000000000000000000000000000000001
TEMPO_CHAIN_ID=42431
```

1. Run the server:

```bash
go run cmd/main.go
```

The server exposes `eth_sendRawTransaction` and `eth_sendRawTransactionSync` JSON-RPC methods on the configured port.

## Running the TypeScript Client

1. Install dependencies:

```bash
cd examples/feepayer/client
pnpm install
```

1. Configure `.env` in the client directory:

```env
TEMPO_CLIENT_PRIVATE_KEY=0x...
FEE_PAYER_SERVER_URL=http://localhost:3000
```

1. Run the client:

```bash
pnpm start
```

To type-check the code:

```bash
pnpm check
```
