#!/bin/bash
set -e

echo "Starting Tempo node..."

tempo node --dev \
  --dev.block-time 1sec \
  --http \
  --http.addr 0.0.0.0 \
  --http.port 8545 \
  --http.api all \
  --chain dev \
  --faucet.enabled \
  --faucet.private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --faucet.amount 1000000000000000 \
  --faucet.address 0x20c0000000000000000000000000000000000000 &

NODE_PID=$!

echo "Tempo node started with PID $NODE_PID"
echo "Waiting for node to be ready..."

max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
  if curl -s -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' > /dev/null 2>&1; then
    echo "Node is ready!"
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done

if [ $attempt -eq $max_attempts ]; then
  echo "ERROR: Node failed to start within $max_attempts seconds"
  kill $NODE_PID
  exit 1
fi

echo ""
echo "Tempo node is running and ready to accept connections"

wait $NODE_PID
