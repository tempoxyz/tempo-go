import { createClient, http, walletActions, publicActions } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { tempoModerato } from 'viem/chains';
import { withFeePayer, tempoActions } from 'viem/tempo';
import { config } from './config.js';

async function main() {
  console.log('Tempo Fee Payer Client Example');
  console.log('RPC URL:', config.getCleanRpcUrl());
  console.log('Chain ID:', config.chainId);
  console.log('Fee Payer Server:', config.feePayerServerUrl);
  console.log('Fee Token:', config.alphaUsdAddress);

  const account = privateKeyToAccount(config.clientPrivateKey);
  console.log('Client address:', account.address);

  const chain = {
    ...tempoModerato,
    feeToken: config.alphaUsdAddress,
    rpcUrls: {
      default: {
        http: [config.getCleanRpcUrl()],
      },
    },
  };

  const client = createClient({
    account,
    chain,
    transport: withFeePayer(
      http(config.getCleanRpcUrl(), {
        fetchOptions: {
          headers: {
            Authorization: config.getAuthHeader(),
          },
        },
      }),
      http(config.feePayerServerUrl),
      { policy: 'sign-and-broadcast' }
    ),
  })
    .extend(publicActions)
    .extend(walletActions)
    .extend(tempoActions());

  const nonce = await client.getTransactionCount({ address: account.address });
  console.log('Current nonce:', nonce);

  console.log('Sending transaction via fee payer relay...');

  const hash = await client.sendTransaction({
    to: '0x0000000000000000000000000000000000000000',
    data: '0xdeadbeef',
    value: 0n,
    feeToken: config.alphaUsdAddress,
    feePayer: true,
  } as any);

  console.log('Transaction hash:', hash);
  console.log('Waiting for confirmation...');

  await client.waitForTransactionReceipt({ hash });

  const transaction = await client.getTransaction({ hash });
  console.log('Transaction confirmed!');
  if ('feePayer' in transaction && transaction.feePayer) {
    console.log('Fee payer address:', transaction.feePayer);
  }
}

main().catch(console.error);
