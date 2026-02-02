import 'dotenv/config';

export class Config {
  readonly tempoRpcUrl: string;
  readonly tempoUsername: string;
  readonly tempoPassword: string;
  readonly feePayerServerUrl: string;
  readonly clientPrivateKey: `0x${string}`;
  readonly alphaUsdAddress: `0x${string}`;
  readonly chainId: number;

  constructor() {
    this.tempoRpcUrl = process.env.TEMPO_RPC_URL || 'https://rpc.moderato.tempo.xyz';
    this.chainId = parseInt(process.env.TEMPO_CHAIN_ID || '42431', 10);
    this.tempoUsername = process.env.TEMPO_USERNAME || '';
    this.tempoPassword = process.env.TEMPO_PASSWORD || '';
    this.feePayerServerUrl = process.env.FEE_PAYER_SERVER_URL || 'http://localhost:3000';
    
    const privateKey = process.env.TEMPO_CLIENT_PRIVATE_KEY;
    if (!privateKey) {
      throw new Error('TEMPO_CLIENT_PRIVATE_KEY environment variable is required');
    }
    this.clientPrivateKey = privateKey as `0x${string}`;
    this.alphaUsdAddress = (process.env.ALPHAUSD_ADDRESS || '0x20c0000000000000000000000000000000000001') as `0x${string}`;
  }

  /**
   * Returns the RPC URL with credentials removed (for use in transport)
   */
  getCleanRpcUrl(): string {
    return this.tempoRpcUrl.replace(/https?:\/\/[^@]+@/, 'https://');
  }

  /**
   * Returns the Basic Auth credentials string (username:password)
   */
  getCredentials(): string {
    return `${this.tempoUsername}:${this.tempoPassword}`;
  }

  /**
   * Returns the Base64 encoded Basic Auth header value
   */
  getAuthHeader(): string {
    return `Basic ${btoa(this.getCredentials())}`;
  }
}

export const config = new Config();
