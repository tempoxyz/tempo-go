
import { Account } from 'viem/tempo'
import { privateKeyToAccount } from 'viem/accounts'
import { P256, Hex, PublicKey, Address, WebAuthnP256, Hash } from 'ox'
const keccak256 = Hash.keccak256
import { SignatureEnvelope, TxEnvelopeTempo, KeyAuthorization } from 'ox/tempo'
import { writeFileSync } from 'node:fs'

const rootKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const p256Key = '0x' + '11'.repeat(32)
const p256Key2 = '0x' + '22'.repeat(32)
const hash = keccak256(Hex.fromString('tempo signature vectors'))
const rpId = 'localhost', origin = 'http://localhost'
const out = { hash, rpId, origin, p256Key, webAuthnKey: p256Key2, rootKey }

const root = Account.fromSecp256k1(rootKey)
out.rootAddress = root.address
const p256 = Account.fromP256(p256Key)
const wa = Account.fromHeadlessWebAuthn(p256Key2, { rpId, origin })
out.p256Address = p256.address
out.webAuthnAddress = wa.address
out.p256PublicKey = PublicKey.toHex(P256.getPublicKey({ privateKey: p256Key }), { includePrefix: false })
out.webAuthnPublicKey = PublicKey.toHex(P256.getPublicKey({ privateKey: p256Key2 }), { includePrefix: false })

out.p256Signature = await p256.sign({ hash })
out.webAuthnSignature = await wa.sign({ hash })
const waEnv = SignatureEnvelope.deserialize(out.webAuthnSignature)
out.webAuthnMetadata = waEnv.metadata

out.p256SignatureRpc = SignatureEnvelope.toRpc(SignatureEnvelope.deserialize(out.p256Signature))
out.webAuthnSignatureRpc = SignatureEnvelope.toRpc(SignatureEnvelope.deserialize(out.webAuthnSignature))
const p256Access = Account.fromP256(p256Key, { access: root })
const waAccess = Account.fromHeadlessWebAuthn(p256Key2, { rpId, origin, access: root })
out.p256AccessKeySignature = await p256Access.sign({ hash })
out.webAuthnAccessKeySignature = await waAccess.sign({ hash })
// Keychain V1 envelope (legacy) wrapping a P256 inner signature over the raw hash.
out.p256KeychainV1Signature = SignatureEnvelope.serialize(SignatureEnvelope.from({ type: 'keychain', version: 'v1', userAddress: root.address, inner: SignatureEnvelope.from(await p256.sign({ hash })) }))

for (const [name, acct] of [['p256', p256Access], ['webAuthn', waAccess]]) {
  const auth = await Account.signKeyAuthorization(root, { key: acct, chainId: 42431n, expiry: 4102444800 })
  out[name + 'KeyAuthorization'] = { serialized: KeyAuthorization.serialize(auth), rpc: KeyAuthorization.toRpc(auth) }
}

// A signed 0x76 transaction from a P256 root account and from a P256 access key.
const call = { to: '0x20c0000000000000000000000000000000000000', data: '0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f1b0f200000000000000000000000000000000000000000000000000000000000f4240', value: 0n }
const base = { chainId: 42431, calls: [call], gas: 300000n, maxFeePerGas: 20000000000n, maxPriorityFeePerGas: 1000000000n, nonce: 7n, nonceKey: 0n, feeToken: '0x20c0000000000000000000000000000000000000' }
for (const [name, acct, extra] of [['p256Root', p256, {}], ['webAuthnRoot', wa, {}], ['p256AccessKey', p256Access, { keyAuthorization: KeyAuthorization.deserialize(out.p256KeyAuthorization.serialized) }]]) {
  const env = TxEnvelopeTempo.from({ ...base, ...extra })
  const payload = TxEnvelopeTempo.getSignPayload(env)
  const signature = await acct.sign({ hash: payload })
  out[name + 'Transaction'] = { signPayload: payload, signature, serialized: TxEnvelopeTempo.serialize(env, { signature: SignatureEnvelope.from(signature) }), sender: acct.address }
}
writeFileSync('vectors.json', JSON.stringify(out, (k, v) => typeof v === 'bigint' ? v.toString() : v, 2))
console.log('ok', Object.keys(out).length)
