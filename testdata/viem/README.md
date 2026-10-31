# viem reference vectors

`vectors.json` holds signatures, key authorizations and signed 0x76 transactions
produced by viem's tempo Accounts (`Account.fromP256`, `Account.fromHeadlessWebAuthn`,
access keys and `Account.signKeyAuthorization`). The Go tests require byte-for-byte
equality with them.

Regenerate with viem and the ox version it bundles:

```sh
npm i viem@2.57.13 ox@0.14.59
node gen.mjs
```

`webauthn_client_data.json` holds WebAuthn signatures over unusual clientDataJSON
encodings (key case, duplicates, escapes, invalid UTF-8, arrays, nesting) and
whether tempo-primitives 1.11.0 accepts each. tempo-go's
`TestWebAuthnClientDataMatchesTempo` exports it; the expectations were verified
against `TempoSignature::recover_signer`.
