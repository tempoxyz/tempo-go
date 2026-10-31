package signer

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// viemVectors are produced by viem's tempo Accounts (testdata/viem/gen.mjs),
// the TypeScript implementation mppx and wallets use.
type viemVectors struct {
	Hash              common.Hash    `json:"hash"`
	RPID              string         `json:"rpId"`
	Origin            string         `json:"origin"`
	P256Key           string         `json:"p256Key"`
	WebAuthnKey       string         `json:"webAuthnKey"`
	RootKey           string         `json:"rootKey"`
	RootAddress       common.Address `json:"rootAddress"`
	P256Address       common.Address `json:"p256Address"`
	WebAuthnAddress   common.Address `json:"webAuthnAddress"`
	P256PublicKey     hexutil.Bytes  `json:"p256PublicKey"`
	WebAuthnPublicKey hexutil.Bytes  `json:"webAuthnPublicKey"`
	P256Signature     hexutil.Bytes  `json:"p256Signature"`
	WebAuthnSignature hexutil.Bytes  `json:"webAuthnSignature"`
	P256AccessKey     hexutil.Bytes  `json:"p256AccessKeySignature"`
	WebAuthnAccessKey hexutil.Bytes  `json:"webAuthnAccessKeySignature"`
	P256KeychainV1    hexutil.Bytes  `json:"p256KeychainV1Signature"`
	WebAuthnMetadata  struct {
		AuthenticatorData hexutil.Bytes `json:"authenticatorData"`
		ClientDataJSON    string        `json:"clientDataJSON"`
	} `json:"webAuthnMetadata"`
}

func loadViemVectors(t testing.TB) viemVectors {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/viem/vectors.json")
	require.NoError(t, err)
	var v viemVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func viemSigners(t testing.TB, v viemVectors) (*P256Signer, *WebAuthnSigner) {
	t.Helper()
	p, err := NewP256Signer(v.P256Key)
	require.NoError(t, err)
	w, err := NewWebAuthnSigner(v.WebAuthnKey, v.RPID, v.Origin)
	require.NoError(t, err)
	return p, w
}

func TestViem_SignersMatchViemAccounts(t *testing.T) {
	v := loadViemVectors(t)
	p, w := viemSigners(t, v)

	assert.Equal(t, v.P256Address, p.Address())
	assert.Equal(t, v.WebAuthnAddress, w.Address())
	pk := p.PublicKey()
	assert.Equal(t, []byte(v.P256PublicKey), pk[:])
	wk := w.PublicKey()
	assert.Equal(t, []byte(v.WebAuthnPublicKey), wk[:])
	assert.Equal(t, KeyTypeP256, p.KeyType())
	assert.Equal(t, KeyTypeWebAuthn, w.KeyType())

	sig, err := p.SignEnvelope(v.Hash)
	require.NoError(t, err)
	assert.Equal(t, hexutil.Encode(v.P256Signature), hexutil.Encode(sig), "Account.fromP256")

	sig, err = w.SignEnvelope(v.Hash)
	require.NoError(t, err)
	assert.Equal(t, hexutil.Encode(v.WebAuthnSignature), hexutil.Encode(sig), "Account.fromHeadlessWebAuthn")

	authenticatorData, clientDataJSON := WebAuthnAssertion(v.Hash, v.RPID, v.Origin)
	assert.Equal(t, []byte(v.WebAuthnMetadata.AuthenticatorData), authenticatorData)
	assert.Equal(t, v.WebAuthnMetadata.ClientDataJSON, string(clientDataJSON))
}

func TestViem_AccessKeyEnvelopesMatchViem(t *testing.T) {
	v := loadViemVectors(t)
	p, w := viemSigners(t, v)
	for name, tt := range map[string]struct {
		signer EnvelopeSigner
		want   []byte
	}{
		"p256":     {p, v.P256AccessKey},
		"webauthn": {w, v.WebAuthnAccessKey},
	} {
		t.Run(name, func(t *testing.T) {
			inner, err := tt.signer.SignEnvelope(KeychainV2Hash(v.Hash, v.RootAddress))
			require.NoError(t, err)
			envelope, err := BuildKeychainEnvelope(SignatureTypeKeychainV2, v.RootAddress, inner)
			require.NoError(t, err)
			assert.Equal(t, hexutil.Encode(tt.want), hexutil.Encode(envelope))
		})
	}

	inner, err := p.SignEnvelope(v.Hash)
	require.NoError(t, err)
	envelope, err := BuildKeychainEnvelope(SignatureTypeKeychainV1, v.RootAddress, inner)
	require.NoError(t, err)
	assert.Equal(t, hexutil.Encode(v.P256KeychainV1), hexutil.Encode(envelope))
}

func TestViem_RecoverEveryVector(t *testing.T) {
	v := loadViemVectors(t)
	for name, tt := range map[string]struct {
		envelope []byte
		want     RecoveredSigner
	}{
		"p256":        {v.P256Signature, RecoveredSigner{Account: v.P256Address, KeyID: v.P256Address, KeyType: KeyTypeP256}},
		"webauthn":    {v.WebAuthnSignature, RecoveredSigner{Account: v.WebAuthnAddress, KeyID: v.WebAuthnAddress, KeyType: KeyTypeWebAuthn}},
		"p256 v2":     {v.P256AccessKey, RecoveredSigner{Account: v.RootAddress, KeyID: v.P256Address, KeyType: KeyTypeP256, Keychain: SignatureTypeKeychainV2}},
		"webauthn v2": {v.WebAuthnAccessKey, RecoveredSigner{Account: v.RootAddress, KeyID: v.WebAuthnAddress, KeyType: KeyTypeWebAuthn, Keychain: SignatureTypeKeychainV2}},
		"p256 v1":     {v.P256KeychainV1, RecoveredSigner{Account: v.RootAddress, KeyID: v.P256Address, KeyType: KeyTypeP256, Keychain: SignatureTypeKeychainV1}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RecoverEnvelope(v.Hash, tt.envelope)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			_, err = RecoverEnvelope(gethcrypto.Keccak256Hash([]byte("other")), tt.envelope)
			assert.ErrorIs(t, err, ErrInvalidEnvelope, "a signature over another hash")
		})
	}
}

// A V2 envelope binds the user address: rewrapping the inner signature for
// another account does not verify.
func TestRecoverEnvelope_KeychainV2BindsUser(t *testing.T) {
	v := loadViemVectors(t)
	envelope := append([]byte{}, v.P256AccessKey...)
	envelope[1] ^= 0xff
	_, err := RecoverEnvelope(v.Hash, envelope)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
}

func TestRecoverEnvelope_Secp256k1(t *testing.T) {
	s, err := NewSigner("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	require.NoError(t, err)
	hash := gethcrypto.Keccak256Hash([]byte("secp"))
	envelope, err := s.SignEnvelope(hash)
	require.NoError(t, err)
	require.Len(t, envelope, 65)

	got, err := RecoverEnvelope(hash, envelope)
	require.NoError(t, err)
	assert.Equal(t, RecoveredSigner{Account: s.Address(), KeyID: s.Address(), KeyType: KeyTypeSecp256k1}, got)

	legacy := append([]byte{}, envelope...)
	legacy[64] += 27
	got, err = RecoverEnvelope(hash, legacy)
	require.NoError(t, err, "v in 27/28 form")
	assert.Equal(t, s.Address(), got.Account)

	legacy[64] = 2
	_, err = RecoverEnvelope(hash, legacy)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)

	inner, err := s.SignEnvelope(KeychainV2Hash(hash, common.HexToAddress("0x01")))
	require.NoError(t, err)
	keychain, err := BuildKeychainEnvelope(SignatureTypeKeychainV2, common.HexToAddress("0x01"), inner)
	require.NoError(t, err)
	require.Len(t, keychain, 86)
	got, err = RecoverEnvelope(hash, keychain)
	require.NoError(t, err)
	assert.Equal(t, s.Address(), got.KeyID)
}

func TestRecoverEnvelope_P256PreHash(t *testing.T) {
	v := loadViemVectors(t)
	p, _ := viemSigners(t, v)
	digest := sha256.Sum256(v.Hash.Bytes())
	sig, err := p.Sign(digest[:])
	require.NoError(t, err)
	pk := p.PublicKey()
	envelope := append(append(append([]byte{SignatureTypeP256}, sig[:]...), pk[:]...), 1)

	got, err := RecoverEnvelope(v.Hash, envelope)
	require.NoError(t, err)
	assert.Equal(t, v.P256Address, got.Account)

	envelope[129] = 0
	_, err = RecoverEnvelope(v.Hash, envelope)
	assert.ErrorIs(t, err, ErrInvalidEnvelope, "the same signature without the pre-hash flag")
}

func TestRecoverEnvelope_RejectsInvalidP256(t *testing.T) {
	v := loadViemVectors(t)
	n := elliptic.P256().Params().N
	mutate := func(f func(b []byte)) []byte {
		b := append([]byte{}, v.P256Signature...)
		f(b)
		return b
	}
	cases := map[string][]byte{
		"high s": mutate(func(b []byte) {
			s := new(big.Int).SetBytes(b[33:65])
			new(big.Int).Sub(n, s).FillBytes(b[33:65])
		}),
		"off-curve key":     mutate(func(b []byte) { b[96] ^= 0x01 }),
		"point at infinity": mutate(func(b []byte) { clear(b[65:129]) }),
		"another key":       mutate(func(b []byte) { copy(b[65:129], v.WebAuthnPublicKey) }),
		"zero r":            mutate(func(b []byte) { clear(b[1:33]) }),
		"short":             v.P256Signature[:129],
		"long":              append(append([]byte{}, v.P256Signature...), 0),
		"unknown type":      mutate(func(b []byte) { b[0] = 0x07 }),
		"empty":             {},
		"type byte only":    {SignatureTypeP256},
	}
	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := RecoverEnvelope(v.Hash, envelope)
			assert.ErrorIs(t, err, ErrInvalidEnvelope)
		})
	}
}

// signedWebAuthn signs custom assertion data with the vectors' WebAuthn key,
// so each rejection below is caused by the rule it names, not the signature.
func signedWebAuthn(t *testing.T, w *WebAuthnSigner, authenticatorData, clientDataJSON []byte) []byte {
	t.Helper()
	message := WebAuthnMessageHash(authenticatorData, clientDataJSON)
	sig, err := w.Sign(message[:])
	require.NoError(t, err)
	pk := w.PublicKey()
	out := append([]byte{SignatureTypeWebAuthn}, authenticatorData...)
	out = append(out, clientDataJSON...)
	out = append(out, sig[:]...)
	return append(out, pk[:]...)
}

func TestRecoverEnvelope_WebAuthnRules(t *testing.T) {
	v := loadViemVectors(t)
	_, w := viemSigners(t, v)
	authenticatorData, clientDataJSON := WebAuthnAssertion(v.Hash, v.RPID, v.Origin)
	withFlags := func(flags byte) []byte {
		data := append([]byte{}, authenticatorData...)
		data[32] = flags
		return data
	}
	clientData := func(fields string) []byte { return []byte(fields) }
	challenge := base64URL(v.Hash.Bytes())

	valid := map[string][]byte{
		"viem":                signedWebAuthn(t, w, authenticatorData, clientDataJSON),
		"user present only":   signedWebAuthn(t, w, withFlags(webAuthnFlagUP), clientDataJSON),
		"user verified only":  signedWebAuthn(t, w, withFlags(webAuthnFlagUV), clientDataJSON),
		"extra client fields": signedWebAuthn(t, w, authenticatorData, clientData(`{"challenge":"`+challenge+`","type":"webauthn.get","origin":"https://x","other":1}`)),
	}
	for name, envelope := range valid {
		t.Run("accepts "+name, func(t *testing.T) {
			got, err := RecoverEnvelope(v.Hash, envelope)
			require.NoError(t, err)
			assert.Equal(t, v.WebAuthnAddress, got.Account)
		})
	}

	invalid := map[string][]byte{
		"no user presence":     signedWebAuthn(t, w, withFlags(0), clientDataJSON),
		"attested data":        signedWebAuthn(t, w, withFlags(webAuthnFlagUP|webAuthnFlagAT), clientDataJSON),
		"extension data":       signedWebAuthn(t, w, withFlags(webAuthnFlagUP|webAuthnFlagED), clientDataJSON),
		"webauthn.create":      signedWebAuthn(t, w, authenticatorData, clientData(`{"type":"webauthn.create","challenge":"`+challenge+`"}`)),
		"wrong challenge":      signedWebAuthn(t, w, authenticatorData, clientData(`{"type":"webauthn.get","challenge":"AAAA"}`)),
		"padded challenge":     signedWebAuthn(t, w, authenticatorData, clientData(`{"type":"webauthn.get","challenge":"`+challenge+`="}`)),
		"not json":             signedWebAuthn(t, w, authenticatorData, clientData("not json at all, but long enough to pass the length checks")),
		"data too short":       signedWebAuthn(t, w, authenticatorData[:36], clientData(`{"type":"webauthn.get","challenge":"x"}`)),
		"oversized":            signedWebAuthn(t, w, authenticatorData, append(clientDataJSON, make([]byte, MaxWebAuthnSignatureLength)...)),
		"tampered client data": func() []byte { b := append([]byte{}, v.WebAuthnSignature...); b[60] ^= 1; return b }(),
		"shorter than 128":     append([]byte{SignatureTypeWebAuthn}, make([]byte, 127)...),
	}
	for name, envelope := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := RecoverEnvelope(v.Hash, envelope)
			assert.ErrorIs(t, err, ErrInvalidEnvelope)
		})
	}
}

func TestBuildKeychainEnvelope_Validates(t *testing.T) {
	_, err := BuildKeychainEnvelope(0x05, common.Address{}, make([]byte, 65))
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
	_, err = BuildKeychainEnvelope(SignatureTypeKeychainV2, common.Address{}, make([]byte, 64))
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
	_, err = RecoverEnvelope(common.Hash{}, append([]byte{SignatureTypeKeychainV2}, make([]byte, 20)...))
	assert.ErrorIs(t, err, ErrInvalidEnvelope, "keychain without an inner signature")
}

func TestP256Signer_DeterministicLowS(t *testing.T) {
	v := loadViemVectors(t)
	p, _ := viemSigners(t, v)
	for i := 0; i < 256; i++ {
		hash := gethcrypto.Keccak256Hash([]byte{byte(i), byte(i >> 8)})
		a, err := p.SignEnvelope(hash)
		require.NoError(t, err)
		b, err := p.SignEnvelope(hash)
		require.NoError(t, err)
		require.Equal(t, a, b, "RFC 6979 signatures are deterministic")
		require.LessOrEqual(t, new(big.Int).SetBytes(a[33:65]).Cmp(p256HalfOrder), 0)
		got, err := RecoverEnvelope(hash, a)
		require.NoError(t, err)
		require.Equal(t, p.Address(), got.Account)
	}
}

func TestNewP256Signer_RejectsBadKeys(t *testing.T) {
	for _, key := range []string{"", "0x", "0x00", "0x" + "00" + "00000000000000000000000000000000000000000000000000000000000000", "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", "zz"} {
		_, err := NewP256Signer(key)
		assert.ErrorIs(t, err, ErrInvalidPrivateKey, key)
	}
}

func TestWebAuthnAssertion_EscapesOriginLikeJSONStringify(t *testing.T) {
	origin := "https://a.example/<&>\"q\""
	_, clientDataJSON := WebAuthnAssertion(common.Hash{}, "x", origin)
	assert.Contains(t, string(clientDataJSON), "<&>", "no HTML escaping, as JSON.stringify")
	var parsed struct{ Origin string }
	require.NoError(t, json.Unmarshal(clientDataJSON, &parsed))
	assert.Equal(t, origin, parsed.Origin)
}

// clientDataJSON variants, each signed correctly, that tempo-primitives'
// serde parsing accepts or rejects. The same table is checked against
// tempo-primitives (see TestWebAuthnClientDataMatchesTempo).
func webAuthnClientDataCases(challenge string) []struct {
	name   string
	json   string
	accept bool
} {
	return []struct {
		name   string
		json   string
		accept bool
	}{
		{"canonical", `{"type":"webauthn.get","challenge":"` + challenge + `"}`, true},
		{"reordered with unknown fields", `{"origin":"x","challenge":"` + challenge + `","n":[1,{"a":2}],"type":"webauthn.get"}`, true},
		{"whitespace", "{ \"type\" : \"webauthn.get\" ,\n \"challenge\" : \"" + challenge + "\" }\n", true},
		{"escaped unknown field", `{"type":"webauthn.get","challenge":"` + challenge + `","origin":"a\"b"}`, true},
		{"uppercase type key", `{"Type":"webauthn.get","challenge":"` + challenge + `"}`, false},
		{"uppercase challenge key", `{"type":"webauthn.get","CHALLENGE":"` + challenge + `"}`, false},
		{"duplicate challenge", `{"type":"webauthn.get","challenge":"AAAA","challenge":"` + challenge + `"}`, false},
		{"duplicate type", `{"type":"webauthn.create","type":"webauthn.get","challenge":"` + challenge + `"}`, false},
		{"escaped type value", `{"type":"webauthn\u002eget","challenge":"` + challenge + `"}`, false},
		{"escaped challenge value", `{"type":"webauthn.get","challenge":"` + fmt.Sprintf(`\u%04x`, challenge[0]) + challenge[1:] + `"}`, false},
		{"trailing data", `{"type":"webauthn.get","challenge":"` + challenge + `"}x`, false},
		{"missing challenge", `{"type":"webauthn.get","origin":"` + challenge + `"}`, false},
		{"numeric type", `{"type":1,"challenge":"` + challenge + `"}`, false},
		{"invalid utf-8 in an ignored value", "{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge + "\",\"o\":\"\xff\xfe\"}", true},
		{"invalid utf-8 in a key", "{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge + "\",\"\xff\":1}", false},
		{"control character in ignored value", "{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge + "\",\"o\":\"a\x01b\"}", false},
		{"NaN in ignored value", `{"type":"webauthn.get","challenge":"` + challenge + `","o":NaN}`, false},
		{"array form", `["webauthn.get","` + challenge + `"]`, true},
		{"array with extra element", `["webauthn.get","` + challenge + `",1]`, false},
		{"empty object", `{}`, false},
		{"null type", `{"type":null,"challenge":"` + challenge + `"}`, false},
		{"escaped key", `{"t\u0079pe":"webauthn.get","challenge":"` + challenge + `"}`, true},
		{"big number in ignored value", `{"type":"webauthn.get","challenge":"` + challenge + `","n":1e400}`, true},
		{"nested fields are ignored", `{"o":{"type":"webauthn.create","challenge":"x"},"type":"webauthn.get","challenge":"` + challenge + `"}`, true},
		{"fields only nested", `{"o":{"type":"webauthn.get","challenge":"` + challenge + `"}}`, false},
		{"nested array", `{"o":[{"type":"webauthn.create"}],"type":"webauthn.get","challenge":"` + challenge + `"}`, true},
		{"non-ascii digit in ignored number", `{"type":"webauthn.get","challenge":"` + challenge + `","n":1٣}`, false},
		{"non-ascii digit in ignored fraction", `{"type":"webauthn.get","challenge":"` + challenge + `","n":0.٣}`, false},
		{"lone surrogate escaped key", `{"type":"webauthn.get","challenge":"` + challenge + `","\ud800":1}`, false},
		{"lone low surrogate escaped key", `{"type":"webauthn.get","challenge":"` + challenge + `","\udc80":1}`, false},
		{"lone surrogate in ignored value", `{"type":"webauthn.get","challenge":"` + challenge + `","o":"\ud800"}`, true},
		{"escaped surrogate pair key", `{"type":"webauthn.get","challenge":"` + challenge + `","\ud83d\ude00":1}`, true},
		{"leading zero in ignored number", `{"type":"webauthn.get","challenge":"` + challenge + `","n":01}`, false},
		{"plus sign in ignored number", `{"type":"webauthn.get","challenge":"` + challenge + `","n":+1}`, false},
		{"Infinity in ignored value", `{"type":"webauthn.get","challenge":"` + challenge + `","n":Infinity}`, false},
	}
}

func TestRecoverEnvelope_WebAuthnClientDataParsing(t *testing.T) {
	v := loadViemVectors(t)
	_, w := viemSigners(t, v)
	authenticatorData, _ := WebAuthnAssertion(v.Hash, v.RPID, v.Origin)
	for _, tc := range webAuthnClientDataCases(base64URL(v.Hash.Bytes())) {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RecoverEnvelope(v.Hash, signedWebAuthn(t, w, authenticatorData, []byte(tc.json)))
			if tc.accept {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrInvalidEnvelope)
			}
		})
	}
}

// TestWebAuthnClientDataMatchesTempo writes the cases above to
// $TEMPO_XCHECK_OUT so tempo-primitives can check them out of tree.
func TestWebAuthnClientDataMatchesTempo(t *testing.T) {
	out := os.Getenv("TEMPO_XCHECK_OUT")
	if out == "" {
		t.Skip("set TEMPO_XCHECK_OUT to export cases for tempo-primitives")
	}
	v := loadViemVectors(t)
	_, w := viemSigners(t, v)
	authenticatorData, _ := WebAuthnAssertion(v.Hash, v.RPID, v.Origin)
	type exported struct {
		Name     string `json:"name"`
		Envelope string `json:"envelope"`
		Accept   bool   `json:"accept"`
	}
	var cases []exported
	for _, tc := range webAuthnClientDataCases(base64URL(v.Hash.Bytes())) {
		cases = append(cases, exported{tc.name, hexutil.Encode(signedWebAuthn(t, w, authenticatorData, []byte(tc.json))), tc.accept})
	}
	raw, err := json.Marshal(map[string]any{"hash": v.Hash, "address": v.WebAuthnAddress, "cases": cases})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(out, raw, 0o600))
}

func TestWebAuthnSigner_RejectsOversizedAssertions(t *testing.T) {
	v := loadViemVectors(t)
	w, err := NewWebAuthnSigner(v.WebAuthnKey, v.RPID, "https://"+strings.Repeat("a", 2000))
	require.NoError(t, err)
	_, err = w.SignEnvelope(v.Hash)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
}
