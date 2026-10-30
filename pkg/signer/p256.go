package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// p256HalfOrder is n/2 for P-256. Tempo rejects P256 signatures with s > n/2.
var p256HalfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// EnvelopeSigner signs a 32-byte hash and returns a Tempo signature envelope:
// 65 bytes r || s || yParity for secp256k1, or a type byte and its data for
// P256 (0x01) and WebAuthn (0x02).
type EnvelopeSigner interface {
	// Address returns the account address of the signing key.
	Address() common.Address
	// KeyType returns the key type as Tempo's SignatureType numbers it:
	// 0 secp256k1, 1 P256, 2 WebAuthn.
	KeyType() uint8
	// SignEnvelope signs hash and returns the signature envelope bytes.
	SignEnvelope(hash common.Hash) ([]byte, error)
}

var (
	_ EnvelopeSigner = (*Signer)(nil)
	_ EnvelopeSigner = (*P256Signer)(nil)
	_ EnvelopeSigner = (*WebAuthnSigner)(nil)
)

// KeyType returns 0 (secp256k1).
func (s *Signer) KeyType() uint8 { return KeyTypeSecp256k1 }

// SignEnvelope signs hash and returns the 65-byte r || s || yParity envelope.
func (s *Signer) SignEnvelope(hash common.Hash) ([]byte, error) {
	sig, err := s.Sign(hash)
	if err != nil {
		return nil, err
	}
	out := make([]byte, secp256k1EnvelopeLength)
	sig.R.FillBytes(out[0:32])
	sig.S.FillBytes(out[32:64])
	out[64] = sig.YParity
	return out, nil
}

// P256Signer signs with a P-256 key, as viem's Account.fromP256: RFC 6979
// deterministic, low-s signatures over the hash itself.
type P256Signer struct {
	privateKey *ecdsa.PrivateKey
	publicKey  [64]byte
	address    common.Address
}

// NewP256Signer creates a P256 signer from a hex-encoded 32-byte private key.
func NewP256Signer(privateKeyHex string) (*P256Signer, error) {
	if !strings.HasPrefix(privateKeyHex, "0x") {
		privateKeyHex = "0x" + privateKeyHex
	}
	raw, err := hexutil.Decode(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode: %v", ErrInvalidPrivateKey, err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	return NewP256SignerFromKey(key)
}

// NewP256SignerFromKey creates a P256 signer from a P-256 private key.
func NewP256SignerFromKey(privateKey *ecdsa.PrivateKey) (*P256Signer, error) {
	if privateKey == nil || privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: not a P-256 key", ErrInvalidPrivateKey)
	}
	encoded, err := privateKey.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	s := &P256Signer{privateKey: privateKey}
	copy(s.publicKey[:], encoded[1:])
	s.address = P256Address(s.publicKey)
	return s, nil
}

// Address returns keccak256(x || y)[12:], the account of the public key.
func (s *P256Signer) Address() common.Address { return s.address }

// PublicKey returns the uncompressed public key coordinates x || y.
func (s *P256Signer) PublicKey() [64]byte { return s.publicKey }

// KeyType returns 1 (P256).
func (s *P256Signer) KeyType() uint8 { return KeyTypeP256 }

// Sign returns the low-s RFC 6979 signature r || s over digest.
func (s *P256Signer) Sign(digest []byte) ([64]byte, error) {
	var out [64]byte
	if len(digest) != 32 {
		return out, errors.New("P256 digest must be 32 bytes")
	}
	der, err := s.privateKey.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		return out, fmt.Errorf("failed to sign with P256 key: %w", err)
	}
	r, sv, err := parseDERSignature(der)
	if err != nil {
		return out, err
	}
	if sv.Cmp(p256HalfOrder) > 0 {
		sv.Sub(elliptic.P256().Params().N, sv)
	}
	r.FillBytes(out[:32])
	sv.FillBytes(out[32:])
	return out, nil
}

// SignEnvelope returns the 130-byte envelope 0x01 || r || s || x || y || 0x00
// (no pre-hash), as viem's Account.fromP256 signs.
func (s *P256Signer) SignEnvelope(hash common.Hash) ([]byte, error) {
	sig, err := s.Sign(hash.Bytes())
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+P256SignatureLength)
	out = append(out, SignatureTypeP256)
	out = append(out, sig[:]...)
	out = append(out, s.publicKey[:]...)
	return append(out, 0), nil
}

// P256Address returns the account of a P256 public key: keccak256(x || y)[12:].
func P256Address(publicKey [64]byte) common.Address {
	return common.BytesToAddress(gethcrypto.Keccak256(publicKey[:])[12:])
}

// WebAuthnSigner signs WebAuthn assertions with a P-256 key, as viem's
// Account.fromHeadlessWebAuthn does: the assertion's challenge is the hash.
type WebAuthnSigner struct {
	*P256Signer
	// RPID is the relying party ID, hashed into the authenticator data.
	RPID string
	// Origin is the clientDataJSON origin.
	Origin string
}

// NewWebAuthnSigner creates a headless WebAuthn signer.
func NewWebAuthnSigner(privateKeyHex, rpID, origin string) (*WebAuthnSigner, error) {
	key, err := NewP256Signer(privateKeyHex)
	if err != nil {
		return nil, err
	}
	return &WebAuthnSigner{P256Signer: key, RPID: rpID, Origin: origin}, nil
}

// KeyType returns 2 (WebAuthn).
func (s *WebAuthnSigner) KeyType() uint8 { return KeyTypeWebAuthn }

// SignEnvelope returns 0x02 || authenticatorData || clientDataJSON || r || s
// || x || y. The authenticator data is sha256(rpId) || 0x05 (user present
// and verified) || a zero counter, and the clientDataJSON is
// {"type":"webauthn.get","challenge":base64url(hash),"origin":origin,
// "crossOrigin":false}, byte for byte as ox's WebAuthnP256.getSignPayload.
func (s *WebAuthnSigner) SignEnvelope(hash common.Hash) ([]byte, error) {
	authenticatorData, clientDataJSON := WebAuthnAssertion(hash, s.RPID, s.Origin)
	message := WebAuthnMessageHash(authenticatorData, clientDataJSON)
	sig, err := s.Sign(message[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(authenticatorData)+len(clientDataJSON)+128)
	out = append(out, SignatureTypeWebAuthn)
	out = append(out, authenticatorData...)
	out = append(out, clientDataJSON...)
	out = append(out, sig[:]...)
	return append(out, s.publicKey[:]...), nil
}

// WebAuthnAssertion returns the authenticator data and clientDataJSON a
// headless WebAuthn signer produces for challenge.
func WebAuthnAssertion(challenge common.Hash, rpID, origin string) (authenticatorData, clientDataJSON []byte) {
	rpIDHash := sha256.Sum256([]byte(rpID))
	authenticatorData = append(rpIDHash[:], webAuthnFlagUP|webAuthnFlagUV, 0, 0, 0, 0)
	clientDataJSON = []byte(`{"type":"webauthn.get","challenge":"` +
		base64URL(challenge.Bytes()) + `","origin":` + jsonString(origin) + `,"crossOrigin":false}`)
	return authenticatorData, clientDataJSON
}

// WebAuthnMessageHash returns sha256(authenticatorData || sha256(clientDataJSON)),
// the digest a WebAuthn assertion's P256 key signs.
func WebAuthnMessageHash(authenticatorData, clientDataJSON []byte) [32]byte {
	clientDataHash := sha256.Sum256(clientDataJSON)
	return sha256.Sum256(append(append([]byte{}, authenticatorData...), clientDataHash[:]...))
}
