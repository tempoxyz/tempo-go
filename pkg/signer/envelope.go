package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Tempo signature types and envelope layout (tempo-primitives tt_signature.rs).
const (
	// KeyTypeSecp256k1, KeyTypeP256 and KeyTypeWebAuthn number key types as
	// Tempo's SignatureType does (key authorizations, the AccountKeychain).
	KeyTypeSecp256k1 uint8 = 0
	KeyTypeP256      uint8 = 1
	KeyTypeWebAuthn  uint8 = 2

	// SignatureTypeP256 prefixes a P256 signature envelope.
	SignatureTypeP256 byte = 0x01
	// SignatureTypeWebAuthn prefixes a WebAuthn signature envelope.
	SignatureTypeWebAuthn byte = 0x02
	// SignatureTypeKeychainV1 prefixes a legacy Keychain envelope, whose
	// inner signature signs the hash itself.
	SignatureTypeKeychainV1 byte = 0x03
	// SignatureTypeKeychainV2 prefixes a Keychain envelope, whose inner
	// signature signs keccak256(0x04 || hash || userAddress).
	SignatureTypeKeychainV2 byte = 0x04

	// P256SignatureLength is r || s || x || y || preHash.
	P256SignatureLength = 129
	// MaxWebAuthnSignatureLength bounds webauthnData || r || s || x || y.
	MaxWebAuthnSignatureLength = 2048

	secp256k1EnvelopeLength    = 65
	minAuthenticatorDataLength = 37

	webAuthnFlagUP = 0x01
	webAuthnFlagUV = 0x04
	webAuthnFlagAT = 0x40
	webAuthnFlagED = 0x80
)

// ErrInvalidEnvelope is returned for a malformed or unverifiable signature envelope.
var ErrInvalidEnvelope = errors.New("invalid signature envelope")

// RecoveredSigner is the signer of a verified Tempo signature envelope.
type RecoveredSigner struct {
	// Account is the account the signature acts for: the signer of a
	// primitive signature, or a Keychain envelope's user address.
	Account common.Address
	// KeyID is the key that signed: Account for a primitive signature, or
	// the access key inside a Keychain envelope.
	KeyID common.Address
	// KeyType is the signing key's type (KeyTypeSecp256k1, ...).
	KeyType uint8
	// Keychain is 0 for a primitive signature, or SignatureTypeKeychainV1
	// or SignatureTypeKeychainV2.
	Keychain byte
}

// RecoverEnvelope verifies a Tempo signature envelope over hash and returns
// its signer, as Tempo's TempoSignature::recover_signer does. P256 and
// WebAuthn signatures are checked cryptographically: low-s, a valid public
// key, and for WebAuthn the assertion rules. For a Keychain envelope it only
// proves that KeyID signed for Account: whether Account authorized KeyID is
// on-chain state (the AccountKeychain precompile) callers must check.
func RecoverEnvelope(hash common.Hash, envelope []byte) (RecoveredSigner, error) {
	if len(envelope) > 21 && len(envelope) != secp256k1EnvelopeLength &&
		(envelope[0] == SignatureTypeKeychainV1 || envelope[0] == SignatureTypeKeychainV2) {
		user := common.BytesToAddress(envelope[1:21])
		innerHash := hash
		if envelope[0] == SignatureTypeKeychainV2 {
			innerHash = KeychainV2Hash(hash, user)
		}
		keyID, keyType, err := RecoverPrimitive(innerHash, envelope[21:])
		if err != nil {
			return RecoveredSigner{}, err
		}
		return RecoveredSigner{Account: user, KeyID: keyID, KeyType: keyType, Keychain: envelope[0]}, nil
	}
	signer, keyType, err := RecoverPrimitive(hash, envelope)
	if err != nil {
		return RecoveredSigner{}, err
	}
	return RecoveredSigner{Account: signer, KeyID: signer, KeyType: keyType}, nil
}

// KeychainV2Hash returns keccak256(0x04 || hash || user), the digest a
// Keychain V2 access key signs.
func KeychainV2Hash(hash common.Hash, user common.Address) common.Hash {
	return gethcrypto.Keccak256Hash([]byte{SignatureTypeKeychainV2}, hash.Bytes(), user.Bytes())
}

// BuildKeychainEnvelope wraps an access key's primitive signature for user:
// version || user || inner. version is SignatureTypeKeychainV1 or V2.
func BuildKeychainEnvelope(version byte, user common.Address, inner []byte) ([]byte, error) {
	if version != SignatureTypeKeychainV1 && version != SignatureTypeKeychainV2 {
		return nil, fmt.Errorf("%w: unknown keychain version 0x%02x", ErrInvalidEnvelope, version)
	}
	if err := ValidatePrimitive(inner); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 21+len(inner))
	out = append(out, version)
	out = append(out, user.Bytes()...)
	return append(out, inner...), nil
}

// ValidatePrimitive checks the layout of a primitive signature: 65 bytes
// for secp256k1, 0x01 and 129 bytes for P256, or 0x02 and 128 to 2048 bytes
// for WebAuthn. It does not verify the signature.
func ValidatePrimitive(signature []byte) error {
	switch {
	case len(signature) == secp256k1EnvelopeLength:
		return nil
	case len(signature) < 2:
		return fmt.Errorf("%w: too short", ErrInvalidEnvelope)
	case signature[0] == SignatureTypeP256:
		if len(signature)-1 != P256SignatureLength {
			return fmt.Errorf("%w: invalid P256 signature length %d", ErrInvalidEnvelope, len(signature))
		}
		return nil
	case signature[0] == SignatureTypeWebAuthn:
		if n := len(signature) - 1; n < 128 || n > MaxWebAuthnSignatureLength {
			return fmt.Errorf("%w: invalid WebAuthn signature length %d", ErrInvalidEnvelope, len(signature))
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown signature type 0x%02x", ErrInvalidEnvelope, signature[0])
	}
}

// RecoverPrimitive verifies a primitive signature over hash and returns its
// signer and key type: the recovered secp256k1 address, or the address of the
// public key a P256 or WebAuthn signature carries.
func RecoverPrimitive(hash common.Hash, signature []byte) (common.Address, uint8, error) {
	if err := ValidatePrimitive(signature); err != nil {
		return common.Address{}, 0, err
	}
	if len(signature) == secp256k1EnvelopeLength {
		v := signature[64]
		if v >= 27 {
			v -= 27
		}
		if v > 1 {
			return common.Address{}, 0, fmt.Errorf("%w: invalid recovery id", ErrInvalidEnvelope)
		}
		address, err := RecoverAddress(hash, NewSignature(
			new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:64]), v))
		if err != nil {
			return common.Address{}, 0, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
		}
		return address, KeyTypeSecp256k1, nil
	}
	data := signature[1:]
	if signature[0] == SignatureTypeP256 {
		digest := hash.Bytes()
		if data[128] != 0 {
			d := sha256.Sum256(digest)
			digest = d[:]
		}
		address, err := verifyP256(digest, data[:128])
		return address, KeyTypeP256, err
	}
	webAuthnData, sig := data[:len(data)-128], data[len(data)-128:]
	message, err := webAuthnMessage(webAuthnData, hash)
	if err != nil {
		return common.Address{}, 0, err
	}
	address, err := verifyP256(message[:], sig)
	return address, KeyTypeWebAuthn, err
}

// verifyP256 checks a low-s signature r || s || x || y over a 32-byte digest
// and returns keccak256(x || y)[12:].
func verifyP256(digest, data []byte) (common.Address, error) {
	r, s := new(big.Int).SetBytes(data[0:32]), new(big.Int).SetBytes(data[32:64])
	if s.Cmp(p256HalfOrder) > 0 {
		return common.Address{}, fmt.Errorf("%w: P256 signature has high s", ErrInvalidEnvelope)
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{0x04}, data[64:128]...))
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: invalid P256 public key", ErrInvalidEnvelope)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil || !ecdsa.VerifyASN1(key, digest, der) {
		return common.Address{}, fmt.Errorf("%w: P256 signature verification failed", ErrInvalidEnvelope)
	}
	var publicKey [64]byte
	copy(publicKey[:], data[64:128])
	return P256Address(publicKey), nil
}

// webAuthnMessage validates WebAuthn assertion data for challenge as Tempo
// does and returns the digest its key signed: user presence or verification
// set, no attested credential or extension data (so the authenticator data is
// exactly 37 bytes), and a clientDataJSON of type "webauthn.get" whose
// challenge is base64url(challenge).
func webAuthnMessage(data []byte, challenge common.Hash) ([32]byte, error) {
	if len(data) < minAuthenticatorDataLength+32 {
		return [32]byte{}, fmt.Errorf("%w: WebAuthn data too short", ErrInvalidEnvelope)
	}
	flags := data[32]
	if flags&(webAuthnFlagUP|webAuthnFlagUV) == 0 {
		return [32]byte{}, fmt.Errorf("%w: WebAuthn user presence flag not set", ErrInvalidEnvelope)
	}
	if flags&webAuthnFlagAT != 0 {
		return [32]byte{}, fmt.Errorf("%w: WebAuthn assertion has attested credential data", ErrInvalidEnvelope)
	}
	if flags&webAuthnFlagED != 0 {
		return [32]byte{}, fmt.Errorf("%w: WebAuthn extensions are not supported", ErrInvalidEnvelope)
	}
	authenticatorData, clientDataJSON := data[:minAuthenticatorDataLength], data[minAuthenticatorDataLength:]
	clientType, challengeValue, err := parseClientData(clientDataJSON)
	if err != nil {
		return [32]byte{}, err
	}
	if clientType != "webauthn.get" {
		return [32]byte{}, fmt.Errorf("%w: clientDataJSON type must be webauthn.get", ErrInvalidEnvelope)
	}
	if challengeValue != base64URL(challenge.Bytes()) {
		return [32]byte{}, fmt.Errorf("%w: WebAuthn challenge does not match", ErrInvalidEnvelope)
	}
	return WebAuthnMessageHash(authenticatorData, clientDataJSON), nil
}

// parseClientData reads the "type" and "challenge" fields of a
// clientDataJSON exactly as tempo-primitives' serde struct does: one JSON
// object with valid UTF-8 keys (or the two-element array serde also reads), field names matched exactly (not case-insensitively),
// unknown fields ignored, each of the two fields present once, and their
// values plain strings without escape sequences (serde borrows them).
func parseClientData(data []byte) (clientType, challenge string, err error) {
	invalid := func(reason string) (string, string, error) {
		return "", "", fmt.Errorf("%w: clientDataJSON %s", ErrInvalidEnvelope, reason)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	open, err := dec.Token()
	if err != nil || (open != json.Delim('{') && open != json.Delim('[')) {
		return invalid("is not a JSON object")
	}
	// serde also reads a struct from a sequence of its fields in order:
	// ["webauthn.get", "<challenge>"].
	if open == json.Delim('[') {
		var fields [2]string
		for i := range fields {
			var raw json.RawMessage
			if !dec.More() || dec.Decode(&raw) != nil || !plainJSONString(raw) {
				return invalid("array must hold the type and challenge strings")
			}
			fields[i] = string(raw[1 : len(raw)-1])
		}
		if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
			return invalid("array must hold exactly the type and challenge")
		}
		if _, err := dec.Token(); err != io.EOF {
			return invalid("has trailing data")
		}
		return fields[0], fields[1], nil
	}
	var haveType, haveChallenge bool
	for dec.More() {
		start := dec.InputOffset()
		keyToken, err := dec.Token()
		if err != nil {
			return invalid("is not valid JSON")
		}
		// serde validates the UTF-8 of every key (and of the two fields it
		// reads) but skips ignored values without validating them.
		if !utf8.Valid(data[start:dec.InputOffset()]) {
			return invalid("has a key that is not valid UTF-8")
		}
		key, _ := keyToken.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return invalid("is not valid JSON")
		}
		if key != "type" && key != "challenge" {
			continue
		}
		if !plainJSONString(raw) {
			return invalid("field " + key + " must be a string without escapes")
		}
		value := string(raw[1 : len(raw)-1])
		if key == "type" {
			if haveType {
				return invalid("has a duplicate type field")
			}
			haveType, clientType = true, value
		} else {
			if haveChallenge {
				return invalid("has a duplicate challenge field")
			}
			haveChallenge, challenge = true, value
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return invalid("is not valid JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalid("has trailing data")
	}
	if !haveType || !haveChallenge {
		return invalid("is missing type or challenge")
	}
	return clientType, challenge, nil
}

// plainJSONString reports whether raw is a JSON string serde can borrow:
// valid UTF-8 with no escape sequences.
func plainJSONString(raw []byte) bool {
	return len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' &&
		bytes.IndexByte(raw, '\\') < 0 && utf8.Valid(raw)
}

func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jsonString encodes s as a JSON string without escaping HTML characters,
// as JavaScript's JSON.stringify does.
func jsonString(s string) string {
	var buf jsonBuffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return string(buf[:len(buf)-1])
}

type jsonBuffer []byte

func (b *jsonBuffer) Write(p []byte) (int, error) { *b = append(*b, p...); return len(p), nil }

func parseDERSignature(der []byte) (*big.Int, *big.Int, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 {
		return nil, nil, errors.New("failed to decode P256 signature")
	}
	return sig.R, sig.S, nil
}
