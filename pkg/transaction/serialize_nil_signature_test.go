package transaction

import (
	"math/big"
	"strings"
	"testing"

	"github.com/tempoxyz/tempo-go/pkg/signer"
)

// A directly-assembled Tx whose fee-payer signature has a nil R or S must not
// crash Serialize with a nil-pointer panic; it must return an error instead.
func TestSerialize_FeePayerSignatureNilScalar(t *testing.T) {
	cases := map[string]*signer.Signature{
		"nil R": {R: nil, S: big.NewInt(1)},
		"nil S": {R: big.NewInt(1), S: nil},
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			tx := New()
			tx.ChainID = big.NewInt(4217)
			tx.FeePayerSignature = sig
			if _, err := Serialize(tx, nil); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}

// Same guarantee for the sender signature envelope.
func TestSerialize_SenderSignatureNilScalar(t *testing.T) {
	cases := map[string]*signer.Signature{
		"nil R": {R: nil, S: big.NewInt(1)},
		"nil S": {R: big.NewInt(1), S: nil},
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			tx := New()
			tx.ChainID = big.NewInt(4217)
			tx.Signature = &signer.SignatureEnvelope{Type: "secp256k1", Signature: sig}
			if _, err := Serialize(tx, nil); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}

// A valid fee-payer signature still serializes without error.
func TestSerialize_FeePayerSignatureValid(t *testing.T) {
	tx := New()
	tx.ChainID = big.NewInt(4217)
	tx.FeePayerSignature = &signer.Signature{R: big.NewInt(0x1234), S: big.NewInt(0x5678), YParity: 1}

	out, err := Serialize(tx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out, "0x76") {
		t.Fatalf("expected 0x76 prefix, got %q", out)
	}
}
