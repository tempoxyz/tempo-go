package keychain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

func TestBuildKeychainSignature_RejectsBadScalars(t *testing.T) {
	root := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	oversized := new(big.Int).SetBytes(make([]byte, 33)) // needs a leading byte
	oversized.SetBit(oversized, 8*33-1, 1)               // 33 significant bytes

	cases := map[string]*signer.Signature{
		"nil R":       {R: nil, S: big.NewInt(1)},
		"nil S":       {R: big.NewInt(1), S: nil},
		"oversized R": {R: oversized, S: big.NewInt(1)},
		"oversized S": {R: big.NewInt(1), S: oversized},
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildKeychainSignature(sig, root); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestBuildKeychainSignature_NilSignature(t *testing.T) {
	if _, err := BuildKeychainSignature(nil, common.Address{}); err == nil {
		t.Fatal("expected error for nil signature")
	}
}

// A valid signature still round-trips through Parse.
func TestBuildKeychainSignature_ValidRoundTrip(t *testing.T) {
	root := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	sig := signer.NewSignature(big.NewInt(0x1234), big.NewInt(0x5678), 1)
	b, err := BuildKeychainSignature(sig, root)
	if err != nil {
		t.Fatal(err)
	}
	_, parsedRoot, inner, err := ParseKeychainSignature(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsedRoot != root {
		t.Fatalf("root mismatch: %s", parsedRoot.Hex())
	}
	if inner.R.Cmp(big.NewInt(0x1234)) != 0 || inner.S.Cmp(big.NewInt(0x5678)) != 0 {
		t.Fatalf("R/S mismatch: %s %s", inner.R, inner.S)
	}
}
