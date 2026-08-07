package keychain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/signer"
)

func TestBuildKeychainSignatureRejectsMalformedScalars(t *testing.T) {
	oversized := new(big.Int).Lsh(big.NewInt(1), 256)
	tests := []struct {
		name string
		sig  *signer.Signature
	}{
		{name: "nil signature"},
		{name: "nil R", sig: signer.NewSignature(nil, big.NewInt(1), 0)},
		{name: "nil S", sig: signer.NewSignature(big.NewInt(1), nil, 0)},
		{name: "oversized R", sig: signer.NewSignature(oversized, big.NewInt(1), 0)},
		{name: "oversized S", sig: signer.NewSignature(big.NewInt(1), oversized, 0)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if result, err := BuildKeychainSignature(test.sig, common.Address{}); err == nil {
				t.Fatalf("BuildKeychainSignature() = %x, nil; want error", result)
			}
		})
	}
}

func TestBuildKeychainSignatureRoundTrip(t *testing.T) {
	root := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	want := signer.NewSignature(big.NewInt(0x1234), big.NewInt(0x5678), 1)

	encoded, err := BuildKeychainSignature(want, root)
	if err != nil {
		t.Fatalf("BuildKeychainSignature() error = %v", err)
	}
	_, gotRoot, got, err := ParseKeychainSignature(encoded)
	if err != nil {
		t.Fatalf("ParseKeychainSignature() error = %v", err)
	}
	if gotRoot != root {
		t.Fatalf("ParseKeychainSignature() root = %s; want %s", gotRoot, root)
	}
	if got.R.Cmp(want.R) != 0 || got.S.Cmp(want.S) != 0 || got.YParity != want.YParity {
		t.Fatalf("ParseKeychainSignature() signature = %+v; want %+v", got, want)
	}
}
