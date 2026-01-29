package keychain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

// Test private keys (DO NOT USE IN PRODUCTION)
const (
	rootKeyPrivate   = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	accessKeyPrivate = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)

func TestBuildKeychainSignature(t *testing.T) {
	// Create a test signature
	r := new(big.Int)
	r.SetString("12345678901234567890123456789012345678901234567890", 10)
	s := new(big.Int)
	s.SetString("98765432109876543210987654321098765432109876543210", 10)
	yParity := uint8(0)

	innerSig := signer.NewSignature(r, s, yParity)
	rootAccount := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	keychainSig := BuildKeychainSignature(innerSig, rootAccount)

	// Verify length
	if len(keychainSig) != KeychainSignatureLength {
		t.Errorf("expected length %d, got %d", KeychainSignatureLength, len(keychainSig))
	}

	// Verify type byte
	if keychainSig[0] != KeychainSignatureType {
		t.Errorf("expected type 0x%02x, got 0x%02x", KeychainSignatureType, keychainSig[0])
	}

	// Verify root account
	recoveredRoot := common.BytesToAddress(keychainSig[1:21])
	if recoveredRoot != rootAccount {
		t.Errorf("expected root account %s, got %s", rootAccount.Hex(), recoveredRoot.Hex())
	}

	// Verify yParity
	if keychainSig[85] != yParity {
		t.Errorf("expected yParity %d, got %d", yParity, keychainSig[85])
	}
}

func TestParseKeychainSignature(t *testing.T) {
	// Build a signature first
	r := new(big.Int)
	r.SetString("12345678901234567890123456789012345678901234567890", 10)
	s := new(big.Int)
	s.SetString("98765432109876543210987654321098765432109876543210", 10)
	yParity := uint8(1)

	innerSig := signer.NewSignature(r, s, yParity)
	rootAccount := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	keychainSig := BuildKeychainSignature(innerSig, rootAccount)

	// Parse it back
	sigType, parsedRoot, parsedInner, err := ParseKeychainSignature(keychainSig)
	if err != nil {
		t.Fatalf("failed to parse keychain signature: %v", err)
	}

	if sigType != KeychainSignatureType {
		t.Errorf("expected type 0x%02x, got 0x%02x", KeychainSignatureType, sigType)
	}

	if parsedRoot != rootAccount {
		t.Errorf("expected root %s, got %s", rootAccount.Hex(), parsedRoot.Hex())
	}

	if parsedInner.R.Cmp(r) != 0 {
		t.Errorf("R mismatch: expected %s, got %s", r.String(), parsedInner.R.String())
	}

	if parsedInner.S.Cmp(s) != 0 {
		t.Errorf("S mismatch: expected %s, got %s", s.String(), parsedInner.S.String())
	}

	if parsedInner.YParity != yParity {
		t.Errorf("yParity mismatch: expected %d, got %d", yParity, parsedInner.YParity)
	}
}

func TestParseKeychainSignature_InvalidLength(t *testing.T) {
	_, _, _, err := ParseKeychainSignature([]byte{0x03, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for invalid length")
	}
}

func TestParseKeychainSignature_InvalidType(t *testing.T) {
	sig := make([]byte, KeychainSignatureLength)
	sig[0] = 0x01 // Wrong type

	_, _, _, err := ParseKeychainSignature(sig)
	if err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestSignWithAccessKey(t *testing.T) {
	// Create signers
	rootSigner, err := signer.NewSigner(rootKeyPrivate)
	if err != nil {
		t.Fatalf("failed to create root signer: %v", err)
	}

	accessKeySigner, err := signer.NewSigner(accessKeyPrivate)
	if err != nil {
		t.Fatalf("failed to create access key signer: %v", err)
	}

	rootAccount := rootSigner.Address()

	// Create a transaction
	recipient := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	tx := transaction.New()
	tx.ChainID = big.NewInt(42431)
	tx.Gas = 21000
	tx.MaxFeePerGas = big.NewInt(1000000000)
	tx.MaxPriorityFeePerGas = big.NewInt(1000000000)
	tx.Calls = []transaction.Call{
		{To: &recipient, Value: big.NewInt(1000000)},
	}

	// Sign with access key
	err = SignWithAccessKey(tx, accessKeySigner, rootAccount)
	if err != nil {
		t.Fatalf("failed to sign with access key: %v", err)
	}

	// Verify the signature is a keychain signature
	if tx.Signature == nil {
		t.Fatal("signature is nil")
	}

	if tx.Signature.Type != "keychain" {
		t.Errorf("expected signature type 'keychain', got '%s'", tx.Signature.Type)
	}

	if tx.Signature.Raw == nil {
		t.Fatal("raw signature is nil")
	}

	if len(tx.Signature.Raw) != KeychainSignatureLength {
		t.Errorf("expected raw signature length %d, got %d", KeychainSignatureLength, len(tx.Signature.Raw))
	}

	// Verify the from address is set to root account
	if tx.From != rootAccount {
		t.Errorf("expected from %s, got %s", rootAccount.Hex(), tx.From.Hex())
	}
}

func TestVerifyAccessKeySignature(t *testing.T) {
	// Create signers
	rootSigner, err := signer.NewSigner(rootKeyPrivate)
	if err != nil {
		t.Fatalf("failed to create root signer: %v", err)
	}

	accessKeySigner, err := signer.NewSigner(accessKeyPrivate)
	if err != nil {
		t.Fatalf("failed to create access key signer: %v", err)
	}

	rootAccount := rootSigner.Address()
	expectedAccessKeyAddr := accessKeySigner.Address()

	// Create and sign a transaction
	recipient := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	tx := transaction.New()
	tx.ChainID = big.NewInt(42431)
	tx.Gas = 21000
	tx.MaxFeePerGas = big.NewInt(1000000000)
	tx.MaxPriorityFeePerGas = big.NewInt(1000000000)
	tx.Calls = []transaction.Call{
		{To: &recipient, Value: big.NewInt(1000000)},
	}

	err = SignWithAccessKey(tx, accessKeySigner, rootAccount)
	if err != nil {
		t.Fatalf("failed to sign with access key: %v", err)
	}

	// Verify the signature
	accessKeyAddr, recoveredRoot, err := VerifyAccessKeySignature(tx)
	if err != nil {
		t.Fatalf("failed to verify access key signature: %v", err)
	}

	if accessKeyAddr != expectedAccessKeyAddr {
		t.Errorf("expected access key address %s, got %s", expectedAccessKeyAddr.Hex(), accessKeyAddr.Hex())
	}

	if recoveredRoot != rootAccount {
		t.Errorf("expected root account %s, got %s", rootAccount.Hex(), recoveredRoot.Hex())
	}
}

func TestIsKeychainSignature(t *testing.T) {
	// Valid keychain signature
	validSig := make([]byte, KeychainSignatureLength)
	validSig[0] = KeychainSignatureType
	if !IsKeychainSignature(validSig) {
		t.Error("expected true for valid keychain signature")
	}

	// Wrong type
	wrongType := make([]byte, KeychainSignatureLength)
	wrongType[0] = 0x01
	if IsKeychainSignature(wrongType) {
		t.Error("expected false for wrong type")
	}

	// Wrong length
	wrongLength := make([]byte, 65)
	wrongLength[0] = KeychainSignatureType
	if IsKeychainSignature(wrongLength) {
		t.Error("expected false for wrong length")
	}
}

func TestGetKeychainAddress(t *testing.T) {
	addr := GetKeychainAddress()
	expected := common.HexToAddress(AccountKeychainAddress)
	if addr != expected {
		t.Errorf("expected %s, got %s", expected.Hex(), addr.Hex())
	}
}

func TestEncodeGetRemainingLimitCalldata(t *testing.T) {
	account := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	keyID := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	token := common.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906")

	calldata := EncodeGetRemainingLimitCalldata(account, keyID, token)

	// Should start with the selector
	if calldata[:10] != GetRemainingLimitSelector {
		t.Errorf("expected selector %s, got %s", GetRemainingLimitSelector, calldata[:10])
	}

	// Should be 10 (selector) + 64*3 (three addresses) = 202 chars
	expectedLen := 10 + 64*3
	if len(calldata) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(calldata))
	}
}

func TestValidateAccessKeySignature(t *testing.T) {
	// Valid signature
	valid := make([]byte, KeychainSignatureLength)
	valid[0] = KeychainSignatureType
	if err := ValidateAccessKeySignature(valid); err != nil {
		t.Errorf("unexpected error for valid signature: %v", err)
	}

	// Invalid length
	if err := ValidateAccessKeySignature([]byte{0x03}); err == nil {
		t.Error("expected error for invalid length")
	}

	// Invalid type
	invalid := make([]byte, KeychainSignatureLength)
	invalid[0] = 0x01
	if err := ValidateAccessKeySignature(invalid); err == nil {
		t.Error("expected error for invalid type")
	}
}
