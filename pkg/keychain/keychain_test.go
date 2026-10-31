package keychain

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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

	keychainSig, err := BuildKeychainSignature(innerSig, rootAccount)
	if err != nil {
		t.Fatalf("BuildKeychainSignature: %v", err)
	}

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

	// Verify v is written as 27 + yParity, the form the node uses
	if keychainSig[85] != 27+yParity {
		t.Errorf("expected v %d, got %d", 27+yParity, keychainSig[85])
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

	keychainSig, err := BuildKeychainSignature(innerSig, rootAccount)
	if err != nil {
		t.Fatalf("BuildKeychainSignature: %v", err)
	}

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
	_, _, _, err := ParseKeychainSignature([]byte{0x04, 0x01, 0x02})
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

// computeSelector computes the 4-byte function selector from a canonical Solidity signature.
func computeSelector(sig string) string {
	hash := crypto.Keccak256([]byte(sig))
	return "0x" + hex.EncodeToString(hash[:4])
}

func TestFunctionSelectors(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		sig      string
	}{
		{"GetRemainingLimit", GetRemainingLimitSelector, "getRemainingLimit(address,address,address)"},
		{"AuthorizeKey", AuthorizeKeySelector, "authorizeKey(address,uint8,uint64,bool,(address,uint256)[])"},
		{"RevokeKey", RevokeKeySelector, "revokeKey(address)"},
		{"UpdateSpendingLimit", UpdateSpendingLimitSelector, "updateSpendingLimit(address,address,uint256)"},
		{"GetKey", GetKeySelector, "getKey(address,address)"},
		{"GetTransactionKey", GetTransactionKeySelector, "getTransactionKey()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeSelector(tt.sig)
			if got != tt.selector {
				t.Errorf("selector mismatch for %s: expected %s, got %s", tt.sig, tt.selector, got)
			}
		})
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
	if err := ValidateAccessKeySignature([]byte{0x04}); err == nil {
		t.Error("expected error for invalid length")
	}

	// Invalid type
	invalid := make([]byte, KeychainSignatureLength)
	invalid[0] = 0x01
	if err := ValidateAccessKeySignature(invalid); err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestParseKeychainSignature_RecoveryIDForms(t *testing.T) {
	root := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	sig, err := BuildKeychainSignature(signer.NewSignature(big.NewInt(1), big.NewInt(2), 1), root)
	if err != nil {
		t.Fatalf("BuildKeychainSignature: %v", err)
	}
	for v, wantYParity := range map[byte]uint8{0: 0, 1: 1, 27: 0, 28: 1} {
		sig[85] = v
		_, _, inner, err := ParseKeychainSignature(sig)
		if err != nil {
			t.Fatalf("v=%d: unexpected error: %v", v, err)
		}
		if inner.YParity != wantYParity {
			t.Errorf("v=%d: yParity = %d, want %d", v, inner.YParity, wantYParity)
		}
	}
	for _, v := range []byte{2, 26, 29, 0xff} {
		sig[85] = v
		if _, _, _, err := ParseKeychainSignature(sig); err == nil {
			t.Errorf("v=%d: expected error", v)
		}
	}
}

func TestBuildKeychainSignature_RecoveryIDForms(t *testing.T) {
	root := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	for yParity, want := range map[uint8]byte{0: 27, 1: 28, 27: 27, 28: 28} {
		sig, err := BuildKeychainSignature(signer.NewSignature(big.NewInt(1), big.NewInt(2), yParity), root)
		if err != nil {
			t.Fatalf("yParity=%d: unexpected error: %v", yParity, err)
		}
		if sig[85] != want {
			t.Errorf("yParity=%d: v = %d, want %d", yParity, sig[85], want)
		}
	}
	if _, err := BuildKeychainSignature(signer.NewSignature(big.NewInt(1), big.NewInt(2), 2), root); err == nil {
		t.Error("expected error for yParity 2")
	}
}

// TestSignWithAccessKey_ConformanceVector checks a keychain transaction against
// the tempo-conformance "keychain_access_key" vector (vectors/transactions.json),
// signed by viem/ox, whose hash is the one the node reports.
func TestSignWithAccessKey_ConformanceVector(t *testing.T) {
	const (
		wantRaw  = "0x76f8d2820539843b9aca00850ba43b7400831e8480f85ef85c9420c000000000000000000000000000000000000080b844a9059cbb000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000000000000000001c0800180808080c0b8560470505783416ca25a9b3bd1334da28240883f3c3bb1f7097d24130dcc5693f92112da92828524e58b7c761e46c2b3f26c33db063a50e06c5600aa18ce4675e3dfdc1a4d27cc060c21aabb25e37c50ffebbc707af91b"
		wantHash = "0x2068f675ce25c9c8e242f6295c4e9c64ed14673839d136e06ef659558e9e87e3"
	)
	root := common.HexToAddress("0x70505783416ca25a9b3bd1334da28240883f3c3b")
	accessKey, err := signer.NewSigner("0xa813b4a2d5ba0ac630e619a178ecd397d8d82e546bc60dbefc3be9e6bc3036e5")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	tx := transaction.NewBuilder(big.NewInt(1337)).
		SetGas(2000000).
		SetNonce(1).
		SetMaxFeePerGas(big.NewInt(50000000000)).
		SetMaxPriorityFeePerGas(big.NewInt(1000000000)).
		AddCall(common.HexToAddress("0x20c0000000000000000000000000000000000000"), big.NewInt(0),
			common.FromHex("0xa9059cbb000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000000000000000001")).
		Build()
	if err := SignWithAccessKey(tx, accessKey, root); err != nil {
		t.Fatalf("SignWithAccessKey: %v", err)
	}
	raw, err := transaction.Serialize(tx, nil)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if raw != wantRaw {
		t.Errorf("raw = %s\nwant %s", raw, wantRaw)
	}
	hash, err := tx.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if hash.Hex() != wantHash {
		t.Errorf("hash = %s, want %s", hash.Hex(), wantHash)
	}

	// The node also accepts a 0/1 inner v; decoding either form gives the node's hash.
	zeroOne := common.FromHex(wantRaw)
	if zeroOne[len(zeroOne)-1] != 27 {
		t.Fatalf("expected vector inner v 27, got %d", zeroOne[len(zeroOne)-1])
	}
	zeroOne[len(zeroOne)-1] = 0
	for _, in := range []string{wantRaw, "0x" + common.Bytes2Hex(zeroOne)} {
		decoded, err := transaction.Deserialize(in)
		if err != nil {
			t.Fatalf("Deserialize: %v", err)
		}
		hash, err := decoded.Hash()
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		if hash.Hex() != wantHash {
			t.Errorf("decoded hash = %s, want %s", hash.Hex(), wantHash)
		}
		gotKey, gotRoot, err := VerifyAccessKeySignature(decoded)
		if err != nil {
			t.Fatalf("VerifyAccessKeySignature: %v", err)
		}
		if gotKey != accessKey.Address() || gotRoot != root {
			t.Errorf("access key = %s, root = %s", gotKey.Hex(), gotRoot.Hex())
		}
	}
}
