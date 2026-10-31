package keychain

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

func testKeyID() common.Address {
	return common.HexToAddress("0x1111111111111111111111111111111111111111")
}

func TestKeyAuthorization_UnrestrictedEncodesThreeFields(t *testing.T) {
	auth := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID())

	fields, err := auth.encodeFields()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields for unrestricted auth, got %d", len(fields))
	}
}

func TestKeyAuthorization_WitnessPlaceholders(t *testing.T) {
	witness := common.HexToHash("0x5353535353535353535353535353535353535353535353535353535353535353")
	auth := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithWitness(witness)

	fields, err := auth.encodeFields()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// chain_id, key_type, key_id, expiry, limits, allowed_calls, witness
	if len(fields) != 7 {
		t.Fatalf("expected 7 fields, got %d", len(fields))
	}
	for i := 3; i <= 5; i++ {
		b, ok := fields[i].([]byte)
		if !ok || len(b) != 0 {
			t.Errorf("field %d should be an empty placeholder, got %v", i, fields[i])
		}
	}
	witnessBytes, ok := fields[6].([]byte)
	if !ok || !bytes.Equal(witnessBytes, witness.Bytes()) {
		t.Errorf("witness field mismatch: got %v", fields[6])
	}
}

func TestKeyAuthorization_ZeroWitnessDistinctFromAbsent(t *testing.T) {
	base := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID())
	zeroWitness := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithWitness(common.Hash{})

	baseHash, err := base.SignatureHash()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	zeroHash, err := zeroWitness.SignatureHash()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if baseHash == zeroHash {
		t.Error("zero witness should change the signature hash")
	}
}

func TestKeyAuthorization_AdminAndAccountBinding(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	other := common.HexToAddress("0x3333333333333333333333333333333333333333")

	normal := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID())
	admin := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).IntoAdmin(account)
	adminOther := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).IntoAdmin(other)

	normalHash, _ := normal.SignatureHash()
	adminHash, _ := admin.SignatureHash()
	adminOtherHash, _ := adminOther.SignatureHash()

	if normalHash == adminHash {
		t.Error("admin flag should change the signature hash")
	}
	if adminHash == adminOtherHash {
		t.Error("account binding should change the signature hash")
	}
}

func TestKeyAuthorization_IsAdminMarker(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	auth := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).IntoAdmin(account)

	fields, err := auth.encodeFields()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// chain_id, key_type, key_id, expiry, limits, allowed_calls, witness, is_admin, account
	if len(fields) != 9 {
		t.Fatalf("expected 9 fields, got %d", len(fields))
	}
	adminMarker, ok := fields[7].([]byte)
	if !ok || !bytes.Equal(adminMarker, []byte{0x01}) {
		t.Errorf("is_admin marker should be 0x01, got %v", fields[7])
	}
}

func TestKeyAuthorization_LimitsNoneVsEmpty(t *testing.T) {
	none := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID())
	noSpending := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithNoSpending()

	noneFields, _ := none.encodeFields()
	if len(noneFields) != 3 {
		t.Fatalf("None limits should be omitted (3 fields), got %d", len(noneFields))
	}

	emptyFields, _ := noSpending.encodeFields()
	if len(emptyFields) != 5 {
		t.Fatalf("Some([]) limits should produce 5 fields, got %d", len(emptyFields))
	}
	// Field 4 is limits; must be an empty list (not an empty byte string).
	if _, ok := emptyFields[4].([]interface{}); !ok {
		t.Errorf("empty limits should encode as an RLP list, got %T", emptyFields[4])
	}
}

func TestKeyAuthorization_TokenLimitPeriodOmittedWhenZero(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	noPeriod := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).
		WithLimits([]TokenLimit{{Token: token, Amount: big.NewInt(100), Period: 0}})
	withPeriod := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).
		WithLimits([]TokenLimit{{Token: token, Amount: big.NewInt(100), Period: 3600}})

	noPeriodFields, _ := noPeriod.encodeFields()
	limits := noPeriodFields[4].([]interface{})
	tuple := limits[0].([]interface{})
	if len(tuple) != 2 {
		t.Errorf("zero period should omit the third field, got %d fields", len(tuple))
	}

	withPeriodFields, _ := withPeriod.encodeFields()
	limits = withPeriodFields[4].([]interface{})
	tuple = limits[0].([]interface{})
	if len(tuple) != 3 {
		t.Errorf("non-zero period should include the third field, got %d fields", len(tuple))
	}
}

func TestKeyAuthorization_SignAndRecover(t *testing.T) {
	s, err := signer.NewSigner(rootKeyPrivate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	auth := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithExpiry(1000)

	signed, err := auth.Sign(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(signed) != 2 {
		t.Fatalf("signed authorization should have 2 elements, got %d", len(signed))
	}

	sigBytes, ok := signed[1].([]byte)
	if !ok || len(sigBytes) != secp256k1SignatureLength {
		t.Fatalf("expected %d-byte signature, got %v", secp256k1SignatureLength, signed[1])
	}

	hash, err := auth.SignatureHash()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := new(big.Int).SetBytes(sigBytes[0:32])
	sv := new(big.Int).SetBytes(sigBytes[32:64])
	yParity := sigBytes[64] - 27
	recovered, err := signer.RecoverAddress(hash, signer.NewSignature(r, sv, yParity))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recovered != s.Address() {
		t.Errorf("recovered %s, expected %s", recovered.Hex(), s.Address().Hex())
	}
}

func TestKeyAuthorization_SignAndAttachRoundtrip(t *testing.T) {
	s, err := signer.NewSigner(rootKeyPrivate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tx := transaction.NewDefault(42431)
	tx.MaxFeePerGas = big.NewInt(2000000000)
	tx.MaxPriorityFeePerGas = big.NewInt(1000000000)
	tx.Gas = 100000
	to := testKeyID()
	tx.Calls = []transaction.Call{{To: &to, Value: big.NewInt(0), Data: []byte{}}}

	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	auth := NewKeyAuthorization(42431, SignatureTypeSecp256k1, testKeyID()).IntoAdmin(account)
	if err := auth.SignAndAttach(tx, s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tx.KeyAuthorization == nil {
		t.Fatal("expected KeyAuthorization to be set")
	}
	if err := transaction.SignTransaction(tx, s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	serialized, err := transaction.Serialize(tx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	decoded, err := transaction.Deserialize(serialized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reserialized, err := transaction.Serialize(decoded, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if serialized != reserialized {
		t.Error("key authorization did not survive a serialize/deserialize round-trip")
	}
}

func TestKeyAuthorization_Validate(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	negative := new(big.Int).Neg(big.NewInt(1))
	over256 := new(big.Int).Lsh(big.NewInt(1), 256)

	tests := []struct {
		name string
		auth *KeyAuthorization
	}{
		{"invalid key type", NewKeyAuthorization(1, 9, testKeyID())},
		{"admin with expiry", NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).IntoAdmin(account).WithExpiry(1000)},
		{"nil limit amount", NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithLimits([]TokenLimit{{Token: token, Amount: nil}})},
		{"negative limit amount", NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithLimits([]TokenLimit{{Token: token, Amount: negative}})},
		{"limit amount over uint256", NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID()).WithLimits([]TokenLimit{{Token: token, Amount: over256}})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.auth.Validate(); err == nil {
				t.Errorf("expected validation error for %s", tt.name)
			}
		})
	}
}

func TestKeyAuthorization_BuildSignedRejectsBadSignature(t *testing.T) {
	auth := NewKeyAuthorization(1, SignatureTypeSecp256k1, testKeyID())

	if _, err := auth.BuildSigned([]byte{0x01, 0x02}); err == nil {
		t.Error("expected error for malformed signature bytes")
	}

	// A 65-byte secp256k1 signature with recovery id 0/1 (not 27/28) is rejected.
	bad := make([]byte, secp256k1SignatureLength)
	bad[64] = 1
	if _, err := auth.BuildSigned(bad); err == nil {
		t.Error("expected error for non-27/28 recovery id")
	}

	good := make([]byte, secp256k1SignatureLength)
	good[64] = 27
	if _, err := auth.BuildSigned(good); err != nil {
		t.Errorf("unexpected error for valid 65-byte signature: %v", err)
	}
}

func TestKeyAuthorization_SignAndAttachRejectsSignedTx(t *testing.T) {
	s, err := signer.NewSigner(rootKeyPrivate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tx := transaction.NewDefault(42431)
	tx.MaxFeePerGas = big.NewInt(2000000000)
	tx.MaxPriorityFeePerGas = big.NewInt(1000000000)
	tx.Gas = 100000
	to := testKeyID()
	tx.Calls = []transaction.Call{{To: &to, Value: big.NewInt(0), Data: []byte{}}}

	if err := transaction.SignTransaction(tx, s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	auth := NewKeyAuthorization(42431, SignatureTypeSecp256k1, testKeyID())
	if err := auth.SignAndAttach(tx, s); err == nil {
		t.Error("expected error when attaching to an already-signed transaction")
	}
}
