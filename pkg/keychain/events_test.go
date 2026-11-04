package keychain

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestAdminKeyAuthorizedTopic(t *testing.T) {
	hash := crypto.Keccak256([]byte("AdminKeyAuthorized(address,address)"))
	got := "0x" + hex.EncodeToString(hash)
	if got != AdminKeyAuthorizedTopic {
		t.Errorf("topic mismatch: expected %s, got %s", AdminKeyAuthorizedTopic, got)
	}
}

func TestDecodeAdminKeyAuthorized(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")

	topics := []common.Hash{
		adminKeyAuthorizedTopic,
		common.BytesToHash(account.Bytes()),
		common.BytesToHash(keyID.Bytes()),
	}

	gotAccount, gotKey, err := DecodeAdminKeyAuthorized(topics)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAccount != account {
		t.Errorf("expected account %s, got %s", account.Hex(), gotAccount.Hex())
	}
	if gotKey != keyID {
		t.Errorf("expected keyID %s, got %s", keyID.Hex(), gotKey.Hex())
	}
}

func TestDecodeAdminKeyAuthorized_WrongTopicCount(t *testing.T) {
	if _, _, err := DecodeAdminKeyAuthorized([]common.Hash{adminKeyAuthorizedTopic}); err == nil {
		t.Error("expected error for wrong topic count")
	}
}

func TestDecodeAdminKeyAuthorized_WrongSignature(t *testing.T) {
	topics := []common.Hash{
		common.HexToHash("0xdeadbeef"),
		{},
		{},
	}
	if _, _, err := DecodeAdminKeyAuthorized(topics); err == nil {
		t.Error("expected error for wrong event signature")
	}
}
