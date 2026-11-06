package receivepolicy

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func selector(sig string) string {
	return "0x" + hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4])
}

func TestReceivePolicySelectors(t *testing.T) {
	cases := map[string]string{
		"setReceivePolicy(uint64,uint64,address)":        SetReceivePolicySelector,
		"receivePolicy(address)":                         ReceivePolicySelector,
		"validateReceivePolicy(address,address,address)": ValidateReceivePolicySelector,
	}
	for sig, want := range cases {
		if got := selector(sig); got != want {
			t.Errorf("%s: expected %s, got %s", sig, want, got)
		}
	}
}

func TestSetReceivePolicyEncode(t *testing.T) {
	recovery := common.HexToAddress("0x1111111111111111111111111111111111111111")
	call, err := SetReceivePolicy(7, 9, recovery)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.To != tip403RegistryAddress {
		t.Errorf("unexpected target: %s", call.To.Hex())
	}
	if got := "0x" + hex.EncodeToString(call.Data[:4]); got != SetReceivePolicySelector {
		t.Errorf("expected selector %s, got %s", SetReceivePolicySelector, got)
	}
}

func TestParseReceivePolicyResult(t *testing.T) {
	recovery := common.HexToAddress("0x2222222222222222222222222222222222222222")
	want := ReceivePolicy{
		HasReceivePolicy:  true,
		SenderPolicyID:    11,
		SenderPolicyType:  PolicyTypeWhitelist,
		TokenFilterID:     22,
		TokenFilterType:   PolicyTypeBlacklist,
		RecoveryAuthority: recovery,
	}
	encoded, err := receivePolicyABI.Methods["receivePolicy"].Outputs.Pack(
		want.HasReceivePolicy, want.SenderPolicyID, want.SenderPolicyType,
		want.TokenFilterID, want.TokenFilterType, want.RecoveryAuthority,
	)
	if err != nil {
		t.Fatalf("failed to pack outputs: %v", err)
	}
	got, err := ParseReceivePolicyResult(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("expected %+v, got %+v", want, got)
	}

	for _, tc := range []struct {
		name   string
		result []byte
	}{
		{"short", encoded[:len(encoded)-1]},
		{"trailing data", append(append([]byte{}, encoded...), make([]byte, 32)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseReceivePolicyResult(tc.result); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParseValidateReceivePolicyResult(t *testing.T) {
	encoded, err := validateReceivePolicyABI.Methods["validateReceivePolicy"].Outputs.Pack(
		false, uint8(BlockedReasonTokenFilter),
	)
	if err != nil {
		t.Fatalf("failed to pack outputs: %v", err)
	}
	authorized, reason, err := ParseValidateReceivePolicyResult(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authorized {
		t.Error("expected authorized=false")
	}
	if reason != BlockedReasonTokenFilter {
		t.Errorf("expected reason %d, got %d", BlockedReasonTokenFilter, reason)
	}

	for _, tc := range []struct {
		name   string
		result []byte
	}{
		{"short", encoded[:len(encoded)-1]},
		{"trailing data", append(append([]byte{}, encoded...), make([]byte, 32)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseValidateReceivePolicyResult(tc.result); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestValidateReceivePolicyEncode(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	sender := common.HexToAddress("0x3333333333333333333333333333333333333333")
	receiver := common.HexToAddress("0x4444444444444444444444444444444444444444")
	call, err := ValidateReceivePolicy(token, sender, receiver)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.HasPrefix(call.Data, common.FromHex(ValidateReceivePolicySelector)) {
		t.Error("missing validateReceivePolicy selector")
	}
}
