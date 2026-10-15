package server

import (
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

func TestRelayRejectsUnauthenticatedRequests(t *testing.T) {
	s := &FeePayerServer{authToken: strings.Repeat("a", 32)}
	for _, token := range []string{"", "Bearer wrong"} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not json"))
		req.Header.Set("Authorization", token)
		out := httptest.NewRecorder()
		s.handleFeePayerRelay(out, req)
		if out.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", out.Code)
		}
		if out.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("unexpected CORS permission")
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+s.authToken)
	req.Header.Set("Origin", "https://untrusted.example")
	out := httptest.NewRecorder()
	s.handleFeePayerRelay(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("status = %d", out.Code)
	}
}

func TestRelayTransactionPolicy(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	s := &FeePayerServer{chainID: 42431, tokenAddress: token.Hex()}
	for _, tc := range []struct {
		name   string
		change func(*transaction.Tx)
		valid  bool
	}{
		{"transfer", func(*transaction.Tx) {}, true},
		{"wrong chain", func(tx *transaction.Tx) { tx.ChainID = big.NewInt(4217) }, false},
		{"nil chain", func(tx *transaction.Tx) { tx.ChainID = nil }, false},
		{"zero gas", func(tx *transaction.Tx) { tx.Gas = 0 }, false},
		{"excess gas", func(tx *transaction.Tx) { tx.Gas = 2_000_001 }, false},
		{"excess fee", func(tx *transaction.Tx) { tx.MaxFeePerGas = big.NewInt(100_000_000_001) }, false},
		{"total fee", func(tx *transaction.Tx) { tx.Gas = 2_000_000; tx.MaxFeePerGas = big.NewInt(100_000_000_000) }, false},
		{"priority", func(tx *transaction.Tx) { tx.MaxPriorityFeePerGas = big.NewInt(2) }, false},
		{"creation", func(tx *transaction.Tx) { tx.Calls[0].To = nil }, false},
		{"wrong target", func(tx *transaction.Tx) { a := common.Address{}; tx.Calls[0].To = &a }, false},
		{"native value", func(tx *transaction.Tx) { tx.Calls[0].Value = big.NewInt(1) }, false},
		{"selector", func(tx *transaction.Tx) { tx.Calls[0].Data[0] = 0 }, false},
		{"short data", func(tx *transaction.Tx) { tx.Calls[0].Data = nil }, false},
		{"key authorization", func(tx *transaction.Tx) { tx.KeyAuthorization = []interface{}{1} }, false},
		{"recipient padding", func(tx *transaction.Tx) { tx.Calls[0].Data[4] = 1 }, false},
		{"extra call", func(tx *transaction.Tx) { tx.Calls = append(tx.Calls, tx.Calls[0]) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 68)
			copy(data, []byte{0xa9, 0x05, 0x9c, 0xbb})
			tx := &transaction.Tx{ChainID: big.NewInt(42431), Gas: 100000, MaxFeePerGas: big.NewInt(1), MaxPriorityFeePerGas: big.NewInt(1), Calls: []transaction.Call{{To: &token, Data: data}}}
			tc.change(tx)
			err := s.validateTransaction(tx)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
		})
	}
}

func TestRelayRequestBodyLimit(t *testing.T) {
	s := &FeePayerServer{authToken: strings.Repeat("a", 32)}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat(" ", 64*1024+1)))
	req.Header.Set("Authorization", "Bearer "+s.authToken)
	out := httptest.NewRecorder()
	s.handleFeePayerRelay(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", out.Code)
	}
}

func TestConfigRequiresAuthentication(t *testing.T) {
	for _, token := range []string{"", "short", strings.Repeat("a", 32)} {
		c := &Config{AuthToken: token, AlphaUSDAddress: "0x20c0000000000000000000000000000000000001", TempoRPCURL: "http://localhost:8545", FeePayerPrivateKey: "test", Port: 3000, ChainID: 42431}
		if (c.Validate() == nil) != (len(token) >= 32) {
			t.Fatal("unexpected authentication validation")
		}
	}
}
