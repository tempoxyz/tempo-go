package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/tempoxyz/tempo-go/pkg/client"
)

func TestFundingChecksTokenBalance(t *testing.T) {
	address := common.HexToAddress("0x1234")
	calls := 0
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, "eth_call", request.Method)
		var call map[string]string
		require.NoError(t, json.Unmarshal(request.Params[0], &call))
		require.Equal(t, nativeFeeToken.Hex(), call["to"])
		require.Equal(t, "0x70a082310000000000000000000000000000000000000000000000000000000000001234", call["data"])
		calls++
		result := "0x01"
		if calls == 1 {
			result = "0x00"
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}))
	}))
	defer rpc.Close()
	tc := testContext{t: t, ctx: context.Background(), client: client.New(rpc.URL)}
	tc.waitForBalance(address)
	require.Equal(t, 2, calls)
}
