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

func TestFundingGasEstimation(t *testing.T) {
	for _, tt := range []struct {
		name     string
		result   any
		rpcError bool
		want     uint64
	}{
		{name: "fork storage costs", result: "0x1e8480", want: 2410000},
		{name: "small estimate", result: "0x5208", want: 35200},
		{name: "zero", result: "0x0"},
		{name: "malformed", result: "not-a-quantity"},
		{name: "wrong type", result: 123},
		{name: "overflow", result: "0xffffffffffffffff"},
		{name: "revert", rpcError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			from := common.HexToAddress("0x1234")
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					ID     json.RawMessage   `json:"id"`
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				require.Equal(t, "eth_estimateGas", request.Method)
				var tx struct {
					Type  string              `json:"type"`
					From  string              `json:"from"`
					Calls []map[string]string `json:"calls"`
				}
				require.NoError(t, json.Unmarshal(request.Params[0], &tx))
				require.Equal(t, "0x76", tx.Type)
				require.Equal(t, from.Hex(), tx.From)
				require.Len(t, tx.Calls, 4)
				for i, token := range []common.Address{nativeFeeToken, alphaUSD, betaUSD, thetaUSD} {
					require.Equal(t, map[string]string{"to": token.Hex(), "value": "0x0", "input": "0xaabb"}, tx.Calls[i])
				}
				response := map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": tt.result}
				if tt.rpcError {
					delete(response, "result")
					response["error"] = map[string]any{"code": 3, "message": "execution reverted"}
				}
				require.NoError(t, json.NewEncoder(w).Encode(response))
			}))
			defer rpc.Close()
			tc := testContext{ctx: context.Background(), client: client.New(rpc.URL)}
			gas, err := tc.estimateFundingGas(from, []byte{0xaa, 0xbb})
			if tt.want == 0 {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, gas)
		})
	}
}
