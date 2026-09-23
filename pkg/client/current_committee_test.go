package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCommitteeMembersSelector(t *testing.T) {
	want := "0x" + hex.EncodeToString(crypto.Keccak256([]byte("getCommitteeMembers()"))[:4])
	assert.Equal(t, want, GetCommitteeMembersSelector)
}

func TestGetCommitteeMembers(t *testing.T) {
	wantEpoch := uint64(42)
	wantPublicKeys := [][32]byte{{0x11}, {0x22}}
	encoded, err := currentCommitteeABI.Methods["getCommitteeMembers"].Outputs.Pack(wantEpoch, wantPublicKeys)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "eth_call", req.Method)
		require.Len(t, req.Params, 2)
		callObject, ok := req.Params[0].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, CurrentCommitteeAddress, callObject["to"])
		assert.Equal(t, GetCommitteeMembersSelector, callObject["data"])
		assert.Equal(t, "latest", req.Params[1])

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(NewJSONRPCResponse(req.ID, "0x"+hex.EncodeToString(encoded))))
	}))
	defer server.Close()

	epoch, publicKeys, err := New(server.URL).GetCommitteeMembers(context.Background())
	require.NoError(t, err)
	assert.Equal(t, wantEpoch, epoch)
	assert.Equal(t, wantPublicKeys, publicKeys)
}
