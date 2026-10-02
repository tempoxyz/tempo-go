package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadBoundedAcceptsBodyAtLimit(t *testing.T) {
	body, err := readBounded(strings.NewReader(strings.Repeat("a", maxResponseBodySize)))

	require.NoError(t, err)
	assert.Len(t, body, maxResponseBodySize)
}

func TestReadBoundedRejectsOversizedBody(t *testing.T) {
	_, err := readBounded(strings.NewReader(strings.Repeat("a", maxResponseBodySize+1)))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestSendRequestRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.Repeat("a", maxResponseBodySize+1))
	}))
	defer server.Close()

	_, err := New(server.URL).sendRequest(context.Background(), NewJSONRPCRequest(1, "eth_blockNumber"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestSendRequestRejectsOversizedErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, strings.Repeat("a", maxResponseBodySize+1))
	}))
	defer server.Close()

	_, err := New(server.URL).sendRequest(context.Background(), NewJSONRPCRequest(1, "eth_blockNumber"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read response body")
}

func TestSendRequestDecodesNormalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(NewJSONRPCResponse(req.ID, "0xabc123")))
	}))
	defer server.Close()

	response, err := New(server.URL).sendRequest(context.Background(), NewJSONRPCRequest(1, "eth_blockNumber"))

	require.NoError(t, err)
	assert.Equal(t, "0xabc123", response.Result)
}