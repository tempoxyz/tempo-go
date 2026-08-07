package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// When a batch fails as a whole, a server may return a single JSON-RPC error
// object rather than an array. SendBatch must surface that error's code/message
// instead of an opaque "failed to unmarshal" message.
func TestSendBatch_TopLevelErrorObjectSurfaced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid batch"}}`))
	}))
	defer server.Close()

	batch := NewBatchRequest()
	batch.Add("eth_blockNumber")

	_, err := New(server.URL).SendBatch(context.Background(), batch)
	if err == nil {
		t.Fatal("expected an error for a top-level batch error object")
	}

	var rpcErr *JSONRPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected a *JSONRPCError to be surfaced, got: %v", err)
	}
	if rpcErr.Code != -32600 || rpcErr.Message != "invalid batch" {
		t.Fatalf("wrong error surfaced: code=%d msg=%q", rpcErr.Code, rpcErr.Message)
	}
}

// A genuinely malformed (non-JSON) body still returns the unmarshal error.
func TestSendBatch_MalformedBodyStillErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer server.Close()

	batch := NewBatchRequest()
	batch.Add("eth_blockNumber")

	if _, err := New(server.URL).SendBatch(context.Background(), batch); err == nil {
		t.Fatal("expected an error for a malformed batch body")
	}
}
