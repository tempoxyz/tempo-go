package client

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSendRawTransaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		var req JSONRPCRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		assert.Equal(t, "eth_sendRawTransaction", req.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := NewJSONRPCResponse(req.ID, "0xabc123def456")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	hash, err := client.SendRawTransaction(context.Background(), "0x76...")

	assert.NoError(t, err)
	assert.Equal(t, "0xabc123def456", hash)
}

func TestSignTransaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)

		var req JSONRPCRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		assert.Equal(t, "eth_signTransaction", req.Method)

		w.Header().Set("Content-Type", "application/json")
		// Return signed transaction in standard format
		result := map[string]interface{}{
			"raw": "0x76f87582a5b8830f42...",
			"tx":  map[string]interface{}{"hash": "0xabc123"},
		}
		resp := NewJSONRPCResponse(req.ID, result)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	txObj := map[string]interface{}{"to": "0x123", "value": "0x0"}
	signedTx, err := client.SignTransaction(context.Background(), txObj)

	assert.NoError(t, err)
	assert.Equal(t, "0x76f87582a5b8830f42...", signedTx)
}

func TestSignTransactionRawString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		w.Header().Set("Content-Type", "application/json")
		// Some implementations return the raw string directly
		resp := NewJSONRPCResponse(req.ID, "0x76f87582a5b8830f42...")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	txObj := map[string]interface{}{"to": "0x123"}
	signedTx, err := client.SignTransaction(context.Background(), txObj)

	assert.NoError(t, err)
	assert.Equal(t, "0x76f87582a5b8830f42...", signedTx)
}

func TestSendRawTransactionSync(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		w.Header().Set("Content-Type", "application/json")
		resp := NewJSONRPCResponse(req.ID, "0xsynchash123")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	hash, err := client.SendRawTransactionSync(context.Background(), "0x76...")

	assert.NoError(t, err)
	assert.Equal(t, "0xsynchash123", hash)
}

func TestSendRawTransactionContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow response
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		resp := NewJSONRPCResponse(1, "0xhash")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.SendRawTransaction(ctx, "0x76...")
	assert.Error(t, err, "expected timeout error")
}

func TestSendBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqs []JSONRPCRequest
		err := json.NewDecoder(r.Body).Decode(&reqs)
		assert.NoError(t, err)

		assert.Len(t, reqs, 2)

		w.Header().Set("Content-Type", "application/json")
		responses := []*JSONRPCResponse{
			NewJSONRPCResponse(reqs[0].ID, "0xhash1"),
			NewJSONRPCResponse(reqs[1].ID, "0xhash2"),
		}
		json.NewEncoder(w).Encode(responses)
	}))
	defer server.Close()

	client := New(server.URL)

	batch := NewBatchRequest()
	batch.Add("eth_sendRawTransaction", "0x76tx1")
	batch.Add("eth_sendRawTransaction", "0x76tx2")

	responses, err := client.SendBatch(context.Background(), batch)
	assert.NoError(t, err)

	assert.Len(t, responses, 2)
	assert.Equal(t, "0xhash1", responses[0].Result)
	assert.Equal(t, "0xhash2", responses[1].Result)
}

func TestWithOptions(t *testing.T) {
	t.Run("WithTimeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(1, "0xhash")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL, WithTimeout(10*time.Millisecond))

		_, err := client.SendRawTransaction(context.Background(), "0x76...")
		assert.Error(t, err, "expected timeout error")
	})

	t.Run("WithAuth", func(t *testing.T) {
		expectedUsername := "testuser"
		expectedPassword := "testpass"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			assert.True(t, ok, "expected basic auth header")
			assert.Equal(t, expectedUsername, username)
			assert.Equal(t, expectedPassword, password)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(1, "0xhash")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL, WithAuth(expectedUsername, expectedPassword))
		_, err := client.SendRawTransaction(context.Background(), "0x76...")
		assert.NoError(t, err)
	})

	t.Run("WithHTTPClient", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(1, "0xhash")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		customClient := &http.Client{
			Timeout: 5 * time.Second,
		}

		client := New(server.URL, WithHTTPClient(customClient))
		_, err := client.SendRawTransaction(context.Background(), "0x76...")
		assert.NoError(t, err)
	})
}

func TestErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		w.Header().Set("Content-Type", "application/json")
		resp := NewJSONRPCErrorResponse(req.ID, InternalError, "something went wrong", nil)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.SendRawTransaction(context.Background(), "0x76...")

	assert.Error(t, err)
	assert.Equal(t, "eth_sendRawTransaction: RPC error -32603: something went wrong", err.Error())
}

func TestNetworkError(t *testing.T) {
	client := New("http://invalid-host-that-does-not-exist:9999")
	_, err := client.SendRawTransaction(context.Background(), "0x76...")

	assert.Error(t, err)
}

func TestSendRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		assert.Equal(t, "eth_blockNumber", req.Method)

		w.Header().Set("Content-Type", "application/json")
		resp := NewJSONRPCResponse(req.ID, "0x12345")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	resp, err := client.SendRequest(context.Background(), "eth_blockNumber")

	assert.NoError(t, err)
	assert.Equal(t, "0x12345", resp.Result)
}

func TestRPCURL(t *testing.T) {
	client := New("https://rpc.example.com")

	assert.Equal(t, "https://rpc.example.com", client.RPCURL())
}

func TestBatchRequestBuilder(t *testing.T) {
	batch := NewBatchRequest()

	assert.Empty(t, batch.requests)

	batch.Add("method1", "param1", "param2")
	batch.Add("method2", 123, true)

	assert.Len(t, batch.requests, 2)
	assert.Equal(t, "method1", batch.requests[0].Method)
	assert.Equal(t, "method2", batch.requests[1].Method)
	assert.Equal(t, 1, batch.requests[0].ID)
	assert.Equal(t, 2, batch.requests[1].ID)
}

func TestJSONRPCResponses(t *testing.T) {
	t.Run("NewJSONRPCResponse", func(t *testing.T) {
		resp := NewJSONRPCResponse(42, "result_data")

		assert.Equal(t, "2.0", resp.JSONRPC)
		assert.Equal(t, 42, resp.ID)
		assert.Equal(t, "result_data", resp.Result)
		assert.Nil(t, resp.Error)
	})

	t.Run("NewJSONRPCErrorResponse", func(t *testing.T) {
		resp := NewJSONRPCErrorResponse(99, ParseError, "parse failed", map[string]interface{}{"detail": "bad json"})

		assert.Equal(t, "2.0", resp.JSONRPC)
		assert.Equal(t, 99, resp.ID)
		assert.NotNil(t, resp.Error)
		assert.Equal(t, ParseError, resp.Error.Code)
		assert.Equal(t, "parse failed", resp.Error.Message)
		assert.Nil(t, resp.Result)
	})
}

func TestParseHexUint64(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      uint64
		wantError bool
	}{
		{
			name:      "with 0x prefix",
			input:     "0x1a",
			want:      26,
			wantError: false,
		},
		{
			name:      "without 0x prefix",
			input:     "ff",
			want:      255,
			wantError: false,
		},
		{
			name:      "zero value",
			input:     "0x0",
			want:      0,
			wantError: false,
		},
		{
			name:      "large value",
			input:     "0xffffffffffffffff",
			want:      18446744073709551615,
			wantError: false,
		},
		{
			name:      "invalid hex",
			input:     "0xzzzz",
			want:      0,
			wantError: true,
		},
		{
			name:      "empty string",
			input:     "",
			want:      0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHexUint64(tt.input)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestGetTransactionCount(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			assert.Equal(t, "eth_getTransactionCount", req.Method)
			assert.Len(t, req.Params, 2)
			assert.Equal(t, "0x1234567890123456789012345678901234567890", req.Params[0])
			assert.Equal(t, "pending", req.Params[1])

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "0x2a") // 42 in hex
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		nonce, err := client.GetTransactionCount(context.Background(), "0x1234567890123456789012345678901234567890")

		assert.NoError(t, err)
		assert.Equal(t, uint64(42), nonce)
	})

	t.Run("zero nonce", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "0x0")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		nonce, err := client.GetTransactionCount(context.Background(), "0xabcd")

		assert.NoError(t, err)
		assert.Equal(t, uint64(0), nonce)
	})

	t.Run("rpc error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCErrorResponse(req.ID, InvalidParams, "invalid address", nil)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.GetTransactionCount(context.Background(), "invalid")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid address")
	})

	t.Run("invalid result type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, 12345) // number instead of hex string
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.GetTransactionCount(context.Background(), "0xabcd")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected result type")
	})
}

func TestGetNonce(t *testing.T) {
	t.Run("success with explicit nonce key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)

			assert.Equal(t, "eth_call", req.Method)
			assert.Len(t, req.Params, 2)
			callObject, ok := req.Params[0].(map[string]interface{})
			assert.True(t, ok)
			assert.Equal(t, nonceManagerAddress, callObject["to"])
			assert.Contains(t, callObject["data"], "0x89535803")
			assert.Equal(t, "latest", req.Params[1])

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "0x2a")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		nonce, err := client.GetNonce(context.Background(), "0x1234567890123456789012345678901234567890", big.NewInt(7))

		assert.NoError(t, err)
		assert.Equal(t, uint64(42), nonce)
	})

	t.Run("success with nil nonce key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			_ = json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "0x0")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		nonce, err := client.GetNonce(context.Background(), "0xabcd", nil)

		assert.NoError(t, err)
		assert.Equal(t, uint64(0), nonce)
	})

	t.Run("invalid result type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			_ = json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, 123)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.GetNonce(context.Background(), "0xabcd", big.NewInt(1))

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected result type")
	})
}

func TestGetBlockNumber(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			assert.Equal(t, "eth_blockNumber", req.Method)
			assert.Empty(t, req.Params)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "0x1234") // 4660 in hex
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		blockNumber, err := client.GetBlockNumber(context.Background())

		assert.NoError(t, err)
		assert.Equal(t, uint64(4660), blockNumber)
	})

	t.Run("zero block number", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "0x0")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		blockNumber, err := client.GetBlockNumber(context.Background())

		assert.NoError(t, err)
		assert.Equal(t, uint64(0), blockNumber)
	})

	t.Run("large block number", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "0xffffff") // 16777215 in hex
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		blockNumber, err := client.GetBlockNumber(context.Background())

		assert.NoError(t, err)
		assert.Equal(t, uint64(16777215), blockNumber)
	})

	t.Run("rpc error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCErrorResponse(req.ID, InternalError, "node error", nil)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.GetBlockNumber(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "node error")
	})

	t.Run("invalid result type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, true) // boolean instead of hex string
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.GetBlockNumber(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected result type")
	})
}

func TestGetTransactionReceipt(t *testing.T) {
	t.Run("receipt found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			assert.Equal(t, "eth_getTransactionReceipt", req.Method)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, map[string]interface{}{
				"transactionHash": "0xabc123",
				"status":          "0x1",
			})
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		receipt, err := client.GetTransactionReceipt(context.Background(), "0xabc123")

		assert.NoError(t, err)
		assert.Equal(t, "0xabc123", receipt["transactionHash"])
	})

	t.Run("receipt pending", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, nil)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		receipt, err := client.GetTransactionReceipt(context.Background(), "0xpending")

		assert.NoError(t, err)
		assert.Nil(t, receipt)
	})

	t.Run("empty receipt map treated as pending", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, map[string]interface{}{})
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		receipt, err := client.GetTransactionReceipt(context.Background(), "0xpending")

		assert.NoError(t, err)
		assert.Nil(t, receipt)
	})

	t.Run("invalid result type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "not-a-receipt")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.GetTransactionReceipt(context.Background(), "0xabc123")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected result type")
	})

	t.Run("rpc error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCErrorResponse(req.ID, InternalError, "receipt unavailable", nil)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.GetTransactionReceipt(context.Background(), "0xabc123")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "receipt unavailable")
	})
}

func TestWaitForReceipt(t *testing.T) {
	t.Run("waits until receipt appears", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			if calls == 1 {
				resp := NewJSONRPCResponse(req.ID, nil)
				json.NewEncoder(w).Encode(resp)
				return
			}
			resp := NewJSONRPCResponse(req.ID, map[string]interface{}{
				"transactionHash": "0xready",
				"status":          "0x1",
			})
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		receipt, err := client.WaitForReceipt(context.Background(), "0xready", time.Millisecond)

		assert.NoError(t, err)
		assert.Equal(t, "0xready", receipt["transactionHash"])
		assert.GreaterOrEqual(t, calls, 2)
	})

	t.Run("context timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, nil)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()

		_, err := client.WaitForReceipt(ctx, "0xpending", time.Millisecond)

		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("rpc error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCErrorResponse(req.ID, InternalError, "receipt fetch failed", nil)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.WaitForReceipt(context.Background(), "0xpending", time.Millisecond)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "receipt fetch failed")
	})

	t.Run("zero poll interval uses default path", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, map[string]interface{}{
				"transactionHash": "0xdefault",
				"status":          "0x1",
			})
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		receipt, err := client.WaitForReceipt(context.Background(), "0xdefault", 0)

		assert.NoError(t, err)
		assert.Equal(t, "0xdefault", receipt["transactionHash"])
	})
}

func TestGetChainID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			_ = json.NewDecoder(r.Body).Decode(&req)

			assert.Equal(t, "eth_chainId", req.Method)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, "0xa5af")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		chainID, err := client.GetChainID(context.Background())

		assert.NoError(t, err)
		assert.Equal(t, uint64(42415), chainID)
	})

	t.Run("invalid result type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			_ = json.NewDecoder(r.Body).Decode(&req)

			w.Header().Set("Content-Type", "application/json")
			resp := NewJSONRPCResponse(req.ID, false)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := New(server.URL)
		_, err := client.GetChainID(context.Background())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected result type")
	})
}

func TestSendBatch_EdgeCases(t *testing.T) {
	t.Run("empty batch", func(t *testing.T) {
		client := New("http://localhost:8545")
		batch := NewBatchRequest()

		responses, err := client.SendBatch(context.Background(), batch)

		assert.NoError(t, err)
		assert.Empty(t, responses)
	})

	t.Run("http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		}))
		defer server.Close()

		client := New(server.URL)
		batch := NewBatchRequest()
		batch.Add("eth_blockNumber")

		_, err := client.SendBatch(context.Background(), batch)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP error 500")
	})
}

func TestSendRequest_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service Unavailable"))
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.SendRequest(context.Background(), "eth_blockNumber")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP error 503")
	assert.Contains(t, err.Error(), "Service Unavailable")
}
