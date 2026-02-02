package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	methodSendRawTransaction     = "eth_sendRawTransaction"
	methodSendRawTransactionSync = "eth_sendRawTransactionSync"
	defaultTimeout               = 30 * time.Second
)

// Client is a basic HTTP client for interacting with the Tempo blockchain.
type Client struct {
	rpcURL     string
	username   string
	password   string
	httpClient *http.Client
}

// Option is a functional option for configuring the Client.
type Option func(*Client)

// WithAuth configures basic authentication for the client.
func WithAuth(username, password string) Option {
	return func(c *Client) {
		c.username = username
		c.password = password
	}
}

// WithTimeout configures the HTTP timeout for the client.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithHTTPClient configures a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// New creates a new Tempo RPC client with the given RPC URL.
// Optional configuration can be provided via Option functions.
func New(rpcURL string, opts ...Option) *Client {
	c := &Client{
		rpcURL: rpcURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// RPCURL returns the RPC URL configured for this client.
func (c *Client) RPCURL() string {
	return c.rpcURL
}

// SignTransaction signs a transaction without broadcasting it.
// Returns the signed transaction as a hex string that can be broadcast later.
// This is useful when you want to sign a transaction but broadcast it through a different channel.
func (c *Client) SignTransaction(ctx context.Context, tx interface{}) (string, error) {
	request := NewJSONRPCRequest(1, "eth_signTransaction", tx)

	response, err := c.sendRequest(ctx, request)
	if err != nil {
		return "", fmt.Errorf("failed to send eth_signTransaction request to %s: %w", c.rpcURL, err)
	}

	if err := response.CheckError(); err != nil {
		return "", fmt.Errorf("eth_signTransaction: %w", err)
	}

	result, ok := response.Result.(map[string]interface{})
	if !ok {
		// Try as string (some implementations may return the raw hex directly)
		if signedTx, ok := response.Result.(string); ok {
			return signedTx, nil
		}
		return "", fmt.Errorf("unexpected result type: %T", response.Result)
	}

	signedTx, ok := result["raw"].(string)
	if !ok {
		return "", fmt.Errorf("missing 'raw' field in response")
	}

	return signedTx, nil
}

// SendRawTransaction broadcasts a raw transaction to the Tempo network.
// The transaction should be a hex-encoded TempoTransaction starting with prefix "0x76".
func (c *Client) SendRawTransaction(ctx context.Context, serializedTx string) (string, error) {
	return c.SendRawTransactionWithMethod(ctx, methodSendRawTransaction, serializedTx)
}

// SendRawTransactionSync broadcasts a raw transaction synchronously to the Tempo network.
// This waits for the transaction to be included in a block before returning.
func (c *Client) SendRawTransactionSync(ctx context.Context, serializedTx string) (string, error) {
	return c.SendRawTransactionWithMethod(ctx, methodSendRawTransactionSync, serializedTx)
}

// SendRawTransactionWithMethod broadcasts a raw transaction using the specified method.
func (c *Client) SendRawTransactionWithMethod(ctx context.Context, method, serializedTx string) (string, error) {
	request := NewJSONRPCRequest(1, method, serializedTx)

	response, err := c.sendRequest(ctx, request)
	if err != nil {
		return "", fmt.Errorf("failed to send %s request to %s: %w", method, c.rpcURL, err)
	}

	if err := response.CheckError(); err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}

	txHash, ok := response.Result.(string)
	if !ok {
		return "", fmt.Errorf("unexpected result type: %T", response.Result)
	}

	return txHash, nil
}

// SendRequest sends a generic JSON-RPC request to the Tempo network.
func (c *Client) SendRequest(ctx context.Context, method string, params ...interface{}) (*JSONRPCResponse, error) {
	request := NewJSONRPCRequest(1, method, params...)
	return c.sendRequest(ctx, request)
}

func (c *Client) sendRequest(ctx context.Context, request *JSONRPCRequest) (*JSONRPCResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := c.newHTTPRequest(ctx, requestBody)
	if err != nil {
		return nil, err
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	responseBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d: %s", httpResp.StatusCode, string(responseBody))
	}

	var response JSONRPCResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// newHTTPRequest creates a new HTTP POST request with JSON content type and optional auth.
func (c *Client) newHTTPRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	return req, nil
}

// parseHexUint64 parses a hex string (with or without 0x prefix) to uint64.
func parseHexUint64(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
}

// GetTransactionCount gets the nonce for an address.
func (c *Client) GetTransactionCount(ctx context.Context, address string) (uint64, error) {
	response, err := c.SendRequest(ctx, "eth_getTransactionCount", address, "pending")
	if err != nil {
		return 0, err
	}
	if err := response.CheckError(); err != nil {
		return 0, err
	}
	nonceHex, ok := response.Result.(string)
	if !ok {
		return 0, fmt.Errorf("unexpected result type: %T", response.Result)
	}
	return parseHexUint64(nonceHex)
}

// GetBlockNumber gets the current block number.
// This is a useful proxy for making sure that the RPC is responsive.
func (c *Client) GetBlockNumber(ctx context.Context) (uint64, error) {
	response, err := c.SendRequest(ctx, "eth_blockNumber")
	if err != nil {
		return 0, err
	}
	if err := response.CheckError(); err != nil {
		return 0, err
	}
	blockNumHex, ok := response.Result.(string)
	if !ok {
		return 0, fmt.Errorf("unexpected result type: %T", response.Result)
	}
	return parseHexUint64(blockNumHex)
}

// GetChainID gets the chain ID from the connected node.
func (c *Client) GetChainID(ctx context.Context) (uint64, error) {
	response, err := c.SendRequest(ctx, "eth_chainId")
	if err != nil {
		return 0, err
	}
	if err := response.CheckError(); err != nil {
		return 0, err
	}
	chainIDHex, ok := response.Result.(string)
	if !ok {
		return 0, fmt.Errorf("unexpected result type: %T", response.Result)
	}
	return parseHexUint64(chainIDHex)
}

// SendBatch sends a batch of JSON-RPC requests to the Tempo network.
// This is more efficient than sending multiple individual requests.
// All requests are sent in a single HTTP request to reduce network overhead.
//
// Example:
//
//	batch := client.NewBatchRequest()
//	batch.Add("eth_blockNumber").
//	     Add("eth_getBalance", "0x...", "latest")
//	responses, err := client.SendBatch(ctx, batch)
func (c *Client) SendBatch(ctx context.Context, batch *BatchRequest) ([]*JSONRPCResponse, error) {
	if batch.Len() == 0 {
		return []*JSONRPCResponse{}, nil
	}

	requestBody, err := json.Marshal(batch.Requests())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %w", err)
	}

	httpReq, err := c.newHTTPRequest(ctx, requestBody)
	if err != nil {
		return nil, err
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send batch request: %w", err)
	}
	defer httpResp.Body.Close()

	responseBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read batch response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d: %s", httpResp.StatusCode, string(responseBody))
	}

	var responses []*JSONRPCResponse
	if err := json.Unmarshal(responseBody, &responses); err != nil {
		return nil, fmt.Errorf("failed to unmarshal batch response: %w", err)
	}

	return responses, nil
}
