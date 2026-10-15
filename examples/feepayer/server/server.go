package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/tempoxyz/tempo-go/pkg/client"
	"github.com/tempoxyz/tempo-go/pkg/signer"
	"github.com/tempoxyz/tempo-go/pkg/transaction"
)

const (
	methodSendRawTransaction     = "eth_sendRawTransaction"
	methodSendRawTransactionSync = "eth_sendRawTransactionSync"
)

// Config holds the configuration for the fee payer server.
type Config struct {
	Port      int
	AuthToken string

	TempoRPCURL   string
	TempoUsername string
	TempoPassword string

	FeePayerPrivateKey string
	AlphaUSDAddress    string
	ChainID            int
}

// LoadConfigFromEnv loads configuration from environment variables.
func LoadConfigFromEnv() (*Config, error) {
	_ = godotenv.Load()

	config := &Config{
		Port:               getEnvInt("FEE_PAYER_PORT", 3000),
		AuthToken:          getEnv("FEE_PAYER_AUTH_TOKEN", ""),
		TempoRPCURL:        getEnv("TEMPO_RPC_URL", "https://rpc.moderato.tempo.xyz"),
		TempoUsername:      getEnv("TEMPO_USERNAME", ""),
		TempoPassword:      getEnv("TEMPO_PASSWORD", ""),
		FeePayerPrivateKey: getEnv("TEMPO_FEE_PAYER_PRIVATE_KEY", ""),
		AlphaUSDAddress:    getEnv("ALPHAUSD_ADDRESS", "0x20c0000000000000000000000000000000000001"),
		ChainID:            getEnvInt("TEMPO_CHAIN_ID", 42431),
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks that all required configuration values are set.
func (c *Config) Validate() error {
	if len(c.AuthToken) < 32 {
		return fmt.Errorf("FEE_PAYER_AUTH_TOKEN must contain at least 32 characters")
	}
	if !common.IsHexAddress(c.AlphaUSDAddress) {
		return fmt.Errorf("ALPHAUSD_ADDRESS must be a valid address")
	}
	if c.TempoRPCURL == "" {
		return fmt.Errorf("TEMPO_RPC_URL is required")
	}

	if c.FeePayerPrivateKey == "" {
		return fmt.Errorf("TEMPO_FEE_PAYER_PRIVATE_KEY is required")
	}

	if c.AlphaUSDAddress == "" {
		return fmt.Errorf("ALPHAUSD_ADDRESS is required")
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}

	if c.ChainID <= 0 {
		return fmt.Errorf("invalid chain ID: %d", c.ChainID)
	}

	return nil
}

// Print logs the configuration (excluding sensitive values).
func (c *Config) Print() {
	fmt.Println("Configuration:")
	fmt.Printf("Port: %d\n", c.Port)
	fmt.Printf("Tempo RPC URL: %s\n", c.TempoRPCURL)
	fmt.Printf("Tempo Username: %s\n", c.TempoUsername)
	fmt.Printf("AlphaUSD Address: %s\n", c.AlphaUSDAddress)
	fmt.Printf("Chain ID: %d\n", c.ChainID)
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}

	return intValue
}

// FeePayerServer is an HTTP server that acts as a fee payer relay.
// It receives client-signed Type 0x76 transactions, adds a fee payer signature,
// and broadcasts them to the Tempo network.
type FeePayerServer struct {
	port         int
	signer       *signer.Signer
	tempoClient  *client.Client
	tokenAddress string
	authToken    string
	chainID      int
}

// NewFeePayerServer creates a new fee payer relay server.
func NewFeePayerServer(cfg *Config, sgn *signer.Signer, tempoClient *client.Client) *FeePayerServer {
	return &FeePayerServer{
		port:         cfg.Port,
		authToken:    cfg.AuthToken,
		chainID:      cfg.ChainID,
		signer:       sgn,
		tempoClient:  tempoClient,
		tokenAddress: cfg.AlphaUSDAddress,
	}
}

// Start begins listening for incoming requests.
func (s *FeePayerServer) Start() error {
	if len(s.authToken) < 32 {
		return fmt.Errorf("relay requires an authentication token of at least 32 characters")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleFeePayerRelay)

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	log.Printf("Fee Payer Relay Server starting on %s", addr)
	log.Printf("Fee Payer Address: %s", s.signer.Address().Hex())
	log.Printf("Token Address: %s", s.tokenAddress)

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second}
	return srv.ListenAndServe()
}

func (s *FeePayerServer) handleFeePayerRelay(w http.ResponseWriter, r *http.Request) {
	if len(s.authToken) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.authToken)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Origin") != "" {
		http.Error(w, "Browser requests are not supported by this example", http.StatusForbidden)
		return
	}

	if r.Method != http.MethodPost {
		s.sendErrorResponse(w, nil, client.InvalidRequest, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendErrorResponse(w, nil, client.ParseError, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var request client.JSONRPCRequest
	if err := json.Unmarshal(body, &request); err != nil {
		s.sendErrorResponse(w, nil, client.ParseError, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("Received %s request (ID: %v)", request.Method, request.ID)

	if len(request.Params) == 0 {
		s.sendErrorResponse(w, request.ID, client.InvalidParams, "Missing transaction parameter", http.StatusOK)
		return
	}

	serializedTx, ok := request.Params[0].(string)
	if !ok {
		s.sendErrorResponse(w, request.ID, client.InvalidParams, "Transaction parameter must be a string", http.StatusOK)
		return
	}

	if !strings.HasPrefix(serializedTx, "0x76") {
		s.sendErrorResponse(
			w,
			request.ID,
			client.InvalidTransactionType,
			"service only supports Type 0x76 transactions",
			http.StatusOK,
		)
		return
	}

	txHash, err := s.processTransaction(serializedTx, request.Method)
	if err != nil {
		log.Printf("Failed to process transaction: %v", err)
		s.sendErrorResponse(
			w,
			request.ID,
			client.InternalError,
			fmt.Sprintf("Failed to process transaction: %v", err),
			http.StatusOK,
		)
		return
	}

	log.Printf("Transaction broadcast successfully: %s", txHash)

	response := client.NewJSONRPCResponse(request.ID, txHash)
	s.sendJSONResponse(w, response, http.StatusOK)
}

// processTransaction deserializes, signs, and broadcasts a transaction.
func (s *FeePayerServer) processTransaction(serializedTx, method string) (string, error) {
	log.Printf("Received raw tx (first 100 chars): %s...", serializedTx[:min(100, len(serializedTx))])

	tx, err := transaction.Deserialize(serializedTx)
	if err != nil {
		return "", fmt.Errorf("failed to deserialize transaction: %w", err)
	}

	log.Printf("Deserialized tx: chainID=%s, gas=%d, nonce=%d, nonceKey=%s",
		tx.ChainID, tx.Gas, tx.Nonce, tx.NonceKey)
	log.Printf("  feeToken=%s, awaitingFeePayer=%v", tx.FeeToken.Hex(), tx.AwaitingFeePayer)
	log.Printf("  calls=%d, maxFeePerGas=%s, maxPriorityFeePerGas=%s",
		len(tx.Calls), tx.MaxFeePerGas, tx.MaxPriorityFeePerGas)

	if tx.Signature == nil {
		return "", fmt.Errorf("transaction must have sender signature")
	}
	log.Printf("  signature present: type=%s", tx.Signature.Type)

	// Debug: Log the signing payload before verification
	signPayload, _ := transaction.SerializeForSigning(tx)
	log.Printf("Sign payload for verification: %s", signPayload)

	// Also log hash
	signHash, _ := transaction.GetSignPayload(tx)
	log.Printf("Sign hash: %s", signHash.Hex())

	senderAddr, err := transaction.VerifySignature(tx)
	if err != nil {
		return "", fmt.Errorf("failed to verify sender signature: %w", err)
	}

	if err := s.validateTransaction(tx); err != nil {
		return "", err
	}
	log.Printf("Processing transaction from sender: %s", senderAddr.Hex())
	tx.From = senderAddr // Set sender address so AddFeePayerSignature doesn't try to recover it

	// Set the fee token before fee payer signing.
	// The sender signed with fee_token=empty (per Tempo spec for sponsored txs),
	// but the final broadcast tx must include the actual fee token.
	tx.FeeToken = common.HexToAddress(s.tokenAddress)
	tx.AwaitingFeePayer = false // No longer awaiting - we're adding the signature now
	log.Printf("Set fee token to: %s", tx.FeeToken.Hex())

	// Debug: Log the fee payer hash BEFORE signing
	feePayerPayload, _ := transaction.SerializeForFeePayerSigning(tx, senderAddr)
	feePayerHash, _ := transaction.GetFeePayerSignPayload(tx, senderAddr)
	log.Printf("Fee payer payload being signed: %s", feePayerPayload)
	log.Printf("Fee payer hash being signed: %s", feePayerHash.Hex())

	err = transaction.AddFeePayerSignature(tx, s.signer)
	if err != nil {
		return "", fmt.Errorf("failed to add fee payer signature: %w", err)
	}
	log.Printf("Added fee payer signature from: %s", s.signer.Address().Hex())
	log.Printf("Fee payer sig: R=%x S=%x V=%d", tx.FeePayerSignature.R.Bytes(), tx.FeePayerSignature.S.Bytes(), tx.FeePayerSignature.YParity)

	// Verify fee payer signature before broadcasting
	recoveredFeePayer, verifyErr := transaction.VerifyFeePayerSignature(tx, senderAddr)
	if verifyErr != nil {
		log.Printf("WARNING: Fee payer signature verification failed: %v", verifyErr)
	} else {
		log.Printf("Fee payer signature verified, recovered: %s", recoveredFeePayer.Hex())
	}

	dualSignedTx, err := transaction.Serialize(tx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to serialize dual-signed transaction: %w", err)
	}
	log.Printf("Dual-signed tx (first 100 chars): %s...", dualSignedTx[:min(100, len(dualSignedTx))])

	ctx := context.Background()
	var txHash string
	log.Printf("Broadcasting via %s to %s", method, s.tempoClient.RPCURL())
	if method == methodSendRawTransactionSync {
		txHash, err = s.tempoClient.SendRawTransactionSync(ctx, dualSignedTx)
	} else {
		txHash, err = s.tempoClient.SendRawTransaction(ctx, dualSignedTx)
	}

	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	log.Printf("Broadcast returned txHash: %s", txHash)
	return txHash, nil
}

func (s *FeePayerServer) sendErrorResponse(w http.ResponseWriter, id interface{}, code int, message string, httpStatus int) {
	response := client.NewJSONRPCErrorResponse(id, code, message, nil)
	s.sendJSONResponse(w, response, httpStatus)
}

func (s *FeePayerServer) sendJSONResponse(w http.ResponseWriter, response *client.JSONRPCResponse, httpStatus int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

// validateTransaction limits the example to bounded transfers of its configured token.
func (s *FeePayerServer) validateTransaction(tx *transaction.Tx) error {
	if tx.ChainID == nil || tx.ChainID.Cmp(big.NewInt(int64(s.chainID))) != 0 {
		return fmt.Errorf("transaction chain does not match relay")
	}
	if tx.Gas == 0 || tx.Gas > 2_000_000 {
		return fmt.Errorf("transaction gas exceeds relay policy")
	}
	if tx.MaxFeePerGas == nil || tx.MaxFeePerGas.Sign() <= 0 || tx.MaxFeePerGas.Cmp(big.NewInt(100_000_000_000)) > 0 {
		return fmt.Errorf("transaction fee exceeds relay policy")
	}
	if tx.MaxPriorityFeePerGas == nil || tx.MaxPriorityFeePerGas.Sign() < 0 || tx.MaxPriorityFeePerGas.Cmp(tx.MaxFeePerGas) > 0 {
		return fmt.Errorf("invalid priority fee")
	}
	cost := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas), tx.MaxFeePerGas)
	if cost.Cmp(big.NewInt(50_000_000_000_000_000)) > 0 {
		return fmt.Errorf("transaction total fee exceeds relay policy")
	}
	if len(tx.KeyAuthorization) != 0 {
		return fmt.Errorf("relay does not sponsor key authorizations")
	}
	if len(tx.Calls) != 1 {
		return fmt.Errorf("relay only sponsors one token transfer")
	}
	call := tx.Calls[0]
	if call.To == nil || *call.To != common.HexToAddress(s.tokenAddress) || (call.Value != nil && call.Value.Sign() != 0) || len(call.Data) != 68 || string(call.Data[:4]) != "\xa9\x05\x9c\xbb" {
		return fmt.Errorf("relay only sponsors transfers of its configured token")
	}
	for _, b := range call.Data[4:16] {
		if b != 0 {
			return fmt.Errorf("transfer recipient is not canonically encoded")
		}
	}
	return nil
}
