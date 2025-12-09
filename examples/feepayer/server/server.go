package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

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
	Port int

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
		TempoRPCURL:        getEnv("TEMPO_RPC_URL", "https://rpc.testnet.tempo.xyz"),
		TempoUsername:      getEnv("TEMPO_USERNAME", ""),
		TempoPassword:      getEnv("TEMPO_PASSWORD", ""),
		FeePayerPrivateKey: getEnv("TEMPO_FEE_PAYER_PRIVATE_KEY", ""),
		AlphaUSDAddress:    getEnv("ALPHAUSD_ADDRESS", "0x20c0000000000000000000000000000000000001"),
		ChainID:            getEnvInt("TEMPO_CHAIN_ID", 42424),
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks that all required configuration values are set.
func (c *Config) Validate() error {
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
}

// NewFeePayerServer creates a new fee payer relay server.
func NewFeePayerServer(port int, sgn *signer.Signer, tempoClient *client.Client, tokenAddress string) *FeePayerServer {
	return &FeePayerServer{
		port:         port,
		signer:       sgn,
		tempoClient:  tempoClient,
		tokenAddress: tokenAddress,
	}
}

// Start begins listening for incoming requests.
func (s *FeePayerServer) Start() error {
	http.HandleFunc("/", s.handleFeePayerRelay)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Fee Payer Relay Server starting on %s", addr)
	log.Printf("Fee Payer Address: %s", s.signer.Address().Hex())
	log.Printf("Token Address: %s", s.tokenAddress)

	return http.ListenAndServe(addr, nil)
}

func (s *FeePayerServer) handleFeePayerRelay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		s.sendErrorResponse(w, nil, client.InvalidRequest, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
	tx, err := transaction.Deserialize(serializedTx)
	if err != nil {
		return "", fmt.Errorf("failed to deserialize transaction: %w", err)
	}

	if tx.Signature == nil {
		return "", fmt.Errorf("transaction must have sender signature")
	}

	senderAddr, err := transaction.VerifySignature(tx)
	if err != nil {
		return "", fmt.Errorf("failed to verify sender signature: %w", err)
	}

	log.Printf("Processing transaction from sender: %s", senderAddr.Hex())

	err = transaction.AddFeePayerSignature(tx, s.signer)
	if err != nil {
		return "", fmt.Errorf("failed to add fee payer signature: %w", err)
	}

	dualSignedTx, err := transaction.Serialize(tx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to serialize dual-signed transaction: %w", err)
	}

	ctx := context.Background()
	var txHash string
	if method == methodSendRawTransactionSync {
		txHash, err = s.tempoClient.SendRawTransactionSync(ctx, dualSignedTx)
	} else {
		txHash, err = s.tempoClient.SendRawTransaction(ctx, dualSignedTx)
	}

	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

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
