package svm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/sigweihq/x402pay/pkg/constants"
)

// RPCClient implements chains.RPCClient for SVM chains
type RPCClient struct {
	network   string
	endpoints []string
	client    *http.Client
}

// NewRPCClient creates a new SVM RPC client
func NewRPCClient(network string, endpoints []string) *RPCClient {
	return &RPCClient{
		network:   network,
		endpoints: endpoints,
		client: &http.Client{
			Timeout: constants.TransactionReceiptTimeout,
		},
	}
}

// Verify RPCClient implements interface
var _ chains.RPCClient = (*RPCClient)(nil)

// GetTransactionReceipt implements chains.RPCClient
// Retries multiple times with exponential backoff, cycling through endpoints with random start for load balancing
func (r *RPCClient) GetTransactionReceipt(txHash string) (chains.TransactionReceipt, error) {
	if len(r.endpoints) == 0 {
		return nil, nil // Skip verification if no endpoints
	}

	// Start at a random position for load balancing
	startIdx := rand.Intn(len(r.endpoints))
	initialDelay := constants.DelayBetweenRPCCalls
	var lastErr error

	for attempt := 0; attempt < constants.MaxRetries; attempt++ {
		// Exponential backoff: first attempt has no delay, subsequent attempts increase delay
		if attempt > 0 {
			delay := time.Duration(attempt*constants.DelayBetweenRPCCalls+initialDelay) * time.Millisecond
			time.Sleep(delay)
		}

		// Cycle through endpoints with random start (wrap around if we have fewer endpoints than retries)
		endpointIdx := (startIdx + attempt) % len(r.endpoints)
		endpoint := r.endpoints[endpointIdx]

		receipt, err := r.getTransaction(endpoint, txHash)
		if err != nil {
			lastErr = err
			continue
		}

		return receipt, nil
	}

	return nil, fmt.Errorf("all RPC endpoints failed for network %s after %d attempts: %w", r.network, constants.MaxRetries, lastErr)
}

// IsHealthy implements chains.RPCClient
func (r *RPCClient) IsHealthy(endpoint string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Call getHealth endpoint
	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getHealth",
		Params:  []interface{}{},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return false
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return false
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// getTransaction fetches a transaction from SVM RPC
func (r *RPCClient) getTransaction(endpoint, signature string) (*SVMReceipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), constants.TransactionReceiptTimeout)
	defer cancel()

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getTransaction",
		Params: []interface{}{
			signature,
			map[string]interface{}{
				"encoding":                       "jsonParsed",
				"maxSupportedTransactionVersion": 0,
			},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp jsonrpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	if rpcResp.Result == nil {
		return nil, fmt.Errorf("transaction not found")
	}

	var tx transactionResult
	resultBytes, err := json.Marshal(rpcResp.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}

	if err := json.Unmarshal(resultBytes, &tx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	return &SVMReceipt{tx: &tx}, nil
}

// jsonrpcRequest represents a JSON-RPC request
type jsonrpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// jsonrpcResponse represents a JSON-RPC response
type jsonrpcResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *jsonrpcError `json:"error,omitempty"`
}

// jsonrpcError represents a JSON-RPC error
type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// transactionResult represents the result of getTransaction
type transactionResult struct {
	Slot        uint64      `json:"slot"`
	Transaction transaction `json:"transaction"`
	Meta        *meta       `json:"meta"`
	BlockTime   *int64      `json:"blockTime"`
}

// transaction represents an SVM transaction
type transaction struct {
	Message    message  `json:"message"`
	Signatures []string `json:"signatures"`
}

// message represents an SVM transaction message
type message struct {
	AccountKeys     []interface{}       `json:"accountKeys"` // Can be string or parsed object
	Header          header              `json:"header"`
	RecentBlockhash string              `json:"recentBlockhash"`
	Instructions    []parsedInstruction `json:"instructions"`
}

// header represents transaction header
type header struct {
	NumRequiredSignatures       int `json:"numRequiredSignatures"`
	NumReadonlySignedAccounts   int `json:"numReadonlySignedAccounts"`
	NumReadonlyUnsignedAccounts int `json:"numReadonlyUnsignedAccounts"`
}

// parsedInstruction represents a parsed transaction instruction
type parsedInstruction struct {
	Program     string                 `json:"program"`
	ProgramID   string                 `json:"programId"`
	Parsed      *parsedInstructionData `json:"parsed,omitempty"`
	StackHeight *int                   `json:"stackHeight,omitempty"`
}

// parsedInstructionData represents parsed instruction data for SPL Token transfers
type parsedInstructionData struct {
	Type string                 `json:"type"`
	Info map[string]interface{} `json:"info"`
}

// meta represents transaction metadata
type meta struct {
	Err               interface{}    `json:"err"`
	Fee               uint64         `json:"fee"`
	PreBalances       []uint64       `json:"preBalances"`
	PostBalances      []uint64       `json:"postBalances"`
	InnerInstructions []interface{}  `json:"innerInstructions"`
	LogMessages       []string       `json:"logMessages"`
	PreTokenBalances  []interface{}  `json:"preTokenBalances"`
	PostTokenBalances []tokenBalance `json:"postTokenBalances"`
	Rewards           []interface{}  `json:"rewards"`
}

// tokenBalance represents a token balance change
type tokenBalance struct {
	AccountIndex  int                    `json:"accountIndex"`
	Mint          string                 `json:"mint"`
	Owner         string                 `json:"owner"`
	ProgramID     string                 `json:"programId"`
	UITokenAmount map[string]interface{} `json:"uiTokenAmount"`
}

// SVMReceipt implements chains.TransactionReceipt
type SVMReceipt struct {
	tx *transactionResult
}

// IsSuccessful implements chains.TransactionReceipt
func (r *SVMReceipt) IsSuccessful() bool {
	return r.tx.Meta != nil && r.tx.Meta.Err == nil
}

// GetTransferEvent implements chains.TransactionReceipt
// For SVM, we extract transfer information from parsed SPL Token instructions
func (r *SVMReceipt) GetTransferEvent() (*chains.TransferEvent, error) {
	if r.tx == nil || r.tx.Transaction.Message.Instructions == nil {
		return nil, fmt.Errorf("no instructions in transaction")
	}

	// Look for SPL Token transfer or transferChecked instructions
	for _, instruction := range r.tx.Transaction.Message.Instructions {
		if instruction.Parsed == nil {
			continue
		}

		// Check for transfer or transferChecked instruction types
		if instruction.Parsed.Type != "transfer" && instruction.Parsed.Type != "transferChecked" {
			continue
		}

		// Extract transfer info
		info := instruction.Parsed.Info

		// Get source (from)
		source, ok := info["source"].(string)
		if !ok {
			continue
		}

		// Get destination (to)
		destination, ok := info["destination"].(string)
		if !ok {
			continue
		}

		// Get amount - can be string or number
		var amount string
		switch v := info["amount"].(type) {
		case string:
			amount = v
		case float64:
			amount = fmt.Sprintf("%.0f", v)
		default:
			// Try tokenAmount for transferChecked
			if tokenAmount, ok := info["tokenAmount"].(map[string]interface{}); ok {
				if amtStr, ok := tokenAmount["amount"].(string); ok {
					amount = amtStr
				}
			}
		}

		if amount == "" {
			continue
		}

		// Get mint address (only present in transferChecked)
		mint, _ := info["mint"].(string)

		// Extract the owner of the destination ATA from postTokenBalances
		// For SVM, we want to return the wallet address (owner), not the ATA address
		// This hides the ATA implementation detail from the validation layer
		destinationWallet := destination // Default to ATA if we can't find owner
		if r.tx.Meta != nil && len(r.tx.Meta.PostTokenBalances) > 0 {
			for _, balance := range r.tx.Meta.PostTokenBalances {
				// Find the balance entry for the destination ATA
				// The accountIndex in message.accountKeys should match
				if len(r.tx.Transaction.Message.AccountKeys) > balance.AccountIndex {
					var accountKey string
					// AccountKeys can be string or parsed object
					switch v := r.tx.Transaction.Message.AccountKeys[balance.AccountIndex].(type) {
					case string:
						accountKey = v
					case map[string]interface{}:
						if pubkey, ok := v["pubkey"].(string); ok {
							accountKey = pubkey
						}
					}

					if accountKey == destination {
						destinationWallet = balance.Owner
						break
					}
				}
			}
		}

		return &chains.TransferEvent{
			From:  source,
			To:    destinationWallet, // Return wallet owner, not ATA
			Value: amount,
			Asset: mint,
		}, nil
	}

	return nil, fmt.Errorf("no token transfer instruction found")
}
