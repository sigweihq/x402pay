package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/sigweihq/x402pay/pkg/constants"
)

// ChainListResponse represents a chain entry from chainlist.org/rpcs.json
type ChainListResponse struct {
	ChainID int                 `json:"chainId"`
	Name    string              `json:"name"`
	RPC     []ChainListRPCEntry `json:"rpc"`
}

// ChainListRPCEntry represents an RPC endpoint entry
type ChainListRPCEntry struct {
	URL      string `json:"url"`
	Tracking string `json:"tracking,omitempty"`
}

// RPCManager handles blockchain RPC endpoints and failover
type RPCManager struct {
	endpoints map[int64][]string // chainID -> []rpc_urls
	logger    *slog.Logger
	mu        sync.RWMutex
}

// Global RPC manager instance
var globalRPCManager *RPCManager

// InitGlobalRPCManager initializes the global RPC manager at server startup
func InitGlobalRPCManager(logger *slog.Logger) {
	globalRPCManager = &RPCManager{
		endpoints: make(map[int64][]string),
		logger:    logger,
	}
	// Start background service immediately
	globalRPCManager.startBackgroundRefresh()
}

// GetGlobalRPCManager returns the singleton RPC manager instance (must be initialized first)
func GetGlobalRPCManager() *RPCManager {
	if globalRPCManager == nil {
		panic("RPC manager not initialized - call InitGlobalRPCManager at server startup")
	}
	return globalRPCManager
}

// startBackgroundRefresh starts the background service to refresh endpoints
func (r *RPCManager) startBackgroundRefresh() {
	// Load official endpoints immediately (fast, non-blocking)
	r.mu.Lock()
	r.setOfficialEndpoints()
	r.mu.Unlock()
	r.logger.Info("loaded official RPC endpoints immediately")

	// Start background service for full endpoint loading and health checking
	go func() {
		// Do initial full load (with health checking) in background
		r.loadEndpoints()

		// Then refresh every 6 hours
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			r.loadEndpoints()
		}
	}()
}

// loadEndpoints fetches RPC endpoints and prioritizes healthy ones
func (r *RPCManager) loadEndpoints() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Start with reliable official endpoints first
	r.setOfficialEndpoints()

	// Try to fetch additional endpoints from chainlist.org
	chains, err := r.fetchAllChains()
	if err != nil {
		r.logger.Warn("failed to fetch chain data from chainlist.org, using official endpoints only", "error", err)
	} else {
		// Add additional endpoints from chainlist.org
		r.addChainlistEndpoints(chains)
	}

	// Health check and prioritize all endpoints
	r.healthCheckAndPrioritize()
}

// setOfficialEndpoints sets the official reliable endpoints first
func (r *RPCManager) setOfficialEndpoints() {
	for network, endpoints := range constants.OfficialRPCEndpoints {
		chainID := constants.NetworkToChainID[network]
		r.endpoints[chainID] = endpoints
	}
}

// addChainlistEndpoints adds additional endpoints from chainlist.org
func (r *RPCManager) addChainlistEndpoints(chains []ChainListResponse) {
	for _, chain := range chains {
		additionalRPCs := r.extractHTTPSRPCs(chain.RPC)
		chainID := int64(chain.ChainID)
		r.endpoints[chainID] = append(r.endpoints[chainID], additionalRPCs...)
	}
}

// healthCheckAndPrioritize tests endpoints and puts healthy ones first
func (r *RPCManager) healthCheckAndPrioritize() {
	for network, endpoints := range r.endpoints {
		if len(endpoints) == 0 {
			continue
		}

		healthyEndpoints := make([]string, 0, len(endpoints))
		unhealthyEndpoints := make([]string, 0, len(endpoints))

		// Test each endpoint
		for _, endpoint := range endpoints {
			if r.isEndpointHealthy(endpoint) {
				healthyEndpoints = append(healthyEndpoints, endpoint)
			} else {
				unhealthyEndpoints = append(unhealthyEndpoints, endpoint)
			}
		}

		// Put healthy endpoints first, then unhealthy as fallback
		r.endpoints[network] = append(healthyEndpoints, unhealthyEndpoints...)

		r.logger.Info("endpoint health check completed",
			"network", network,
			"healthy", len(healthyEndpoints),
			"unhealthy", len(unhealthyEndpoints),
			"total", len(endpoints))
	}
}

// isEndpointHealthy performs a quick health check on an RPC endpoint
func (r *RPCManager) isEndpointHealthy(endpoint string) bool {
	client, err := ethclient.Dial(endpoint)
	if err != nil {
		return false
	}
	defer client.Close()

	// Quick test: get latest block number with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = client.BlockNumber(ctx)
	return err == nil
}

// fetchAllChains fetches all chain data from chainlist.org/rpcs.json
func (r *RPCManager) fetchAllChains() ([]ChainListResponse, error) {
	url := "https://chainlist.org/rpcs.json"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chain data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var chains []ChainListResponse
	if err := json.NewDecoder(resp.Body).Decode(&chains); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return chains, nil
}

// extractHTTPSRPCs filters and extracts HTTPS RPC URLs from RPC entries
func (r *RPCManager) extractHTTPSRPCs(rpcEntries []ChainListRPCEntry) []string {
	var httpsRPCs []string
	for _, rpc := range rpcEntries {
		// Only include HTTPS URLs and exclude templated URLs
		if strings.HasPrefix(rpc.URL, "https://") && !strings.Contains(rpc.URL, "${") {
			httpsRPCs = append(httpsRPCs, rpc.URL)
		}
	}
	return httpsRPCs
}

// GetTransactionReceipt attempts to get a transaction receipt with RPC failover
func (r *RPCManager) GetTransactionReceipt(network, txHash string) (*ethtypes.Receipt, error) {
	r.mu.RLock()
	chainID := constants.NetworkToChainID[network]
	endpoints := make([]string, len(r.endpoints[chainID]))
	copy(endpoints, r.endpoints[chainID])
	r.mu.RUnlock()

	if len(endpoints) == 0 {
		r.logger.Warn("no RPC endpoints available for network, skipping verification", "network", network)
		return nil, nil // Skip verification
	}

	initialDelay := constants.DelayBetweenRPCCalls // delay in milliseconds for first endpoint
	for i, endpoint := range endpoints {
		// Add progressive delay
		if i > 0 {
			delay := time.Duration(i*constants.DelayBetweenRPCCalls+initialDelay) * time.Millisecond
			time.Sleep(delay)
		}

		client, err := ethclient.Dial(endpoint)
		if err != nil {
			r.logger.Warn("failed to connect to RPC", "endpoint", endpoint, "error", err)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), constants.TransactionReceiptTimeout)
		receipt, err := PatchedTransactionReceipt(ctx, client, common.HexToHash(txHash))
		client.Close()
		cancel()

		if err != nil {
			r.logger.Warn("RPC call failed", "endpoint", endpoint, "error", err)
			continue
		}

		return receipt, nil
	}

	return nil, fmt.Errorf("all RPC endpoints failed for network %s", network)
}

// PatchedTransactionReceipt gets a transaction receipt with Base-specific fixes
func PatchedTransactionReceipt(ctx context.Context, client *ethclient.Client, txHash common.Hash) (*ethtypes.Receipt, error) {
	var raw json.RawMessage
	err := client.Client().CallContext(ctx, &raw, "eth_getTransactionReceipt", txHash)
	if err != nil {
		return nil, err
	}
	if string(raw) == "null" {
		return nil, errors.New("not found")
	}

	// Patch out `blockTimestamp` from the logs
	cleaned, err := stripBlockTimestampFromLogs(raw)
	if err != nil {
		return nil, err
	}

	var receipt ethtypes.Receipt
	err = json.Unmarshal(cleaned, &receipt)
	if err != nil {
		return nil, err
	}

	return &receipt, nil
}

// stripBlockTimestampFromLogs removes the blockTimestamp field from transaction logs
func stripBlockTimestampFromLogs(raw json.RawMessage) ([]byte, error) {
	var receiptMap map[string]interface{}
	if err := json.Unmarshal(raw, &receiptMap); err != nil {
		return nil, err
	}

	logs, ok := receiptMap["logs"].([]interface{})
	if ok {
		for _, log := range logs {
			logMap, ok := log.(map[string]interface{})
			if ok {
				delete(logMap, "blockTimestamp")
			}
		}
	}

	return json.Marshal(receiptMap)
}

// CallContract makes a contract call with RPC failover
func (r *RPCManager) CallContract(network, contractAddress, data string) (string, error) {
	r.mu.RLock()
	chainID := constants.NetworkToChainID[network]
	endpoints := make([]string, len(r.endpoints[chainID]))
	copy(endpoints, r.endpoints[chainID])
	r.mu.RUnlock()

	if len(endpoints) == 0 {
		r.logger.Warn("no RPC endpoints available for network", "network", network)
		return "", fmt.Errorf("no RPC endpoints available for network %s", network)
	}

	for i, endpoint := range endpoints {
		// Add progressive delay: 0ms for first endpoint, delayBetweenRPCCalls ms for second, 2*delayBetweenRPCCalls ms for third, etc.
		if i > 0 {
			delay := time.Duration(i*constants.DelayBetweenRPCCalls) * time.Millisecond
			time.Sleep(delay)
		}

		client, err := ethclient.Dial(endpoint)
		if err != nil {
			r.logger.Warn("failed to connect to RPC", "endpoint", endpoint, "error", err)
			continue
		}

		// Create call message
		// Ensure data has 0x prefix for JSON-RPC
		callData := data
		if !strings.HasPrefix(data, "0x") {
			callData = "0x" + data
		}
		msg := map[string]interface{}{
			"to":   contractAddress,
			"data": callData,
		}

		// Make the call with timeout
		ctx, cancel := context.WithTimeout(context.Background(), constants.CallContractTimeout)
		var result string
		err = client.Client().CallContext(ctx, &result, "eth_call", msg, "latest")
		client.Close()
		cancel()

		if err != nil {
			r.logger.Warn("contract call failed", "endpoint", endpoint, "error", err)
			continue
		}

		return result, nil
	}

	return "", fmt.Errorf("all RPC endpoints failed for network %s", network)
}
