package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sigweihq/x402pay/pkg/constants"
)

// ChainListResponse represents a chain entry from chainlist.org/rpcs.json
type ChainListResponse struct {
	ChainID int `json:"chainId"`
	RPC     []struct {
		URL string `json:"url"`
	} `json:"rpc"`
}

// ChainListEndpointProvider fetches RPC endpoints from chainlist.org
// and performs health checks to prioritize reliable endpoints
type ChainListEndpointProvider struct {
	endpoints map[int64][]string // chainID -> []rpc_urls
	logger    *slog.Logger
	mu        sync.RWMutex
}

// NewChainListEndpointProvider creates a provider that fetches from chainlist.org
func NewChainListEndpointProvider(logger *slog.Logger) *ChainListEndpointProvider {
	return &ChainListEndpointProvider{
		endpoints: make(map[int64][]string),
		logger:    logger,
	}
}

// GetEndpoints implements chains.EndpointProvider
func (p *ChainListEndpointProvider) GetEndpoints(network string) []string {
	chainID, ok := constants.NetworkToChainID[network]
	if !ok {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	endpoints := p.endpoints[chainID]
	if len(endpoints) == 0 {
		// Fallback to official endpoints if chainlist fetch hasn't completed
		return constants.OfficialRPCEndpoints[network]
	}

	return endpoints
}

// RefreshEndpoints implements chains.EndpointProvider
// Fetches fresh endpoints from chainlist.org and performs health checks
func (p *ChainListEndpointProvider) RefreshEndpoints() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear existing endpoints and start fresh
	p.endpoints = make(map[int64][]string)

	// Start with official endpoints
	p.setOfficialEndpoints()

	// Fetch from chainlist.org
	chainListData, err := p.fetchAllChains()
	if err != nil {
		p.logger.Warn("failed to fetch from chainlist.org, using official endpoints only", "error", err)
		return err
	}

	// Add chainlist endpoints
	p.addChainlistEndpoints(chainListData)

	// Health check and prioritize
	p.healthCheckAndPrioritize()

	return nil
}

// setOfficialEndpoints sets the official reliable endpoints
func (p *ChainListEndpointProvider) setOfficialEndpoints() {
	for network, endpoints := range constants.OfficialRPCEndpoints {
		chainID, ok := constants.NetworkToChainID[network]
		if !ok {
			continue
		}
		p.endpoints[chainID] = endpoints
	}
}

// fetchAllChains fetches chain data from chainlist.org
func (p *ChainListEndpointProvider) fetchAllChains() ([]ChainListResponse, error) {
	client := &http.Client{
		Timeout: constants.FacilitatorTimeout,
	}

	resp, err := client.Get("https://chainlist.org/rpcs.json")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chainlist data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chainlist.org returned status %d", resp.StatusCode)
	}

	var chains []ChainListResponse
	if err := json.NewDecoder(resp.Body).Decode(&chains); err != nil {
		return nil, fmt.Errorf("failed to decode chainlist data: %w", err)
	}

	return chains, nil
}

// addChainlistEndpoints adds endpoints from chainlist.org
func (p *ChainListEndpointProvider) addChainlistEndpoints(chainListData []ChainListResponse) {
	for _, chain := range chainListData {
		var httpsRPCs []string
		for _, rpc := range chain.RPC {
			// Only include HTTPS URLs and exclude templated URLs
			if strings.HasPrefix(rpc.URL, "https://") && !strings.Contains(rpc.URL, "${") {
				httpsRPCs = append(httpsRPCs, rpc.URL)
			}
		}
		if len(httpsRPCs) > 0 {
			p.endpoints[int64(chain.ChainID)] = append(p.endpoints[int64(chain.ChainID)], httpsRPCs...)
		}
	}
}

// healthCheckAndPrioritize checks endpoint health and prioritizes working ones
func (p *ChainListEndpointProvider) healthCheckAndPrioritize() {
	for chainID, endpoints := range p.endpoints {
		if len(endpoints) == 0 {
			continue
		}

		// Check health of each endpoint
		var healthyEndpoints, unhealthyEndpoints []string
		for _, endpoint := range endpoints {
			if p.isEndpointHealthy(endpoint) {
				healthyEndpoints = append(healthyEndpoints, endpoint)
			} else {
				unhealthyEndpoints = append(unhealthyEndpoints, endpoint)
			}
		}

		// Prioritize healthy endpoints first, then unhealthy as backup
		p.endpoints[chainID] = append(healthyEndpoints, unhealthyEndpoints...)

		p.logger.Debug("health check complete",
			"chainID", chainID,
			"healthy", len(healthyEndpoints),
			"unhealthy", len(unhealthyEndpoints))
	}
}

// isEndpointHealthy performs a simple health check on an RPC endpoint
func (p *ChainListEndpointProvider) isEndpointHealthy(endpoint string) bool {
	client, err := ethclient.Dial(endpoint)
	if err != nil {
		return false
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = client.BlockNumber(ctx)
	return err == nil
}
