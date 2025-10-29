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
// Only processes endpoints for the specified networks to avoid unnecessary work
// If async is true, returns immediately with official endpoints and runs health checks in background
func (p *ChainListEndpointProvider) RefreshEndpoints(networks []string, async bool) error {
	// Build set of chain IDs we actually need
	neededChainIDs := make(map[int64]bool)
	for _, network := range networks {
		if chainID, ok := constants.NetworkToChainID[network]; ok {
			neededChainIDs[chainID] = true
		}
	}

	// If no networks specified, nothing to do
	if len(neededChainIDs) == 0 {
		p.logger.Warn("no valid networks specified for endpoint refresh")
		return nil
	}

	// Set official endpoints immediately (fast, no HTTP calls)
	p.mu.Lock()
	p.endpoints = make(map[int64][]string)
	p.setOfficialEndpoints(neededChainIDs)
	p.mu.Unlock()

	if async {
		// Run chainlist fetch and health checks in background
		go func() {
			p.logger.Info("Starting background endpoint refresh with health checks")
			if err := p.refreshWithHealthChecks(neededChainIDs); err != nil {
				p.logger.Warn("background endpoint refresh failed", "error", err)
			} else {
				p.logger.Info("Background endpoint refresh completed successfully")
			}
		}()
		return nil
	}

	// Synchronous: do health checks now
	return p.refreshWithHealthChecks(neededChainIDs)
}

// refreshWithHealthChecks fetches chainlist data and performs health checks
func (p *ChainListEndpointProvider) refreshWithHealthChecks(neededChainIDs map[int64]bool) error {
	// Fetch from chainlist.org
	chainListData, err := p.fetchAllChains()
	if err != nil {
		p.logger.Warn("failed to fetch from chainlist.org, using official endpoints only", "error", err)
		return err
	}

	p.mu.Lock()
	// Add chainlist endpoints (only for needed networks)
	p.addChainlistEndpoints(chainListData, neededChainIDs)
	p.mu.Unlock()

	// Health check and prioritize (only needed networks)
	p.healthCheckAndPrioritize()

	return nil
}

// setOfficialEndpoints sets the official reliable endpoints
// Only sets endpoints for chain IDs in the neededChainIDs set
func (p *ChainListEndpointProvider) setOfficialEndpoints(neededChainIDs map[int64]bool) {
	for network, endpoints := range constants.OfficialRPCEndpoints {
		chainID, ok := constants.NetworkToChainID[network]
		if !ok {
			continue
		}
		// Only add if we need this chain
		if neededChainIDs[chainID] {
			p.endpoints[chainID] = endpoints
		}
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
// Only adds endpoints for chain IDs in the neededChainIDs set
func (p *ChainListEndpointProvider) addChainlistEndpoints(chainListData []ChainListResponse, neededChainIDs map[int64]bool) {
	for _, chain := range chainListData {
		chainID := int64(chain.ChainID)

		// Skip chains we don't need
		if !neededChainIDs[chainID] {
			continue
		}

		var httpsRPCs []string
		for _, rpc := range chain.RPC {
			// Only include HTTPS URLs and exclude templated URLs
			if strings.HasPrefix(rpc.URL, "https://") && !strings.Contains(rpc.URL, "${") {
				httpsRPCs = append(httpsRPCs, rpc.URL)
			}
		}
		if len(httpsRPCs) > 0 {
			p.endpoints[chainID] = append(p.endpoints[chainID], httpsRPCs...)
		}
	}
}

// healthCheckAndPrioritize checks endpoint health and prioritizes working ones
// Performs health checks in parallel for speed
func (p *ChainListEndpointProvider) healthCheckAndPrioritize() {
	for chainID, endpoints := range p.endpoints {
		if len(endpoints) == 0 {
			continue
		}

		// Health check results
		type result struct {
			endpoint  string
			isHealthy bool
		}
		results := make(chan result, len(endpoints))

		// Check health of each endpoint in parallel
		for _, endpoint := range endpoints {
			go func(ep string) {
				results <- result{
					endpoint:  ep,
					isHealthy: p.isEndpointHealthy(ep),
				}
			}(endpoint)
		}

		// Collect results
		var healthyEndpoints, unhealthyEndpoints []string
		for range endpoints {
			res := <-results
			if res.isHealthy {
				healthyEndpoints = append(healthyEndpoints, res.endpoint)
			} else {
				unhealthyEndpoints = append(unhealthyEndpoints, res.endpoint)
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
