package evm

import (
	"log/slog"
	"time"

	"github.com/sigweihq/x402pay/pkg/chains"
)

// InitEVMChains initializes EVM chain support with automatic endpoint discovery from chainlist.org
// Behavior depends on parameters and processor map state:
//   - With networks specified: Initializes those specific networks with chainlist.org endpoints
//   - Without networks, after InitProcessorMap: Auto-discovers EVM networks from facilitator /supported and initialized with chainlist.org endpoints
//   - Without networks, before InitProcessorMap: Only initializes the registry (no chains registered)
func InitEVMChains(logger *slog.Logger, networksToMonitor ...string) error {
	// Initialize global registry
	registry := chains.InitGlobalRegistry()

	// If no networks specified, try auto-discovery from processor map
	if len(networksToMonitor) == 0 {
		networksToMonitor = chains.GetDiscoveredEVMNetworks()
		if len(networksToMonitor) == 0 {
			// No networks to initialize - just return with initialized registry
			return nil
		}
	}

	// Create chainlist.org endpoint provider
	provider := NewChainListEndpointProvider(logger)

	// Refresh endpoints asynchronously (starts with official endpoints, health checks in background)
	// This allows the server to start immediately without blocking on health checks
	if err := provider.RefreshEndpoints(networksToMonitor, true); err != nil {
		logger.Warn("initial endpoint refresh failed, using official endpoints only", "error", err)
	}

	// Register chain adapters for monitored networks
	for _, network := range networksToMonitor {
		endpoints := provider.GetEndpoints(network)
		if len(endpoints) == 0 {
			logger.Warn("no endpoints available for network", "network", network)
			continue
		}

		adapter, err := NewEVMAdapter(network, endpoints)
		if err != nil {
			logger.Warn("failed to create EVM adapter", "network", network, "error", err)
			continue
		}

		if err := registry.Register(adapter); err != nil {
			logger.Warn("failed to register EVM adapter", "network", network, "error", err)
		}
	}

	// Start background refresh (every 6 hours)
	go startBackgroundRefresh(logger, provider, registry, networksToMonitor)

	return nil
}

// InitEVMChainsWithEndpoints initializes EVM chains with user-provided endpoints
// This is useful when SDK users want full control over RPC endpoints
func InitEVMChainsWithEndpoints(logger *slog.Logger, endpoints map[string][]string) error {
	// Initialize global registry
	registry := chains.InitGlobalRegistry()

	// Register chain adapters for each network
	for network, networkEndpoints := range endpoints {
		if len(networkEndpoints) == 0 {
			logger.Warn("no endpoints provided for network", "network", network)
			continue
		}

		adapter, err := NewEVMAdapter(network, networkEndpoints)
		if err != nil {
			logger.Warn("failed to create EVM adapter", "network", network, "error", err)
			continue
		}

		if err := registry.Register(adapter); err != nil {
			logger.Warn("failed to register EVM adapter", "network", network, "error", err)
		}
	}

	return nil
}

// startBackgroundRefresh refreshes endpoints and re-registers adapters periodically
func startBackgroundRefresh(logger *slog.Logger, provider *ChainListEndpointProvider, registry *chains.Registry, networks []string) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Background refresh runs synchronously within this goroutine
		if err := provider.RefreshEndpoints(networks, false); err != nil {
			logger.Warn("background endpoint refresh failed", "error", err)
			continue
		}

		// Re-register adapters with fresh endpoints
		for _, network := range networks {
			endpoints := provider.GetEndpoints(network)
			if len(endpoints) == 0 {
				continue
			}

			adapter, err := NewEVMAdapter(network, endpoints)
			if err != nil {
				logger.Warn("failed to recreate EVM adapter", "network", network, "error", err)
				continue
			}

			// Re-register (will update existing entry)
			if err := registry.Register(adapter); err != nil {
				logger.Warn("failed to re-register EVM adapter", "network", network, "error", err)
			}
		}
	}
}
