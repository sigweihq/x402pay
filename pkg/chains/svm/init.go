package svm

import (
	"fmt"
	"log/slog"

	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/sigweihq/x402pay/pkg/constants"
)

// InitSVMChains initializes SVM chain support using official RPC endpoints
// Behavior depends on parameters and processor map state:
//   - With networks specified: Initializes those specific networks with official RPC endpoints
//   - Without networks, after InitProcessorMap: Auto-discovers SVM networks from facilitator /supported
//   - Without networks, before InitProcessorMap: Defaults to both Solana mainnet and devnet
func InitSVMChains(logger *slog.Logger, networksToMonitor ...string) error {
	registry := chains.InitGlobalRegistry()

	// If no networks specified, try auto-discovery from processor map
	if len(networksToMonitor) == 0 {
		networksToMonitor = chains.GetDiscoveredSVMNetworks()
		if len(networksToMonitor) == 0 {
			// Fallback to default Solana networks if no processor map networks found
			networksToMonitor = []string{
				constants.NetworkSolana,
				constants.NetworkSolanaDevnet,
			}
		}
	}

	// Register chain adapters for monitored networks using official endpoints
	for _, network := range networksToMonitor {
		endpoints, ok := constants.OfficialRPCEndpoints[network]
		if !ok {
			logger.Warn("no official endpoints available for SVM network", "network", network)
			continue
		}

		adapter := NewSVMAdapter(network, endpoints)

		if err := registry.Register(adapter); err != nil {
			return fmt.Errorf("failed to register SVM adapter for %s: %w", network, err)
		}
	}

	return nil
}

// InitSVMChainsWithEndpoints initializes SVM chain support with user-provided endpoints
// If a specific network has no endpoints, falls back to official endpoints if available
func InitSVMChainsWithEndpoints(logger *slog.Logger, endpoints map[string][]string) error {
	registry := chains.InitGlobalRegistry()

	for network, eps := range endpoints {
		// Fallback to official endpoints if empty
		if len(eps) == 0 {
			if officialEps, ok := constants.OfficialRPCEndpoints[network]; ok {
				eps = officialEps
				logger.Info("using official endpoints for SVM network", "network", network)
			} else {
				logger.Warn("no endpoints provided for SVM network", "network", network)
				continue
			}
		}

		adapter := NewSVMAdapter(network, eps)

		if err := registry.Register(adapter); err != nil {
			return fmt.Errorf("failed to register SVM adapter for %s: %w", network, err)
		}
	}

	return nil
}
