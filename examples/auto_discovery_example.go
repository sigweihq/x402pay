package main

import (
	"log/slog"
	"os"

	"github.com/sigweihq/x402pay/pkg/chains/evm"
	"github.com/sigweihq/x402pay/pkg/chains/svm"
	"github.com/sigweihq/x402pay/pkg/processor"
)

// This example demonstrates the auto-discovery feature where chains
// automatically discover which networks to initialize based on what
// facilitators support.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Step 1: Initialize processor map first
	// This queries facilitator /supported endpoints to discover networks
	config := &processor.ProcessorConfig{
		FacilitatorURLs: []string{
			"https://facilitator.example.com",
		},
		// Or use CDP
		CDPAPIKeyID:     os.Getenv("CDP_API_KEY_ID"),
		CDPAPIKeySecret: os.Getenv("CDP_API_KEY_SECRET"),
	}
	processor.InitProcessorMap(config, logger)

	// Step 2: Initialize chains WITHOUT specifying networks
	// They will auto-discover from the facilitators initialized above

	// EVM chains will auto-discover (e.g., base, polygon, etc.)
	// and fetch RPC endpoints from chainlist.org
	err := evm.InitEVMChains(logger)
	if err != nil {
		logger.Error("Failed to initialize EVM chains", "error", err)
		return
	}
	logger.Info("EVM chains initialized via auto-discovery")

	// SVM chains will auto-discover (e.g., solana, solana-devnet)
	// and use official RPC endpoints
	err = svm.InitSVMChains(logger)
	if err != nil {
		logger.Error("Failed to initialize SVM chains", "error", err)
		return
	}
	logger.Info("SVM chains initialized via auto-discovery")

	// Now you can process payments!
	// The SDK only initialized RPC clients for networks your facilitators support
}
