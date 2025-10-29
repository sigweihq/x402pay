package svm

import (
	"log/slog"
	"os"
	"testing"

	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/stretchr/testify/assert"
)

func TestInitSVMChains(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Reset global registry before test
	chains.ResetGlobalRegistry()

	// Initialize SVM chains with default networks (uses official endpoints)
	err := InitSVMChains(logger)
	assert.NoError(t, err)

	// Verify that the chain registry was initialized
	registry := chains.GetGlobalRegistry()
	assert.NotNil(t, registry)

	// Verify that both default networks were registered
	adapter, err := registry.Get("solana")
	assert.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, "solana", adapter.Network())

	adapter, err = registry.Get("solana-devnet")
	assert.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, "solana-devnet", adapter.Network())
}

func TestInitSVMChainsWithEmptyEndpoints(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Reset global registry before test
	chains.ResetGlobalRegistry()

	// Initialize with empty endpoints for a network (should fall back to official endpoints)
	testEndpoints := map[string][]string{
		"solana":        {"https://api.mainnet-beta.solana.com"},
		"solana-devnet": {}, // Empty endpoints - should use official endpoints
	}

	err := InitSVMChainsWithEndpoints(logger, testEndpoints)
	assert.NoError(t, err)

	// Verify that both networks were registered
	registry := chains.GetGlobalRegistry()
	assert.NotNil(t, registry)

	adapter, err := registry.Get("solana")
	assert.NoError(t, err)
	assert.NotNil(t, adapter)

	// solana-devnet should be registered with official endpoints
	adapter, err = registry.Get("solana-devnet")
	assert.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, "solana-devnet", adapter.Network())
}

func TestInitSVMChainsMultipleEndpoints(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Reset global registry before test
	chains.ResetGlobalRegistry()

	// Initialize with multiple endpoints for failover
	testEndpoints := map[string][]string{
		"solana": {
			"https://api.mainnet-beta.solana.com",
			"https://solana-api.projectserum.com",
		},
	}

	err := InitSVMChainsWithEndpoints(logger, testEndpoints)
	assert.NoError(t, err)

	// Verify that the chain was registered
	registry := chains.GetGlobalRegistry()
	assert.NotNil(t, registry)

	adapter, err := registry.Get("solana")
	assert.NoError(t, err)
	assert.NotNil(t, adapter)

	// Verify RPC client was created
	rpcClient := adapter.RPCClient()
	assert.NotNil(t, rpcClient)
}

func TestInitSVMChainsWithSpecificNetworks(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Reset global registry before test
	chains.ResetGlobalRegistry()

	// Initialize with specific network (uses official endpoints)
	err := InitSVMChains(logger, "solana")
	assert.NoError(t, err)

	// Verify that only the specified network was registered
	registry := chains.GetGlobalRegistry()
	assert.NotNil(t, registry)

	adapter, err := registry.Get("solana")
	assert.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, "solana", adapter.Network())

	// solana-devnet should NOT be registered
	_, err = registry.Get("solana-devnet")
	assert.Error(t, err)
}

func TestInitSVMChainsWithEndpointsAndCustomEndpoints(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Reset global registry before test
	chains.ResetGlobalRegistry()

	// Initialize with custom endpoints
	testEndpoints := map[string][]string{
		"solana":        {"https://api.mainnet-beta.solana.com"},
		"solana-devnet": {"https://api.devnet.solana.com"},
	}

	err := InitSVMChainsWithEndpoints(logger, testEndpoints)
	assert.NoError(t, err)

	// Verify that both networks were registered
	registry := chains.GetGlobalRegistry()
	assert.NotNil(t, registry)

	adapter, err := registry.Get("solana")
	assert.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, "solana", adapter.Network())

	adapter, err = registry.Get("solana-devnet")
	assert.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, "solana-devnet", adapter.Network())
}
