package chains

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockChainAdapter is a simple test adapter
type mockChainAdapter struct {
	network string
}

func (m *mockChainAdapter) Network() string {
	return m.network
}

func (m *mockChainAdapter) RPCClient() RPCClient {
	return nil // Not needed for registry tests
}

func (m *mockChainAdapter) SignatureScheme() SignatureScheme {
	return nil // Not needed for registry tests
}

func (m *mockChainAdapter) TransactionValidator() TransactionValidator {
	return nil // Not needed for registry tests
}

func TestRegistryIdempotent(t *testing.T) {
	// Create a fresh registry for this test
	registry := &Registry{
		adapters: make(map[string]ChainAdapter),
	}

	adapter1 := &mockChainAdapter{network: "test-network"}
	adapter2 := &mockChainAdapter{network: "test-network"}

	// First registration should succeed
	err := registry.Register(adapter1)
	assert.NoError(t, err, "First registration should succeed")

	// Second registration with same network should also succeed (idempotent)
	err = registry.Register(adapter2)
	assert.NoError(t, err, "Second registration should succeed (idempotent)")

	// Verify the second adapter replaced the first
	retrieved, err := registry.Get("test-network")
	assert.NoError(t, err)
	assert.Equal(t, adapter2, retrieved, "Second adapter should have replaced the first")
}

func TestRegistryConcurrentRegistration(t *testing.T) {
	// Create a fresh registry for this test
	registry := &Registry{
		adapters: make(map[string]ChainAdapter),
	}

	// Simulate concurrent registrations from multiple goroutines
	// This mimics the scenario where:
	// 1. Initial sync initialization registers adapters
	// 2. Background async health checks complete and re-register
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			adapter := &mockChainAdapter{network: "test-network"}
			err := registry.Register(adapter)
			assert.NoError(t, err, "Concurrent registration should not fail")
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify the network is registered
	assert.True(t, registry.IsSupported("test-network"))
}

func TestRegistryMultipleNetworks(t *testing.T) {
	registry := &Registry{
		adapters: make(map[string]ChainAdapter),
	}

	networks := []string{"base", "polygon", "avalanche", "solana"}
	for _, network := range networks {
		adapter := &mockChainAdapter{network: network}
		err := registry.Register(adapter)
		assert.NoError(t, err)
	}

	supported := registry.GetSupportedNetworks()
	assert.Len(t, supported, len(networks))

	for _, network := range networks {
		assert.True(t, registry.IsSupported(network))
	}
}

func TestRegistryUnregister(t *testing.T) {
	registry := &Registry{
		adapters: make(map[string]ChainAdapter),
	}

	adapter := &mockChainAdapter{network: "test-network"}
	err := registry.Register(adapter)
	assert.NoError(t, err)

	assert.True(t, registry.IsSupported("test-network"))

	registry.Unregister("test-network")
	assert.False(t, registry.IsSupported("test-network"))
}
