package chains

import (
	"fmt"
	"sync"

	"github.com/sigweihq/x402pay/pkg/constants"
)

// Registry manages chain adapters for different blockchain networks
type Registry struct {
	adapters map[string]ChainAdapter
	mu       sync.RWMutex
}

var (
	globalRegistry     *Registry
	globalRegistryOnce sync.Once

	// discoveredNetworks stores networks discovered from facilitators
	discoveredNetworks   []string
	discoveredNetworksMu sync.RWMutex
)

// InitGlobalRegistry initializes the global chain registry
func InitGlobalRegistry() *Registry {
	globalRegistryOnce.Do(func() {
		globalRegistry = &Registry{
			adapters: make(map[string]ChainAdapter),
		}
	})
	return globalRegistry
}

// GetGlobalRegistry returns the global chain registry (returns nil if not initialized)
func GetGlobalRegistry() *Registry {
	return globalRegistry
}

// Register registers a chain adapter (uses adapter.Network() as key)
// If an adapter already exists for the network, it will be replaced (idempotent)
func (r *Registry) Register(adapter ChainAdapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	network := adapter.Network()
	// Update existing adapter or register new one (idempotent)
	r.adapters[network] = adapter
	return nil
}

// Get retrieves a chain adapter by network name
func (r *Registry) Get(network string) (ChainAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapter, exists := r.adapters[network]
	if !exists {
		return nil, fmt.Errorf("no adapter registered for network: %s", network)
	}

	return adapter, nil
}

// GetSupportedNetworks returns a list of all registered networks
func (r *Registry) GetSupportedNetworks() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	networks := make([]string, 0, len(r.adapters))
	for network := range r.adapters {
		networks = append(networks, network)
	}
	return networks
}

// IsSupported checks if a network is supported
func (r *Registry) IsSupported(network string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.adapters[network]
	return exists
}

// Unregister removes a chain adapter (useful for testing)
func (r *Registry) Unregister(network string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.adapters, network)
}

// ResetGlobalRegistry resets the global registry (useful for testing)
func ResetGlobalRegistry() {
	globalRegistry = nil
	globalRegistryOnce = sync.Once{}
}

// SetDiscoveredNetworks stores networks discovered from facilitators
// This is called by processor.InitProcessorMap to enable auto-discovery
func SetDiscoveredNetworks(networks []string) {
	discoveredNetworksMu.Lock()
	defer discoveredNetworksMu.Unlock()
	discoveredNetworks = networks
}

// GetDiscoveredEVMNetworks returns EVM networks discovered from facilitators
// A network is considered EVM if it has a chain ID mapping
func GetDiscoveredEVMNetworks() []string {
	discoveredNetworksMu.RLock()
	defer discoveredNetworksMu.RUnlock()

	evmNetworks := make([]string, 0)
	for _, network := range discoveredNetworks {
		if _, isEVM := constants.NetworkToChainID[network]; isEVM {
			evmNetworks = append(evmNetworks, network)
		}
	}
	return evmNetworks
}

// GetDiscoveredSVMNetworks returns SVM networks discovered from facilitators
// A network is considered SVM if it does NOT have a chain ID mapping
func GetDiscoveredSVMNetworks() []string {
	discoveredNetworksMu.RLock()
	defer discoveredNetworksMu.RUnlock()

	svmNetworks := make([]string, 0)
	for _, network := range discoveredNetworks {
		if _, isEVM := constants.NetworkToChainID[network]; !isEVM {
			svmNetworks = append(svmNetworks, network)
		}
	}
	return svmNetworks
}
