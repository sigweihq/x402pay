package processor

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/sigweihq/x402pay/pkg/constants"
	"github.com/stretchr/testify/assert"
)

func TestShouldRetryWithNextFacilitator(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error should not retry",
			err:      nil,
			expected: false,
		},
		{
			name:     "timeout error should retry",
			err:      &MockError{"request timeout"},
			expected: true,
		},
		{
			name:     "connection refused should retry",
			err:      &MockError{"connection refused"},
			expected: true,
		},
		{
			name:     "network unreachable should retry",
			err:      &MockError{"network is unreachable"},
			expected: true,
		},
		{
			name:     "host not found should retry",
			err:      &MockError{"no such host"},
			expected: true,
		},
		{
			name:     "context deadline exceeded should retry",
			err:      &MockError{"context deadline exceeded"},
			expected: true,
		},
		{
			name:     "HTTP 500 should retry",
			err:      &MockError{"HTTP 500 Internal Server Error"},
			expected: true,
		},
		{
			name:     "HTTP 502 should retry",
			err:      &MockError{"HTTP 502 Bad Gateway"},
			expected: true,
		},
		{
			name:     "HTTP 503 should retry",
			err:      &MockError{"HTTP 503 Service Unavailable"},
			expected: true,
		},
		{
			name:     "HTTP 504 should retry",
			err:      &MockError{"HTTP 504 Gateway Timeout"},
			expected: true,
		},
		{
			name:     "unauthorized should retry",
			err:      &MockError{"unauthorized access"},
			expected: true,
		},
		{
			name:     "authentication failed should retry",
			err:      &MockError{"authentication failed"},
			expected: true,
		},
		{
			name:     "HTTP 401 should retry",
			err:      &MockError{"HTTP 401 Unauthorized"},
			expected: true,
		},
		{
			name:     "insufficient funds should not retry",
			err:      &MockError{"insufficient funds"},
			expected: false,
		},
		{
			name:     "invalid signature should not retry",
			err:      &MockError{"invalid signature"},
			expected: false,
		},
		{
			name:     "HTTP 400 should not retry",
			err:      &MockError{"HTTP 400 Bad Request"},
			expected: false,
		},
		{
			name:     "generic error should not retry",
			err:      &MockError{"some generic error"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldRetryWithNextFacilitator(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// mockFacilitatorServer creates a test HTTP server that responds to /supported endpoint
func mockFacilitatorServer(networks []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/supported" {
			kinds := make([]map[string]string, len(networks))
			for i, network := range networks {
				kinds[i] = map[string]string{
					"scheme":  "exact",
					"network": network,
				}
			}
			response := map[string]any{
				"kinds": kinds,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	}))
}

func TestInitProcessorMap(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Create mock facilitator servers
	server1 := mockFacilitatorServer([]string{constants.NetworkBase, constants.NetworkBaseSepolia})
	defer server1.Close()

	server2 := mockFacilitatorServer([]string{constants.NetworkBase})
	defer server2.Close()

	config := &ProcessorConfig{
		FacilitatorURLs: []string{server1.URL, server2.URL},
	}

	// Reset state for testing
	processorMap = sync.Map{}
	processorMapOnce = sync.Once{}

	InitProcessorMap(config, logger)

	// Verify processors were created for each network
	baseProcessor := getProcessor(constants.NetworkBase)
	assert.NotNil(t, baseProcessor)
	assert.Len(t, baseProcessor.facilitatorClients, 2) // Both servers support base

	sepoliaProcessor := getProcessor(constants.NetworkBaseSepolia)
	assert.NotNil(t, sepoliaProcessor)
	assert.Len(t, sepoliaProcessor.facilitatorClients, 1) // Only server1 supports sepolia

	// Verify error for unknown network
	unknownProcessor := getProcessor("unknown-network")
	assert.Nil(t, unknownProcessor)
}

func TestProcessorFacilitatorConfigs(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	t.Run("multiple facilitators with different network support", func(t *testing.T) {
		// Create mock facilitator servers
		// Mock for https://facilitator.x402.rs/ - supports both networks
		server1 := mockFacilitatorServer([]string{constants.NetworkBase, constants.NetworkBaseSepolia})
		defer server1.Close()

		// Mock for https://www.x402.org/facilitator - supports only sepolia
		server2 := mockFacilitatorServer([]string{constants.NetworkBaseSepolia})
		defer server2.Close()

		config := &ProcessorConfig{
			FacilitatorURLs: []string{server1.URL, server2.URL},
		}

		// Reset state for testing
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}

		InitProcessorMap(config, logger)

		// Sepolia should have both facilitators
		sepoliaProcessor := getProcessor(constants.NetworkBaseSepolia)
		assert.NotNil(t, sepoliaProcessor)
		assert.Len(t, sepoliaProcessor.facilitatorClients, 2) // Both servers support sepolia
		assert.Equal(t, server1.URL, sepoliaProcessor.facilitatorClients[0].URL)
		assert.Equal(t, server2.URL, sepoliaProcessor.facilitatorClients[1].URL)

		// Base should only have server1
		baseProcessor := getProcessor(constants.NetworkBase)
		assert.NotNil(t, baseProcessor)
		assert.Len(t, baseProcessor.facilitatorClients, 1) // Only server1 supports base
		assert.Equal(t, server1.URL, baseProcessor.facilitatorClients[0].URL)
	})

	t.Run("single facilitator supporting multiple networks", func(t *testing.T) {
		// Create mock facilitator that supports both networks
		server := mockFacilitatorServer([]string{constants.NetworkBase, constants.NetworkBaseSepolia})
		defer server.Close()

		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}

		// Reset state for testing
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}

		InitProcessorMap(config, logger)

		// Both networks should have the same facilitator
		sepoliaProcessor := getProcessor(constants.NetworkBaseSepolia)
		assert.NotNil(t, sepoliaProcessor)
		assert.Len(t, sepoliaProcessor.facilitatorClients, 1)
		assert.Equal(t, server.URL, sepoliaProcessor.facilitatorClients[0].URL)

		baseProcessor := getProcessor(constants.NetworkBase)
		assert.NotNil(t, baseProcessor)
		assert.Len(t, baseProcessor.facilitatorClients, 1)
		assert.Equal(t, server.URL, baseProcessor.facilitatorClients[0].URL)
	})

	t.Run("no facilitators configured", func(t *testing.T) {
		config := &ProcessorConfig{
			FacilitatorURLs: []string{},
		}

		// Reset state for testing
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}

		InitProcessorMap(config, logger)

		// No processors should be created
		baseProcessor := getProcessor(constants.NetworkBase)
		assert.Nil(t, baseProcessor)

		sepoliaProcessor := getProcessor(constants.NetworkBaseSepolia)
		assert.Nil(t, sepoliaProcessor)
	})
}

func TestGetSupportedNetworks(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	t.Run("no networks configured", func(t *testing.T) {
		// Reset state for testing
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}

		config := &ProcessorConfig{
			FacilitatorURLs: []string{},
		}
		InitProcessorMap(config, logger)

		networks := GetSupportedNetworks()
		assert.Empty(t, networks)
	})

	t.Run("single network configured", func(t *testing.T) {
		// Create mock facilitator server supporting only base
		server := mockFacilitatorServer([]string{constants.NetworkBase})
		defer server.Close()

		// Reset state for testing
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}

		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		networks := GetSupportedNetworks()
		assert.Len(t, networks, 1)
		assert.Contains(t, networks, constants.NetworkBase)
	})

	t.Run("multiple networks configured", func(t *testing.T) {
		// Create mock facilitator server supporting multiple networks
		server := mockFacilitatorServer([]string{
			constants.NetworkBase,
			constants.NetworkBaseSepolia,
		})
		defer server.Close()

		// Reset state for testing
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}

		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		networks := GetSupportedNetworks()
		assert.Len(t, networks, 2)
		assert.Contains(t, networks, constants.NetworkBase)
		assert.Contains(t, networks, constants.NetworkBaseSepolia)
	})

	t.Run("multiple facilitators with different network support", func(t *testing.T) {
		// Create mock facilitator servers with different network support
		server1 := mockFacilitatorServer([]string{constants.NetworkBase})
		defer server1.Close()

		server2 := mockFacilitatorServer([]string{constants.NetworkBaseSepolia})
		defer server2.Close()

		// Reset state for testing
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}

		config := &ProcessorConfig{
			FacilitatorURLs: []string{server1.URL, server2.URL},
		}
		InitProcessorMap(config, logger)

		networks := GetSupportedNetworks()
		assert.Len(t, networks, 2)
		assert.Contains(t, networks, constants.NetworkBase)
		assert.Contains(t, networks, constants.NetworkBaseSepolia)
	})

	t.Run("overlapping network support from multiple facilitators", func(t *testing.T) {
		// Both facilitators support the same networks
		server1 := mockFacilitatorServer([]string{constants.NetworkBase, constants.NetworkBaseSepolia})
		defer server1.Close()

		server2 := mockFacilitatorServer([]string{constants.NetworkBase})
		defer server2.Close()

		// Reset state for testing
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}

		config := &ProcessorConfig{
			FacilitatorURLs: []string{server1.URL, server2.URL},
		}
		InitProcessorMap(config, logger)

		networks := GetSupportedNetworks()
		// Should still return unique networks (no duplicates)
		assert.Len(t, networks, 2)
		assert.Contains(t, networks, constants.NetworkBase)
		assert.Contains(t, networks, constants.NetworkBaseSepolia)
	})
}

// MockError is a simple error type for testing
type MockError struct {
	message string
}

func (e *MockError) Error() string {
	return e.message
}
