package processor

import (
	"log/slog"
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

func TestInitProcessorMap(t *testing.T) {
	config := &ProcessorConfig{
		NetworkToFacilitatorURLs: map[string][]string{
			constants.NetworkBase:        {"https://facilitator1.com", "https://facilitator2.com"},
			constants.NetworkBaseSepolia: {"https://testnet1.com", "https://testnet2.com"},
		},
		CDPAPIKeyID:     "test-key-id",
		CDPAPIKeySecret: "test-secret",
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Reset state for testing
	processorMap = sync.Map{}
	processorMapOnce = sync.Once{}

	InitProcessorMap(config, logger)

	// Verify processors were created for each network
	baseProcessor := getProcessor(constants.NetworkBase)
	assert.NotNil(t, baseProcessor)

	sepoliaProcessor := getProcessor(constants.NetworkBaseSepolia)
	assert.NotNil(t, sepoliaProcessor)

	// Verify error for unknown network
	unknownProcessor := getProcessor("unknown-network")
	assert.Nil(t, unknownProcessor)
}

func TestProcessorFacilitatorConfigs(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Test with CDP credentials - should use CDP first, then also add URL-based clients for failover
	configWithCDP := &ProcessorConfig{
		NetworkToFacilitatorURLs: map[string][]string{
			constants.NetworkBase:        {"https://facilitator1.com", "https://facilitator2.com"},
			constants.NetworkBaseSepolia: {"https://testnet1.com", "https://testnet2.com"},
		},
		CDPAPIKeyID:     "test-key-id",
		CDPAPIKeySecret: "test-secret",
	}

	// Reset state for testing
	processorMap = sync.Map{}
	processorMapOnce = sync.Once{}

	InitProcessorMap(configWithCDP, logger)

	// When CDP credentials are present, should use CDP facilitator first, then URL-based clients
	testnetProcessor := getProcessor(constants.NetworkBaseSepolia)
	assert.Len(t, testnetProcessor.facilitatorClients, 3) // 1 CDP + 2 URLs
	assert.Equal(t, "https://api.cdp.coinbase.com/platform/v2/x402", testnetProcessor.facilitatorClients[0].URL)
	assert.Equal(t, "https://testnet1.com", testnetProcessor.facilitatorClients[1].URL)
	assert.Equal(t, "https://testnet2.com", testnetProcessor.facilitatorClients[2].URL)

	mainnetProcessor := getProcessor(constants.NetworkBase)
	assert.Len(t, mainnetProcessor.facilitatorClients, 3) // 1 CDP + 2 URLs
	assert.Equal(t, "https://api.cdp.coinbase.com/platform/v2/x402", mainnetProcessor.facilitatorClients[0].URL)
	assert.Equal(t, "https://facilitator1.com", mainnetProcessor.facilitatorClients[1].URL)
	assert.Equal(t, "https://facilitator2.com", mainnetProcessor.facilitatorClients[2].URL)

	// Test without CDP credentials - should use configured URLs
	configWithoutCDP := &ProcessorConfig{
		NetworkToFacilitatorURLs: map[string][]string{
			constants.NetworkBase:        {"https://facilitator1.com", "https://facilitator2.com"},
			constants.NetworkBaseSepolia: {"https://testnet1.com", "https://testnet2.com"},
		},
	}

	// Reset state for testing
	processorMap = sync.Map{}
	processorMapOnce = sync.Once{}

	InitProcessorMap(configWithoutCDP, logger)

	testnetProcessorNoCDP := getProcessor(constants.NetworkBaseSepolia)
	assert.Len(t, testnetProcessorNoCDP.facilitatorClients, 2)
	assert.Equal(t, "https://testnet1.com", testnetProcessorNoCDP.facilitatorClients[0].URL)
	assert.Equal(t, "https://testnet2.com", testnetProcessorNoCDP.facilitatorClients[1].URL)

	mainnetProcessorNoCDP := getProcessor(constants.NetworkBase)
	assert.Len(t, mainnetProcessorNoCDP.facilitatorClients, 2)
	assert.Equal(t, "https://facilitator1.com", mainnetProcessorNoCDP.facilitatorClients[0].URL)
	assert.Equal(t, "https://facilitator2.com", mainnetProcessorNoCDP.facilitatorClients[1].URL)
}

// MockError is a simple error type for testing
type MockError struct {
	message string
}

func (e *MockError) Error() string {
	return e.message
}
