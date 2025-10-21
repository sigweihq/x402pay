package processor

import (
	"log/slog"
	"os"
	"testing"

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

func TestNewPaymentProcessor(t *testing.T) {
	config := &FacilitatorConfig{
		FacilitatorURLs:        []string{"https://facilitator1.com", "https://facilitator2.com"},
		FacilitatorTestnetURLs: []string{"https://testnet1.com", "https://testnet2.com"},
		CDPAPIKeyID:            "test-key-id",
		CDPAPIKeySecret:        "test-secret",
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	processor := NewPaymentProcessor(config, logger)

	assert.NotNil(t, processor)
	assert.Equal(t, config, processor.config)
}

func TestGetFacilitatorConfigs(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Test with CDP credentials - should use CDP for both testnet and mainnet
	configWithCDP := &FacilitatorConfig{
		FacilitatorURLs:        []string{"https://facilitator1.com", "https://facilitator2.com"},
		FacilitatorTestnetURLs: []string{"https://testnet1.com", "https://testnet2.com"},
		CDPAPIKeyID:            "test-key-id",
		CDPAPIKeySecret:        "test-secret",
	}
	processorWithCDP := NewPaymentProcessor(configWithCDP, logger)

	// When CDP credentials are present, should use CDP facilitator
	testnetConfigs := processorWithCDP.GetFacilitatorConfigs(true)
	assert.Len(t, testnetConfigs, 1)
	assert.Equal(t, "https://api.cdp.coinbase.com/platform/v2/x402", testnetConfigs[0].URL)

	mainnetConfigs := processorWithCDP.GetFacilitatorConfigs(false)
	assert.Len(t, mainnetConfigs, 1)
	assert.Equal(t, "https://api.cdp.coinbase.com/platform/v2/x402", mainnetConfigs[0].URL)

	// Test without CDP credentials - should use configured URLs
	configWithoutCDP := &FacilitatorConfig{
		FacilitatorURLs:        []string{"https://facilitator1.com", "https://facilitator2.com"},
		FacilitatorTestnetURLs: []string{"https://testnet1.com", "https://testnet2.com"},
	}
	processorWithoutCDP := NewPaymentProcessor(configWithoutCDP, logger)

	testnetConfigsNoCDP := processorWithoutCDP.GetFacilitatorConfigs(true)
	assert.Len(t, testnetConfigsNoCDP, 2)
	assert.Equal(t, "https://testnet1.com", testnetConfigsNoCDP[0].URL)
	assert.Equal(t, "https://testnet2.com", testnetConfigsNoCDP[1].URL)

	mainnetConfigsNoCDP := processorWithoutCDP.GetFacilitatorConfigs(false)
	assert.Len(t, mainnetConfigsNoCDP, 2)
	assert.Equal(t, "https://facilitator1.com", mainnetConfigsNoCDP[0].URL)
	assert.Equal(t, "https://facilitator2.com", mainnetConfigsNoCDP[1].URL)
}

// MockError is a simple error type for testing
type MockError struct {
	message string
}

func (e *MockError) Error() string {
	return e.message
}
