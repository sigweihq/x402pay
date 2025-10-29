package processor

import (
	"log/slog"
	"os"
	"testing"

	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/sigweihq/x402pay/pkg/chains/evm"
	"github.com/stretchr/testify/assert"
)

func TestExtractTransactionHash(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Initialize EVM chains with test endpoints
	testEndpoints := map[string][]string{
		"base": {"https://mainnet.base.org"},
	}
	err := evm.InitEVMChainsWithEndpoints(logger, testEndpoints)
	assert.NoError(t, err)

	tests := []struct {
		name          string
		settleResp    *x402types.SettleResponse
		expected      string
		expectedError bool
	}{
		{
			name: "valid transaction hash with 0x prefix",
			settleResp: &x402types.SettleResponse{
				Transaction: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Network:     "base",
			},
			expected:      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedError: false,
		},
		{
			name: "valid transaction hash without 0x prefix",
			settleResp: &x402types.SettleResponse{
				Transaction: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Network:     "base",
			},
			expected:      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedError: false,
		},
		{
			name: "empty transaction hash",
			settleResp: &x402types.SettleResponse{
				Transaction: "",
				Network:     "base",
			},
			expected:      "",
			expectedError: true,
		},
		{
			name: "invalid transaction hash format",
			settleResp: &x402types.SettleResponse{
				Transaction: "0x123invalid",
				Network:     "base",
			},
			expected:      "",
			expectedError: true,
		},
		{
			name: "missing network field",
			settleResp: &x402types.SettleResponse{
				Transaction: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Network:     "",
			},
			expected:      "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractTransactionHash(tt.settleResp)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGlobalRPCManagerCreation(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Initialize EVM chains with test endpoints (avoids network calls)
	testEndpoints := map[string][]string{
		"base":         {"https://mainnet.base.org"},
		"base-sepolia": {"https://sepolia.base.org"},
	}
	err := evm.InitEVMChainsWithEndpoints(logger, testEndpoints)
	assert.NoError(t, err)

	// Verify that the chain registry was initialized
	registry := chains.GetGlobalRegistry()
	assert.NotNil(t, registry)
}

func TestProcessorWithBlockchainVerification(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Create a test processor with empty feePayer map for testing structure
	processor := &PaymentProcessor{
		feePayerToClients: make(map[string][]*facilitatorclient.FacilitatorClient),
		logger:            logger,
	}

	assert.NotNil(t, processor)
	assert.Equal(t, logger, processor.logger)

	// Initialize and verify chain registry with test endpoints (avoids network calls)
	testEndpoints := map[string][]string{
		"base":         {"https://mainnet.base.org"},
		"base-sepolia": {"https://sepolia.base.org"},
	}
	err := evm.InitEVMChainsWithEndpoints(logger, testEndpoints)
	assert.NoError(t, err)

	registry := chains.GetGlobalRegistry()
	assert.NotNil(t, registry)
}
