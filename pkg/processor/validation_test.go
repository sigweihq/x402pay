package processor

import (
	"log/slog"
	"os"
	"testing"

	"x402pay/pkg/constants"

	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestExtractTransactionHash(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	processor := &PaymentProcessor{
		logger: logger,
	}

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
			},
			expected:      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedError: false,
		},
		{
			name: "valid transaction hash without 0x prefix",
			settleResp: &x402types.SettleResponse{
				Transaction: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			expected:      "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedError: false,
		},
		{
			name: "empty transaction hash",
			settleResp: &x402types.SettleResponse{
				Transaction: "",
			},
			expected:      "",
			expectedError: true,
		},
		{
			name: "invalid transaction hash format",
			settleResp: &x402types.SettleResponse{
				Transaction: "0x123invalid",
			},
			expected:      "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.extractTransactionHash(tt.settleResp)

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

	// Initialize the global manager
	InitGlobalRPCManager(logger)

	rpcManager := GetGlobalRPCManager()

	assert.NotNil(t, rpcManager)
	assert.NotNil(t, rpcManager.endpoints)
	assert.Equal(t, logger, rpcManager.logger)
}

func TestProcessorWithBlockchainVerification(t *testing.T) {
	config := &FacilitatorsConfig{
		networkToFacilitatorURLs: map[string][]string{
			constants.NetworkBaseSepolia: []string{"https://testnet.example.com"},
		},
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	processor := NewPaymentProcessor(config, logger)

	assert.NotNil(t, processor)
	assert.Equal(t, logger, processor.logger)
	assert.Equal(t, config, processor.config)

	// Initialize and verify global RPC manager
	InitGlobalRPCManager(logger)
	rpcManager := GetGlobalRPCManager()
	assert.NotNil(t, rpcManager)
}
