package processor

import (
	"log/slog"
	"os"
	"testing"

	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestExtractTransactionHash(t *testing.T) {
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

	// Initialize the global manager
	InitGlobalRPCManager(logger)

	rpcManager := GetGlobalRPCManager()

	assert.NotNil(t, rpcManager)
	assert.NotNil(t, rpcManager.endpoints)
	assert.Equal(t, logger, rpcManager.logger)
}

func TestProcessorWithBlockchainVerification(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Create a test processor with empty client list for testing structure
	processor := &PaymentProcessor{
		facilitatorClients: []*facilitatorclient.FacilitatorClient{},
		logger:             logger,
	}

	assert.NotNil(t, processor)
	assert.Equal(t, logger, processor.logger)

	// Initialize and verify global RPC manager
	InitGlobalRPCManager(logger)
	rpcManager := GetGlobalRPCManager()
	assert.NotNil(t, rpcManager)
}
