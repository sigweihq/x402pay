package processor

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	x402types "github.com/coinbase/x402/go/pkg/types"
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
	assert.Len(t, baseProcessor.feePayerToClients[""], 2) // Both servers support base (no specific feePayer)

	sepoliaProcessor := getProcessor(constants.NetworkBaseSepolia)
	assert.NotNil(t, sepoliaProcessor)
	assert.Len(t, sepoliaProcessor.feePayerToClients[""], 1) // Only server1 supports sepolia (no specific feePayer)

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
		assert.Len(t, sepoliaProcessor.feePayerToClients[""], 2) // Both servers support sepolia (no specific feePayer)
		assert.Equal(t, server1.URL, sepoliaProcessor.feePayerToClients[""][0].URL)
		assert.Equal(t, server2.URL, sepoliaProcessor.feePayerToClients[""][1].URL)

		// Base should only have server1
		baseProcessor := getProcessor(constants.NetworkBase)
		assert.NotNil(t, baseProcessor)
		assert.Len(t, baseProcessor.feePayerToClients[""], 1) // Only server1 supports base (no specific feePayer)
		assert.Equal(t, server1.URL, baseProcessor.feePayerToClients[""][0].URL)
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
		assert.Len(t, sepoliaProcessor.feePayerToClients[""], 1)
		assert.Equal(t, server.URL, sepoliaProcessor.feePayerToClients[""][0].URL)

		baseProcessor := getProcessor(constants.NetworkBase)
		assert.NotNil(t, baseProcessor)
		assert.Len(t, baseProcessor.feePayerToClients[""], 1)
		assert.Equal(t, server.URL, baseProcessor.feePayerToClients[""][0].URL)
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

// mockFacilitatorServerWithHandlers creates a test HTTP server with custom handlers
func mockFacilitatorServerWithHandlers(handlers map[string]http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, ok := handlers[r.URL.Path]
		if ok {
			handler(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))
}

// createTestPaymentPayload creates a test PaymentPayload for testing
func createTestPaymentPayload(network, asset, value string) *x402types.PaymentPayload {
	return &x402types.PaymentPayload{
		X402Version: 1,
		Scheme:      "exact",
		Network:     network,
		Payload: &x402types.ExactEvmPayload{
			Signature: "0xtest_signature",
			Authorization: &x402types.ExactEvmPayloadAuthorization{
				From:        "0xFromAddress",
				To:          asset,
				Value:       value,
				ValidAfter:  "0",
				ValidBefore: "999999999999",
				Nonce:       "1",
			},
		},
	}
}

func TestProcessTransfer(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	t.Run("successful transfer with USDC on Base", func(t *testing.T) {
		// Create mock facilitator server
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBase},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.VerifyResponse{
					IsValid: true,
					Payer:   stringPtr("0xFromAddress"),
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/settle": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.SettleResponse{
					Success:     true,
					Transaction: "0xtxhash123",
					Network:     constants.NetworkBase,
					Payer:       stringPtr("0xFromAddress"),
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			constants.USDCAddressBase,
			"1000000", // 1 USDC (6 decimals)
		)

		// Execute test
		settleResp, err := ProcessTransfer(
			paymentPayload,
			"https://example.com/api/resource",
			constants.USDCAddressBase,
		)

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, settleResp)
		assert.True(t, settleResp.Success)
		assert.Equal(t, "0xtxhash123", settleResp.Transaction)
		assert.Equal(t, constants.NetworkBase, settleResp.Network)
	})

	t.Run("successful transfer with USDC on Base Sepolia", func(t *testing.T) {
		// Create mock facilitator server
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBaseSepolia},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.VerifyResponse{
					IsValid: true,
					Payer:   stringPtr("0xFromAddress"),
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/settle": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.SettleResponse{
					Success:     true,
					Transaction: "0xtxhash456",
					Network:     constants.NetworkBaseSepolia,
					Payer:       stringPtr("0xFromAddress"),
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBaseSepolia,
			constants.NetworkToUSDCAddress[constants.NetworkBaseSepolia],
			"5000000", // 5 USDC (6 decimals)
		)

		// Execute test
		settleResp, err := ProcessTransfer(
			paymentPayload,
			"https://example.com/api/resource",
			constants.NetworkToUSDCAddress[constants.NetworkBaseSepolia],
		)

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, settleResp)
		assert.True(t, settleResp.Success)
		assert.Equal(t, "0xtxhash456", settleResp.Transaction)
		assert.Equal(t, constants.NetworkBaseSepolia, settleResp.Network)
	})

	t.Run("successful transfer with USDC case-insensitive matching", func(t *testing.T) {
		// Create mock facilitator server
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBase},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.VerifyResponse{
					IsValid: true,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/settle": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.SettleResponse{
					Success:     true,
					Transaction: "0xtxhash789",
					Network:     constants.NetworkBase,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Test with lowercase USDC address
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			constants.NetworkToUSDCAddress[constants.NetworkBase],
			"1000000",
		)

		// Execute test with lowercase asset address
		settleResp, err := ProcessTransfer(
			paymentPayload,
			"https://example.com/api/resource",
			strings.ToLower(constants.USDCAddressBase),
		)

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, settleResp)
		assert.True(t, settleResp.Success)
	})

	t.Run("successful transfer with non-USDC asset", func(t *testing.T) {
		// Create mock facilitator server
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBase},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.VerifyResponse{
					IsValid: true,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/settle": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.SettleResponse{
					Success:     true,
					Transaction: "0xtxhashABC",
					Network:     constants.NetworkBase,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload with custom ERC20 token
		customToken := "0x1234567890123456789012345678901234567890"
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			customToken,
			"1000000000000000000", // 1 token (18 decimals)
		)

		// Execute test
		settleResp, err := ProcessTransfer(
			paymentPayload,
			"https://example.com/api/resource",
			customToken,
		)

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, settleResp)
		assert.True(t, settleResp.Success)
	})

	t.Run("error when no processor configured for network", func(t *testing.T) {
		// Reset processor map to empty state
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			constants.USDCAddressBase,
			"1000000",
		)

		// Execute test
		settleResp, err := ProcessTransfer(
			paymentPayload,
			"https://example.com/api/resource",
			constants.USDCAddressBase,
		)

		// Verify error
		assert.Error(t, err)
		assert.Nil(t, settleResp)
		assert.Contains(t, err.Error(), "no processor configured for network")
	})

	t.Run("error when verification fails", func(t *testing.T) {
		// Create mock facilitator server that fails verification
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBase},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				invalidReason := "insufficient funds"
				response := x402types.VerifyResponse{
					IsValid:       false,
					InvalidReason: &invalidReason,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			constants.USDCAddressBase,
			"1000000",
		)

		// Execute test
		settleResp, err := ProcessTransfer(
			paymentPayload,
			"https://example.com/api/resource",
			constants.USDCAddressBase,
		)

		// Verify error
		assert.Error(t, err)
		assert.Nil(t, settleResp)
		assert.Contains(t, err.Error(), "insufficient funds")
	})

	t.Run("error when settlement fails", func(t *testing.T) {
		// Create mock facilitator server that fails settlement
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBase},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.VerifyResponse{
					IsValid: true,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/settle": func(w http.ResponseWriter, r *http.Request) {
				errorReason := "settlement failed: network error"
				response := x402types.SettleResponse{
					Success:     false,
					ErrorReason: &errorReason,
					Network:     constants.NetworkBase,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			constants.USDCAddressBase,
			"1000000",
		)

		// Execute test
		settleResp, err := ProcessTransfer(
			paymentPayload,
			"https://example.com/api/resource",
			constants.USDCAddressBase,
		)

		// Verify error
		assert.Error(t, err)
		assert.Nil(t, settleResp)
		assert.Contains(t, err.Error(), "settlement failed")
	})
}

func TestProcessTransfertWithCallback(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	t.Run("successful transfer with callback", func(t *testing.T) {
		verifiedCallbackCalled := false
		settledCallbackCalled := false
		var capturedPayload *x402types.PaymentPayload
		var capturedRequirements *x402types.PaymentRequirements
		var capturedSettleResponse *x402types.SettleResponse

		onVerified := func(payload any, requirements *x402types.PaymentRequirements) error {
			verifiedCallbackCalled = true
			capturedPayload = payload.(*x402types.PaymentPayload)
			capturedRequirements = requirements
			return nil
		}

		onSettled := func(payload any, requirements *x402types.PaymentRequirements, settleResp *x402types.SettleResponse) error {
			settledCallbackCalled = true
			capturedSettleResponse = settleResp
			return nil
		}

		// Create mock facilitator server
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBase},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.VerifyResponse{
					IsValid: true,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/settle": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.SettleResponse{
					Success:     true,
					Transaction: "0xtxhash123",
					Network:     constants.NetworkBase,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			constants.USDCAddressBase,
			"1000000",
		)

		resourceURL := "https://example.com/api/resource"

		// Execute test
		callbacks := &PaymentCallbacks{
			OnVerified: onVerified,
			OnSettled:  onSettled,
		}
		settleResp, err := ProcessTransferWithCallbacks(
			paymentPayload,
			resourceURL,
			constants.USDCAddressBase,
			callbacks,
		)

		// Verify results
		assert.NoError(t, err)
		assert.NotNil(t, settleResp)
		assert.True(t, settleResp.Success)
		assert.True(t, verifiedCallbackCalled, "onVerified callback should have been called")
		assert.True(t, settledCallbackCalled, "onSettled callback should have been called")
		assert.NotNil(t, capturedPayload)
		assert.NotNil(t, capturedRequirements)
		assert.NotNil(t, capturedSettleResponse)

		// Verify SettleResponse was captured correctly
		assert.True(t, capturedSettleResponse.Success)
		assert.Equal(t, "0xtxhash123", capturedSettleResponse.Transaction)
		assert.Equal(t, constants.NetworkBase, capturedSettleResponse.Network)

		// Verify PaymentRequirements was constructed correctly
		assert.Equal(t, "exact", capturedRequirements.Scheme)
		assert.Equal(t, constants.NetworkBase, capturedRequirements.Network)
		assert.Equal(t, "1000000", capturedRequirements.MaxAmountRequired)
		assert.Equal(t, resourceURL, capturedRequirements.Resource)
		assert.Equal(t, constants.USDCAddressBase, capturedRequirements.PayTo)
		assert.Equal(t, constants.USDCAddressBase, capturedRequirements.Asset)
		assert.Contains(t, capturedRequirements.Description, resourceURL)
	})

	t.Run("error when onVerified callback fails", func(t *testing.T) {
		onVerified := func(payload any, requirements *x402types.PaymentRequirements) error {
			return assert.AnError
		}

		onSettled := func(payload any, requirements *x402types.PaymentRequirements, settleResp *x402types.SettleResponse) error {
			return nil
		}

		// Create mock facilitator server
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBase},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.VerifyResponse{
					IsValid: true,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			constants.USDCAddressBase,
			"1000000",
		)

		// Execute test
		callbacks := &PaymentCallbacks{
			OnVerified: onVerified,
			OnSettled:  onSettled,
		}
		settleResp, err := ProcessTransferWithCallbacks(
			paymentPayload,
			"https://example.com/api/resource",
			constants.USDCAddressBase,
			callbacks,
		)

		// Verify error
		assert.Error(t, err)
		assert.Nil(t, settleResp)
		assert.Contains(t, err.Error(), "verification callback failed")
	})

	t.Run("error when onSettled callback fails", func(t *testing.T) {
		onVerified := func(payload any, requirements *x402types.PaymentRequirements) error {
			return nil
		}

		onSettled := func(payload any, requirements *x402types.PaymentRequirements, settleResp *x402types.SettleResponse) error {
			return assert.AnError
		}

		// Create mock facilitator server
		handlers := map[string]http.HandlerFunc{
			"/supported": func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"kinds": []map[string]string{
						{"scheme": "exact", "network": constants.NetworkBase},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/verify": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.VerifyResponse{
					IsValid: true,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			"/settle": func(w http.ResponseWriter, r *http.Request) {
				response := x402types.SettleResponse{
					Success:     true,
					Transaction: "0xtxhash123",
					Network:     constants.NetworkBase,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
		}
		server := mockFacilitatorServerWithHandlers(handlers)
		defer server.Close()

		// Reset and initialize processor
		processorMap = sync.Map{}
		processorMapOnce = sync.Once{}
		config := &ProcessorConfig{
			FacilitatorURLs: []string{server.URL},
		}
		InitProcessorMap(config, logger)

		// Create test payment payload
		paymentPayload := createTestPaymentPayload(
			constants.NetworkBase,
			constants.USDCAddressBase,
			"1000000",
		)

		// Execute test
		callbacks := &PaymentCallbacks{
			OnVerified: onVerified,
			OnSettled:  onSettled,
		}
		settleResp, err := ProcessTransferWithCallbacks(
			paymentPayload,
			"https://example.com/api/resource",
			constants.USDCAddressBase,
			callbacks,
		)

		// Verify error - settlement succeeded but callback failed
		assert.Error(t, err)
		assert.NotNil(t, settleResp, "settle response should be returned even when callback fails")
		assert.True(t, settleResp.Success, "settlement itself should have succeeded")
		assert.Equal(t, "0xtxhash123", settleResp.Transaction)
		assert.Contains(t, err.Error(), "settlement callback failed")
	})
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
