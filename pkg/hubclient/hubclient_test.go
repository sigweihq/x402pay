package hubclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coinbase/x402/go/pkg/types"
	x402paytypes "github.com/sigweihq/x402pay/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

func TestNewHubClient(t *testing.T) {
	tests := []struct {
		name           string
		config         *types.FacilitatorConfig
		expectedURL    string
		expectTimeout  bool
		timeoutValue   time.Duration
	}{
		{
			name:          "creates client with default config when nil",
			config:        nil,
			expectedURL:   DefaultHubURL,
			expectTimeout: false,
		},
		{
			name: "creates client with custom URL",
			config: &types.FacilitatorConfig{
				URL: "https://custom.hub.com",
			},
			expectedURL:   "https://custom.hub.com",
			expectTimeout: false,
		},
		{
			name: "creates client with custom timeout",
			config: &types.FacilitatorConfig{
				URL: "https://custom.hub.com",
				Timeout: func() time.Duration {
					return 5 * time.Second
				},
			},
			expectedURL:   "https://custom.hub.com",
			expectTimeout: true,
			timeoutValue:  5 * time.Second,
		},
		{
			name: "creates client with auth headers function",
			config: &types.FacilitatorConfig{
				URL: DefaultHubURL,
				CreateAuthHeaders: func() (map[string]map[string]string, error) {
					return map[string]map[string]string{
						"verify": {"Authorization": "Bearer token"},
					}, nil
				},
			},
			expectedURL:   DefaultHubURL,
			expectTimeout: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewHubClient(tt.config)

			assert.NotNil(t, client)
			assert.Equal(t, tt.expectedURL, client.URL)
			assert.NotNil(t, client.HTTPClient)

			if tt.expectTimeout {
				assert.Equal(t, tt.timeoutValue, client.HTTPClient.Timeout)
			}

			if tt.config != nil && tt.config.CreateAuthHeaders != nil {
				assert.NotNil(t, client.CreateAuthHeaders)
			}
		})
	}
}

func TestHubClient_Verify(t *testing.T) {
	tests := []struct {
		name               string
		payload            *types.PaymentPayload
		requirements       *types.PaymentRequirements
		serverResponse     *types.VerifyResponse
		serverStatusCode   int
		serverError        bool
		expectedError      bool
		errorContains      string
		authHeaders        map[string]map[string]string
		authHeadersError   error
		validateRequest    func(*testing.T, *http.Request)
	}{
		{
			name: "successful verification",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			serverResponse: &types.VerifyResponse{
				IsValid: true,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name: "verification with auth headers",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			serverResponse: &types.VerifyResponse{
				IsValid: true,
			},
			serverStatusCode: http.StatusOK,
			authHeaders: map[string]map[string]string{
				"verify": {
					"Authorization": "Bearer test-token",
					"X-Custom":      "custom-value",
				},
			},
			expectedError: false,
			validateRequest: func(t *testing.T, req *http.Request) {
				assert.Equal(t, "Bearer test-token", req.Header.Get("Authorization"))
				assert.Equal(t, "custom-value", req.Header.Get("X-Custom"))
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			},
		},
		{
			name: "verification returns invalid",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			serverResponse: &types.VerifyResponse{
				IsValid:       false,
				InvalidReason: stringPtr("insufficient funds"),
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name: "server returns error status",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			serverStatusCode: http.StatusInternalServerError,
			expectedError:    true,
			errorContains:    "failed to verify payment",
		},
		{
			name: "server returns bad request",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			serverStatusCode: http.StatusBadRequest,
			expectedError:    true,
			errorContains:    "failed to verify payment",
		},
		{
			name: "invalid JSON response",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			serverStatusCode: http.StatusOK,
			serverError:      true,
			expectedError:    true,
			errorContains:    "failed to decode verify response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Validate request method and path
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/verify", r.URL.Path)

				// Validate request body
				var reqBody map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				require.NoError(t, err)
				assert.Equal(t, float64(1), reqBody["x402Version"])
				assert.NotNil(t, reqBody["paymentPayload"])
				assert.NotNil(t, reqBody["paymentRequirements"])

				// Call custom validation if provided
				if tt.validateRequest != nil {
					tt.validateRequest(t, r)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatusCode)

				if tt.serverError {
					w.Write([]byte("invalid json"))
				} else if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			config := &types.FacilitatorConfig{
				URL: server.URL,
			}
			if tt.authHeaders != nil {
				config.CreateAuthHeaders = func() (map[string]map[string]string, error) {
					if tt.authHeadersError != nil {
						return nil, tt.authHeadersError
					}
					return tt.authHeaders, nil
				}
			}

			client := NewHubClient(config)
			resp, err := client.Verify(tt.payload, tt.requirements)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.serverResponse.IsValid, resp.IsValid)
			}
		})
	}
}

func TestHubClient_Settle(t *testing.T) {
	tests := []struct {
		name             string
		payload          *types.PaymentPayload
		requirements     *types.PaymentRequirements
		confirm          bool
		useDbId          bool
		serverResponse   *types.SettleResponse
		serverStatusCode int
		serverError      bool
		expectedError    bool
		errorContains    string
		authHeaders      map[string]map[string]string
		validateRequest  func(*testing.T, *http.Request)
	}{
		{
			name: "successful settlement",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			confirm: true,
			useDbId: false,
			serverResponse: &types.SettleResponse{
				Success: true,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name: "settlement with confirm false",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			confirm: false,
			useDbId: false,
			serverResponse: &types.SettleResponse{
				Success: true,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
			validateRequest: func(t *testing.T, req *http.Request) {
				// Note: request body is already read by the server handler
			},
		},
		{
			name: "settlement with useDbId true",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			confirm: true,
			useDbId: true,
			serverResponse: &types.SettleResponse{
				Success: true,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
			validateRequest: func(t *testing.T, req *http.Request) {
				// Note: request body is already read by the server handler
			},
		},
		{
			name: "settlement with auth headers",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			confirm: true,
			useDbId: false,
			serverResponse: &types.SettleResponse{
				Success: true,
			},
			serverStatusCode: http.StatusOK,
			authHeaders: map[string]map[string]string{
				"settle": {
					"Authorization": "Bearer settle-token",
					"X-Api-Key":     "api-key",
				},
			},
			expectedError: false,
			validateRequest: func(t *testing.T, req *http.Request) {
				assert.Equal(t, "Bearer settle-token", req.Header.Get("Authorization"))
				assert.Equal(t, "api-key", req.Header.Get("X-Api-Key"))
			},
		},
		{
			name: "server returns error status",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			confirm:          true,
			useDbId:          false,
			serverStatusCode: http.StatusInternalServerError,
			expectedError:    true,
			errorContains:    "failed to settle payment",
		},
		{
			name: "invalid JSON response",
			payload: &types.PaymentPayload{
				X402Version: 1,
				Network:     "base",
			},
			requirements: &types.PaymentRequirements{
				Network: "base",
				Asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			},
			confirm:          true,
			useDbId:          false,
			serverStatusCode: http.StatusOK,
			serverError:      true,
			expectedError:    true,
			errorContains:    "failed to decode settle response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Validate request method and path
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/settle", r.URL.Path)

				// Validate request body
				var reqBody map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				require.NoError(t, err)
				assert.Equal(t, float64(1), reqBody["x402Version"])
				assert.NotNil(t, reqBody["paymentPayload"])
				assert.NotNil(t, reqBody["paymentRequirements"])
				assert.Equal(t, tt.confirm, reqBody["confirm"])
				assert.Equal(t, tt.useDbId, reqBody["useDbId"])

				// Call custom validation if provided
				if tt.validateRequest != nil {
					tt.validateRequest(t, r)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatusCode)

				if tt.serverError {
					w.Write([]byte("invalid json"))
				} else if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			config := &types.FacilitatorConfig{
				URL: server.URL,
			}
			if tt.authHeaders != nil {
				config.CreateAuthHeaders = func() (map[string]map[string]string, error) {
					return tt.authHeaders, nil
				}
			}

			client := NewHubClient(config)
			resp, err := client.SettleWithOptions(tt.payload, tt.requirements, tt.confirm, tt.useDbId)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.serverResponse.Success, resp.Success)
			}
		})
	}
}

func TestHubClient_Transfer(t *testing.T) {
	tests := []struct {
		name             string
		payload          *types.ExactEvmPayload
		network          string
		asset            string
		confirm          bool
		serverResponse   *types.SettleResponse
		serverStatusCode int
		expectedError    bool
		validateRequest  func(*testing.T, *http.Request)
	}{
		{
			name: "successful transfer",
			payload: &types.ExactEvmPayload{
				Signature: "0x1234567890abcdef",
				Authorization: &types.ExactEvmPayloadAuthorization{
					From:        "0xSender",
					To:          "0xRecipient",
					Value:       "1000000",
					ValidAfter:  "0",
					ValidBefore: "9999999999",
					Nonce:       "1",
				},
			},
			network: "base",
			asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			confirm: true,
			serverResponse: &types.SettleResponse{
				Success: true,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
			validateRequest: func(t *testing.T, req *http.Request) {
				// Note: request body is already read by the server handler
			},
		},
		{
			name: "transfer with confirm false",
			payload: &types.ExactEvmPayload{
				Signature: "0xabcdef1234567890",
				Authorization: &types.ExactEvmPayloadAuthorization{
					From:        "0xSender2",
					To:          "0xRecipient2",
					Value:       "2000000",
					ValidAfter:  "0",
					ValidBefore: "9999999999",
					Nonce:       "2",
				},
			},
			network: "base",
			asset:   "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			confirm: false,
			serverResponse: &types.SettleResponse{
				Success: true,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
			validateRequest: func(t *testing.T, req *http.Request) {
				// Note: request body is already read by the server handler
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/transfer", r.URL.Path)

				if tt.validateRequest != nil {
					tt.validateRequest(t, r)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := NewHubClient(&types.FacilitatorConfig{
				URL: server.URL,
			})

			resp, err := client.Transfer(tt.payload, tt.network, tt.asset, tt.confirm)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.serverResponse.Success, resp.Success)
			}
		})
	}
}

func TestHubClient_AuthHeadersError(t *testing.T) {
	t.Run("verify returns error when CreateAuthHeaders fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("should not reach server")
		}))
		defer server.Close()

		client := NewHubClient(&types.FacilitatorConfig{
			URL: server.URL,
			CreateAuthHeaders: func() (map[string]map[string]string, error) {
				return nil, assert.AnError
			},
		})

		resp, err := client.Verify(&types.PaymentPayload{}, &types.PaymentRequirements{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create auth headers")
		assert.Nil(t, resp)
	})

	t.Run("settle returns error when CreateAuthHeaders fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("should not reach server")
		}))
		defer server.Close()

		client := NewHubClient(&types.FacilitatorConfig{
			URL: server.URL,
			CreateAuthHeaders: func() (map[string]map[string]string, error) {
				return nil, assert.AnError
			},
		})

		resp, err := client.SettleWithOptions(&types.PaymentPayload{}, &types.PaymentRequirements{}, true, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create auth headers")
		assert.Nil(t, resp)
	})
}

func TestHubClient_Supported(t *testing.T) {
	tests := []struct {
		name             string
		serverResponse   *x402paytypes.SupportedResponse
		serverStatusCode int
		expectedError    bool
		errorContains    string
		validateRequest  func(*testing.T, *http.Request)
	}{
		{
			name: "successful response with multiple networks",
			serverResponse: &x402paytypes.SupportedResponse{
				Kinds: []x402paytypes.NetworkKind{
					{
						Scheme:  "exact",
						Network: "base",
					},
					{
						Scheme:  "exact",
						Network: "base-sepolia",
					},
					{
						Scheme:  "exact",
						Network: "ethereum",
					},
				},
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
			validateRequest: func(t *testing.T, req *http.Request) {
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "/supported", req.URL.Path)
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			},
		},
		{
			name: "successful response with empty list",
			serverResponse: &x402paytypes.SupportedResponse{
				Kinds: []x402paytypes.NetworkKind{},
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:             "server returns 500 error",
			serverResponse:   nil,
			serverStatusCode: http.StatusInternalServerError,
			expectedError:    true,
			errorContains:    "failed to get supported networks",
		},
		{
			name:             "server returns 404 error",
			serverResponse:   nil,
			serverStatusCode: http.StatusNotFound,
			expectedError:    true,
			errorContains:    "failed to get supported networks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.validateRequest != nil {
					tt.validateRequest(t, r)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := NewHubClient(&types.FacilitatorConfig{
				URL: server.URL,
			})

			resp, err := client.Supported()

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, len(tt.serverResponse.Kinds), len(resp.Kinds))
				for i, kind := range tt.serverResponse.Kinds {
					assert.Equal(t, kind.Scheme, resp.Kinds[i].Scheme)
					assert.Equal(t, kind.Network, resp.Kinds[i].Network)
				}
			}
		})
	}

	t.Run("invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		client := NewHubClient(&types.FacilitatorConfig{
			URL: server.URL,
		})

		resp, err := client.Supported()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode supported response")
		assert.Nil(t, resp)
	})

	t.Run("auth headers are added when configured", func(t *testing.T) {
		authHeaderCalled := false
		expectedAuthHeader := "test-auth-token"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, expectedAuthHeader, r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(&x402paytypes.SupportedResponse{
				Kinds: []x402paytypes.NetworkKind{},
			})
		}))
		defer server.Close()

		client := NewHubClient(&types.FacilitatorConfig{
			URL: server.URL,
			CreateAuthHeaders: func() (map[string]map[string]string, error) {
				authHeaderCalled = true
				return map[string]map[string]string{
					"supported": {
						"Authorization": expectedAuthHeader,
					},
				}, nil
			},
		})

		resp, err := client.Supported()
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, authHeaderCalled)
	})

	t.Run("auth header creation fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := NewHubClient(&types.FacilitatorConfig{
			URL: server.URL,
			CreateAuthHeaders: func() (map[string]map[string]string, error) {
				return nil, assert.AnError
			},
		})

		resp, err := client.Supported()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create auth headers")
		assert.Nil(t, resp)
	})
}
