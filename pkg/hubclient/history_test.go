package hubclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	x402paytypes "github.com/sigweihq/x402pay/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryClient_GetHistory(t *testing.T) {
	txHash := "0xabc123"
	tests := []struct {
		name             string
		accessToken      string
		params           *x402paytypes.HistoryParams
		serverResponse   *x402paytypes.HistoryResponse
		serverStatusCode int
		expectedError    bool
		errorContains    string
	}{
		{
			name:        "successful history retrieval with all params",
			accessToken: "valid-token",
			params: &x402paytypes.HistoryParams{
				Network: "base",
				Limit:   10,
				Offset:  5,
			},
			serverResponse: &x402paytypes.HistoryResponse{
				Transactions: []*x402paytypes.TransactionHistoryItem{
					{
						ID:              1,
						CreatedAt:       time.Now(),
						UpdatedAt:       time.Now(),
						SignerAddress:   "0x1234567890123456789012345678901234567890",
						Amount:          "1000000",
						Network:         "base",
						TransactionHash: &txHash,
						Status:          "success",
					},
				},
				Total:  100,
				Limit:  10,
				Offset: 5,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:        "successful history retrieval with defaults",
			accessToken: "valid-token",
			params:      nil, // Will use defaults
			serverResponse: &x402paytypes.HistoryResponse{
				Transactions: []*x402paytypes.TransactionHistoryItem{},
				Total:        0,
				Limit:        50,
				Offset:       0,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:             "not authenticated",
			accessToken:      "",
			params:           &x402paytypes.HistoryParams{Limit: 50, Offset: 0},
			serverResponse:   nil,
			serverStatusCode: http.StatusOK,
			expectedError:    true,
			errorContains:    "not authenticated",
		},
		{
			name:        "successful with limit 0 (defaults to 50)",
			accessToken: "valid-token",
			params: &x402paytypes.HistoryParams{
				Limit:  0,
				Offset: 0,
			},
			serverResponse: &x402paytypes.HistoryResponse{
				Transactions: []*x402paytypes.TransactionHistoryItem{},
				Total:        0,
				Limit:        50,
				Offset:       0,
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:        "invalid limit - too large",
			accessToken: "valid-token",
			params: &x402paytypes.HistoryParams{
				Limit:  101,
				Offset: 0,
			},
			serverResponse:   nil,
			serverStatusCode: http.StatusOK,
			expectedError:    true,
			errorContains:    "limit must be between 1 and 100",
		},
		{
			name:        "invalid offset - negative",
			accessToken: "valid-token",
			params: &x402paytypes.HistoryParams{
				Limit:  50,
				Offset: -1,
			},
			serverResponse:   nil,
			serverStatusCode: http.StatusOK,
			expectedError:    true,
			errorContains:    "offset must be non-negative",
		},
		{
			name:        "unauthorized - expired token",
			accessToken: "expired-token",
			params: &x402paytypes.HistoryParams{
				Limit:  50,
				Offset: 0,
			},
			serverResponse:   nil,
			serverStatusCode: http.StatusUnauthorized,
			expectedError:    true,
			errorContains:    "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v1/history", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)

				if tt.accessToken != "" {
					assert.Equal(t, "Bearer "+tt.accessToken, r.Header.Get("Authorization"))
				}

				// Verify query parameters
				if tt.params != nil && tt.params.Network != "" {
					assert.Equal(t, tt.params.Network, r.URL.Query().Get("network"))
				}

				w.WriteHeader(tt.serverStatusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			authClient := newAuthClient(server.URL, http.DefaultClient)
			authClient.SetTokens(tt.accessToken, "refresh-token")

			client := newHistoryClient(server.URL, http.DefaultClient, authClient)
			result, err := client.GetHistory(tt.params)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.serverResponse.Total, result.Total)
				assert.Equal(t, tt.serverResponse.Limit, result.Limit)
				assert.Equal(t, tt.serverResponse.Offset, result.Offset)
				assert.Equal(t, len(tt.serverResponse.Transactions), len(result.Transactions))
			}
		})
	}
}

func TestHistoryClient_GetHistoryWithAutoRefresh(t *testing.T) {
	t.Run("successful with valid token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/history" {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(&x402paytypes.HistoryResponse{
					Transactions: []*x402paytypes.TransactionHistoryItem{},
					Total:        0,
					Limit:        50,
					Offset:       0,
				})
			}
		}))
		defer server.Close()

		authClient := newAuthClient(server.URL, http.DefaultClient)
		authClient.SetTokens("valid-token", "refresh-token")

		client := newHistoryClient(server.URL, http.DefaultClient, authClient)
		result, err := client.GetHistoryWithAutoRefresh(&x402paytypes.HistoryParams{
			Limit:  50,
			Offset: 0,
		})

		assert.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("auto refresh on 401", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/history" {
				requestCount++
				if requestCount == 1 {
					// First request fails with 401
					w.WriteHeader(http.StatusUnauthorized)
				} else {
					// Second request succeeds
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(&x402paytypes.HistoryResponse{
						Transactions: []*x402paytypes.TransactionHistoryItem{},
						Total:        0,
						Limit:        50,
						Offset:       0,
					})
				}
			} else if r.URL.Path == "/api/v1/auth/refresh" {
				// Refresh endpoint
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(&x402paytypes.TokenPair{
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
				})
			}
		}))
		defer server.Close()

		authClient := newAuthClient(server.URL, http.DefaultClient)
		authClient.SetTokens("expired-token", "valid-refresh-token")

		client := newHistoryClient(server.URL, http.DefaultClient, authClient)
		result, err := client.GetHistoryWithAutoRefresh(&x402paytypes.HistoryParams{
			Limit:  50,
			Offset: 0,
		})

		assert.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, 2, requestCount, "Should make 2 requests (one fail, one success after refresh)")
		assert.Equal(t, "new-access-token", authClient.GetAccessToken())
	})

	t.Run("refresh fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/history" {
				w.WriteHeader(http.StatusUnauthorized)
			} else if r.URL.Path == "/api/v1/auth/refresh" {
				// Refresh also fails
				w.WriteHeader(http.StatusUnauthorized)
			}
		}))
		defer server.Close()

		authClient := newAuthClient(server.URL, http.DefaultClient)
		authClient.SetTokens("expired-token", "invalid-refresh-token")

		client := newHistoryClient(server.URL, http.DefaultClient, authClient)
		result, err := client.GetHistoryWithAutoRefresh(&x402paytypes.HistoryParams{
			Limit:  50,
			Offset: 0,
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to refresh token")
		assert.Nil(t, result)
	})
}

func TestHistoryClient_Integration(t *testing.T) {
	t.Run("full auth and history flow", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/auth/message":
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(&x402paytypes.MessageResponse{
					Message: "Sign this message",
				})
			case "/api/v1/auth/login":
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(&x402paytypes.AuthResponse{
					User: &x402paytypes.User{
						ID:            1,
						WalletAddress: "0x1234567890123456789012345678901234567890",
					},
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
				})
			case "/api/v1/history":
				// Check authorization
				assert.Equal(t, "Bearer access-token", r.Header.Get("Authorization"))
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(&x402paytypes.HistoryResponse{
					Transactions: []*x402paytypes.TransactionHistoryItem{},
					Total:        0,
					Limit:        50,
					Offset:       0,
				})
			}
		}))
		defer server.Close()

		authClient := newAuthClient(server.URL, http.DefaultClient)
		historyClient := newHistoryClient(server.URL, http.DefaultClient, authClient)

		// 1. Get auth message
		msg, err := authClient.GetAuthMessage("0x1234567890123456789012345678901234567890")
		require.NoError(t, err)
		assert.NotEmpty(t, msg.Message)

		// 2. Login
		authResp, err := authClient.Login(msg.Message, "0xsignature")
		require.NoError(t, err)
		assert.NotEmpty(t, authResp.AccessToken)

		// 3. Get history (should work now that we're authenticated)
		history, err := historyClient.GetHistory(&x402paytypes.HistoryParams{
			Limit:  50,
			Offset: 0,
		})
		require.NoError(t, err)
		assert.NotNil(t, history)
	})
}
