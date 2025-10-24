package hubclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	x402paytypes "github.com/sigweihq/x402pay/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthClient_GetAuthMessage(t *testing.T) {
	tests := []struct {
		name             string
		walletAddress    string
		serverResponse   *x402paytypes.MessageResponse
		serverStatusCode int
		expectedError    bool
		errorContains    string
	}{
		{
			name:          "successful message retrieval",
			walletAddress: "0x1234567890123456789012345678901234567890",
			serverResponse: &x402paytypes.MessageResponse{
				Message: "Sign this message to authenticate with x402-hub.\n\nNonce: abc123\nTimestamp: 1234567890",
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:             "server error",
			walletAddress:    "0x1234567890123456789012345678901234567890",
			serverResponse:   nil,
			serverStatusCode: http.StatusInternalServerError,
			expectedError:    true,
			errorContains:    "failed to get auth message",
		},
		{
			name:             "invalid wallet address",
			walletAddress:    "invalid",
			serverResponse:   nil,
			serverStatusCode: http.StatusBadRequest,
			expectedError:    true,
			errorContains:    "failed to get auth message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v1/auth/message", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, tt.walletAddress, r.URL.Query().Get("walletAddress"))

				w.WriteHeader(tt.serverStatusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := newAuthClient(server.URL, http.DefaultClient)
			result, err := client.GetAuthMessage(tt.walletAddress)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.serverResponse.Message, result.Message)
			}
		})
	}
}

func TestAuthClient_Login(t *testing.T) {
	tests := []struct {
		name             string
		message          string
		signature        string
		serverResponse   *x402paytypes.AuthResponse
		serverStatusCode int
		expectedError    bool
		errorContains    string
	}{
		{
			name:      "successful login",
			message:   "Sign this message...",
			signature: "0xabc123",
			serverResponse: &x402paytypes.AuthResponse{
				User: &x402paytypes.User{
					ID:            1,
					WalletAddress: "0x1234567890123456789012345678901234567890",
				},
				AccessToken:  "access-token-123",
				RefreshToken: "refresh-token-456",
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:             "invalid signature",
			message:          "Sign this message...",
			signature:        "0xinvalid",
			serverResponse:   nil,
			serverStatusCode: http.StatusUnauthorized,
			expectedError:    true,
			errorContains:    "failed to login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v1/auth/login", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)

				// Verify request body
				var req x402paytypes.AuthRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				assert.NoError(t, err)
				assert.Equal(t, tt.message, req.Message)
				assert.Equal(t, tt.signature, req.Signature)

				w.WriteHeader(tt.serverStatusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := newAuthClient(server.URL, http.DefaultClient)
			result, err := client.Login(tt.message, tt.signature)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.serverResponse.User.ID, result.User.ID)
				assert.Equal(t, tt.serverResponse.AccessToken, result.AccessToken)
				assert.Equal(t, tt.serverResponse.RefreshToken, result.RefreshToken)

				// Verify tokens are stored
				assert.Equal(t, tt.serverResponse.AccessToken, client.GetAccessToken())
				assert.Equal(t, tt.serverResponse.RefreshToken, client.GetRefreshToken())
				assert.True(t, client.IsAuthenticated())
			}
		})
	}
}

func TestAuthClient_RefreshToken(t *testing.T) {
	tests := []struct {
		name              string
		initialRefreshTok string
		serverResponse    *x402paytypes.TokenPair
		serverStatusCode  int
		expectedError     bool
		errorContains     string
	}{
		{
			name:              "successful token refresh",
			initialRefreshTok: "refresh-token-456",
			serverResponse: &x402paytypes.TokenPair{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:              "no refresh token available",
			initialRefreshTok: "",
			serverResponse:    nil,
			serverStatusCode:  http.StatusOK,
			expectedError:     true,
			errorContains:     "no refresh token available",
		},
		{
			name:              "invalid refresh token",
			initialRefreshTok: "invalid-token",
			serverResponse:    nil,
			serverStatusCode:  http.StatusUnauthorized,
			expectedError:     true,
			errorContains:     "failed to refresh token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v1/auth/refresh", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)

				w.WriteHeader(tt.serverStatusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := newAuthClient(server.URL, http.DefaultClient)
			client.SetTokens("old-access-token", tt.initialRefreshTok)

			result, err := client.RefreshToken()

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.serverResponse.AccessToken, result.AccessToken)
				assert.Equal(t, tt.serverResponse.RefreshToken, result.RefreshToken)

				// Verify tokens are updated
				assert.Equal(t, tt.serverResponse.AccessToken, client.GetAccessToken())
				assert.Equal(t, tt.serverResponse.RefreshToken, client.GetRefreshToken())
			}
		})
	}
}

func TestAuthClient_GetMe(t *testing.T) {
	tests := []struct {
		name             string
		accessToken      string
		serverResponse   *x402paytypes.User
		serverStatusCode int
		expectedError    bool
		errorContains    string
	}{
		{
			name:        "successful user info retrieval",
			accessToken: "valid-token",
			serverResponse: &x402paytypes.User{
				ID:            1,
				WalletAddress: "0x1234567890123456789012345678901234567890",
				CreatedAt:     "2024-01-01T00:00:00Z",
				UpdatedAt:     "2024-01-02T00:00:00Z",
			},
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:             "not authenticated",
			accessToken:      "",
			serverResponse:   nil,
			serverStatusCode: http.StatusOK,
			expectedError:    true,
			errorContains:    "not authenticated",
		},
		{
			name:             "invalid token",
			accessToken:      "invalid-token",
			serverResponse:   nil,
			serverStatusCode: http.StatusUnauthorized,
			expectedError:    true,
			errorContains:    "failed to get user info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v1/auth/me", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)

				if tt.accessToken != "" {
					assert.Equal(t, "Bearer "+tt.accessToken, r.Header.Get("Authorization"))
				}

				w.WriteHeader(tt.serverStatusCode)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := newAuthClient(server.URL, http.DefaultClient)
			client.SetTokens(tt.accessToken, "refresh-token")

			result, err := client.GetMe()

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.serverResponse.ID, result.ID)
				assert.Equal(t, tt.serverResponse.WalletAddress, result.WalletAddress)
			}
		})
	}
}

func TestAuthClient_Logout(t *testing.T) {
	tests := []struct {
		name             string
		accessToken      string
		serverStatusCode int
		expectedError    bool
		errorContains    string
	}{
		{
			name:             "successful logout",
			accessToken:      "valid-token",
			serverStatusCode: http.StatusOK,
			expectedError:    false,
		},
		{
			name:             "not authenticated",
			accessToken:      "",
			serverStatusCode: http.StatusOK,
			expectedError:    true,
			errorContains:    "not authenticated",
		},
		{
			name:             "server error",
			accessToken:      "valid-token",
			serverStatusCode: http.StatusInternalServerError,
			expectedError:    true,
			errorContains:    "failed to logout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v1/auth/logout", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)

				if tt.accessToken != "" {
					assert.Equal(t, "Bearer "+tt.accessToken, r.Header.Get("Authorization"))
				}

				w.WriteHeader(tt.serverStatusCode)
			}))
			defer server.Close()

			client := newAuthClient(server.URL, http.DefaultClient)
			client.SetTokens(tt.accessToken, "refresh-token")

			err := client.Logout()

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				// Verify tokens are cleared
				assert.Equal(t, "", client.GetAccessToken())
				assert.Equal(t, "", client.GetRefreshToken())
				assert.False(t, client.IsAuthenticated())
			}
		})
	}
}

func TestAuthClient_TokenManagement(t *testing.T) {
	client := newAuthClient("http://example.com", http.DefaultClient)

	// Initially not authenticated
	assert.False(t, client.IsAuthenticated())
	assert.Equal(t, "", client.GetAccessToken())
	assert.Equal(t, "", client.GetRefreshToken())

	// Set tokens
	client.SetTokens("access-123", "refresh-456")
	assert.True(t, client.IsAuthenticated())
	assert.Equal(t, "access-123", client.GetAccessToken())
	assert.Equal(t, "refresh-456", client.GetRefreshToken())

	// Clear tokens
	client.ClearTokens()
	assert.False(t, client.IsAuthenticated())
	assert.Equal(t, "", client.GetAccessToken())
	assert.Equal(t, "", client.GetRefreshToken())
}
