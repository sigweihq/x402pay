package hubclient

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"

	x402paytypes "github.com/sigweihq/x402pay/pkg/types"
)

// AuthClient handles wallet-based authentication with the x402-hub
type AuthClient struct {
	baseURL      string
	httpClient   *http.Client
	accessToken  string
	refreshToken string
	tokenMutex   sync.RWMutex
}

// newAuthClient creates a new auth client (internal constructor)
func newAuthClient(baseURL string, httpClient *http.Client) *AuthClient {
	return &AuthClient{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

// GetAuthMessage retrieves an authentication message with nonce for the given wallet address
// GET /api/v1/auth/message?walletAddress=0x...
func (c *AuthClient) GetAuthMessage(walletAddress string) (*x402paytypes.MessageResponse, error) {
	// Build URL with query parameter
	u, err := url.Parse(fmt.Sprintf("%s/api/v1/auth/message", c.baseURL))
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	q := u.Query()
	q.Set("walletAddress", walletAddress)
	u.RawQuery = q.Encode()

	var result x402paytypes.MessageResponse
	if err := httpRequest(c.httpClient, http.MethodGet, u.String(), nil, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to get auth message: %w", err)
	}

	return &result, nil
}

// Login authenticates a user with wallet signature
// POST /api/v1/auth/login
// Body: {"message": "...", "signature": "0x..."}
func (c *AuthClient) Login(message, signature string) (*x402paytypes.AuthResponse, error) {
	reqBody := x402paytypes.AuthRequest{
		Message:   message,
		Signature: signature,
	}

	url := fmt.Sprintf("%s/api/v1/auth/login", c.baseURL)
	var result x402paytypes.AuthResponse

	if err := httpRequest(c.httpClient, http.MethodPost, url, reqBody, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to login: %w", err)
	}

	// Store tokens
	c.SetTokens(result.AccessToken, result.RefreshToken)

	return &result, nil
}

// RefreshToken refreshes the access token using the refresh token
// POST /api/v1/auth/refresh
// Body: {"refreshToken": "..."}
func (c *AuthClient) RefreshToken() (*x402paytypes.TokenPair, error) {
	c.tokenMutex.RLock()
	currentRefreshToken := c.refreshToken
	c.tokenMutex.RUnlock()

	if currentRefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	reqBody := x402paytypes.RefreshRequest{
		RefreshToken: currentRefreshToken,
	}

	url := fmt.Sprintf("%s/api/v1/auth/refresh", c.baseURL)
	var result x402paytypes.TokenPair

	if err := httpRequest(c.httpClient, http.MethodPost, url, reqBody, nil, &result); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// Update stored tokens atomically to prevent race conditions
	c.tokenMutex.Lock()
	c.accessToken = result.AccessToken
	c.refreshToken = result.RefreshToken
	c.tokenMutex.Unlock()

	return &result, nil
}

// GetMe retrieves the current authenticated user information
// GET /api/v1/auth/me
// Requires: Authorization header with access token
func (c *AuthClient) GetMe() (*x402paytypes.User, error) {
	token := c.GetAccessToken()
	if token == "" {
		return nil, fmt.Errorf("not authenticated: no access token")
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}

	url := fmt.Sprintf("%s/api/v1/auth/me", c.baseURL)
	var result x402paytypes.User

	if err := httpRequest(c.httpClient, http.MethodGet, url, nil, headers, &result); err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return &result, nil
}

// Logout logs out the current user
// POST /api/v1/auth/logout
// Requires: Authorization header with access token
func (c *AuthClient) Logout() error {
	token := c.GetAccessToken()
	if token == "" {
		return fmt.Errorf("not authenticated: no access token")
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}

	url := fmt.Sprintf("%s/api/v1/auth/logout", c.baseURL)

	if err := httpRequest(c.httpClient, http.MethodPost, url, nil, headers, nil); err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	// Clear stored tokens
	c.ClearTokens()

	return nil
}

// SetTokens stores the access and refresh tokens (thread-safe)
func (c *AuthClient) SetTokens(accessToken, refreshToken string) {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()
	c.accessToken = accessToken
	c.refreshToken = refreshToken
}

// GetAccessToken retrieves the current access token (thread-safe)
func (c *AuthClient) GetAccessToken() string {
	c.tokenMutex.RLock()
	defer c.tokenMutex.RUnlock()
	return c.accessToken
}

// GetRefreshToken retrieves the current refresh token (thread-safe)
func (c *AuthClient) GetRefreshToken() string {
	c.tokenMutex.RLock()
	defer c.tokenMutex.RUnlock()
	return c.refreshToken
}

// ClearTokens clears all stored tokens (thread-safe)
func (c *AuthClient) ClearTokens() {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()
	c.accessToken = ""
	c.refreshToken = ""
}

// IsAuthenticated returns true if an access token is available
func (c *AuthClient) IsAuthenticated() bool {
	c.tokenMutex.RLock()
	defer c.tokenMutex.RUnlock()
	return c.accessToken != ""
}
