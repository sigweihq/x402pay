package hubclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	x402paytypes "github.com/sigweihq/x402pay/pkg/types"
)

// HistoryClient handles transaction history queries with the x402-hub
type HistoryClient struct {
	baseURL    string
	httpClient *http.Client
	authClient *AuthClient // Reference to auth client for token management
}

// newHistoryClient creates a new history client (internal constructor)
func newHistoryClient(baseURL string, httpClient *http.Client, authClient *AuthClient) *HistoryClient {
	return &HistoryClient{
		baseURL:    baseURL,
		httpClient: httpClient,
		authClient: authClient,
	}
}

// GetHistory retrieves transaction history for the authenticated user
// GET /api/v1/history?network=base&limit=50&offset=0
// Requires: Authorization header with access token
func (c *HistoryClient) GetHistory(params *x402paytypes.HistoryParams) (*x402paytypes.HistoryResponse, error) {
	// Check authentication
	token := c.authClient.GetAccessToken()
	if token == "" {
		return nil, fmt.Errorf("not authenticated: please login first")
	}

	// Set defaults
	if params == nil {
		params = &x402paytypes.HistoryParams{
			Limit:  50,
			Offset: 0,
		}
	}
	if params.Limit == 0 {
		params.Limit = 50
	}

	// Validate params
	if params.Limit < 1 || params.Limit > 100 {
		return nil, fmt.Errorf("limit must be between 1 and 100, got %d", params.Limit)
	}
	if params.Offset < 0 {
		return nil, fmt.Errorf("offset must be non-negative, got %d", params.Offset)
	}

	// Build URL with query parameters
	u, err := url.Parse(fmt.Sprintf("%s/api/v1/history", c.baseURL))
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	q := u.Query()
	if params.Network != "" {
		q.Set("network", params.Network)
	}
	q.Set("limit", strconv.Itoa(params.Limit))
	q.Set("offset", strconv.Itoa(params.Offset))
	u.RawQuery = q.Encode()

	// Add authorization header
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}

	var result x402paytypes.HistoryResponse
	if err := httpRequest(c.httpClient, http.MethodGet, u.String(), nil, headers, &result); err != nil {
		// Don't wrap HTTPError so errors.As works in GetHistoryWithAutoRefresh
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			if httpErr.IsUnauthorized() {
				return nil, fmt.Errorf("authentication failed: %w (hint: token may be expired, try refreshing)", err)
			}
			return nil, fmt.Errorf("failed to get transaction history: %w", err)
		}
		return nil, fmt.Errorf("failed to get transaction history: %w", err)
	}

	return &result, nil
}

// GetHistoryWithAutoRefresh attempts to get history and automatically refreshes token if needed
// This is a convenience method that handles token refresh automatically
func (c *HistoryClient) GetHistoryWithAutoRefresh(params *x402paytypes.HistoryParams) (*x402paytypes.HistoryResponse, error) {
	// Try the request first
	result, err := c.GetHistory(params)
	if err != nil {
		// Check if it's an unauthorized error (unwrap the error to find HTTPError)
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.IsUnauthorized() {
			// Try to refresh the token
			if _, refreshErr := c.authClient.RefreshToken(); refreshErr != nil {
				return nil, fmt.Errorf("failed to refresh token: %w", refreshErr)
			}

			// Retry the request with new token
			result, err = c.GetHistory(params)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return result, nil
}
