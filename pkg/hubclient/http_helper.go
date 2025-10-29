package hubclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sigweihq/x402pay/pkg/constants"
)

// httpRequest is a shared helper for making HTTP requests with consistent error handling
// This implements DRY by consolidating common HTTP request logic used by all clients
func httpRequest(client *http.Client, method, url string, body interface{}, headers map[string]string, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set default Content-Type
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	limitedReader := io.LimitReader(resp.Body, int64(constants.MaxResponseBodySize))

	// Handle non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to read error response body
		bodyBytes, _ := io.ReadAll(limitedReader)
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       bodyBytes,
		}
	}

	// Decode response if result is provided
	if result != nil {
		if err := json.NewDecoder(limitedReader).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// HTTPError represents an HTTP error with status code and response body
type HTTPError struct {
	StatusCode int
	Status     string
	Body       []byte
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	if len(e.Body) > 0 {
		// Try to parse as JSON error
		var errResp struct {
			Error   string `json:"error"`
			Details string `json:"details"`
		}
		if err := json.Unmarshal(e.Body, &errResp); err == nil {
			if errResp.Details != "" {
				return fmt.Sprintf("HTTP %d: %s - %s", e.StatusCode, errResp.Error, errResp.Details)
			}
			if errResp.Error != "" {
				return fmt.Sprintf("HTTP %d: %s", e.StatusCode, errResp.Error)
			}
		}
		return fmt.Sprintf("HTTP %d: %s - %s", e.StatusCode, e.Status, string(e.Body))
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Status)
}

// IsUnauthorized returns true if the error is a 401 Unauthorized error
func (e *HTTPError) IsUnauthorized() bool {
	return e.StatusCode == http.StatusUnauthorized
}

// IsForbidden returns true if the error is a 403 Forbidden error
func (e *HTTPError) IsForbidden() bool {
	return e.StatusCode == http.StatusForbidden
}
