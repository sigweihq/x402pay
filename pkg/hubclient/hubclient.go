package hubclient

// Based on facilitatorclient.FacilitatorClient
// https://github.com/coinbase/x402/blob/main/go/pkg/facilitatorclient/facilitatorclient.go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	"github.com/coinbase/x402/go/pkg/types"
	x402paytypes "github.com/sigweihq/x402pay/pkg/types"
)

// DefaultHubURL is the default URL for the x402 hub service
const DefaultHubURL = "https://hub.sigwei.com"

// HubClient provides access to x402-hub services
// It embeds FacilitatorClient for standard x402 protocol endpoints (verify, settle)
// and adds Auth and History clients for hub-specific features
type HubClient struct {
	*facilitatorclient.FacilitatorClient

	// Auth provides wallet-based authentication functionality
	// Endpoints: /api/v1/auth/message, /api/v1/auth/login, /api/v1/auth/refresh, etc.
	Auth *AuthClient

	// History provides transaction history queries for authenticated users
	// Endpoints: /api/v1/history
	History *HistoryClient
}

// NewHubClient creates a new hub client with all sub-clients initialized
// The Auth and History clients share the same HTTP client and base URL
func NewHubClient(config *types.FacilitatorConfig) *HubClient {
	if config == nil {
		config = &types.FacilitatorConfig{
			URL: DefaultHubURL,
		}
	}

	facilitatorClient := facilitatorclient.NewFacilitatorClient(config)

	// Create sub-clients using the same HTTP client and URL
	authClient := newAuthClient(config.URL, facilitatorClient.HTTPClient)
	historyClient := newHistoryClient(config.URL, facilitatorClient.HTTPClient, authClient)

	return &HubClient{
		FacilitatorClient: facilitatorClient,
		Auth:              authClient,
		History:           historyClient,
	}
}

// SettleWithOptions sends a payment settlement request to the hub with additional options
func (c *HubClient) SettleWithOptions(payload *types.PaymentPayload, requirements *types.PaymentRequirements, confirm bool, useDbId bool) (*types.SettleResponse, error) {
	reqBody := map[string]any{
		"x402Version":         1,
		"paymentPayload":      payload,
		"paymentRequirements": requirements,
		"confirm":             confirm,
		"useDbId":             useDbId,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/settle", c.URL), bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add auth headers if available
	if c.CreateAuthHeaders != nil {
		headers, err := c.CreateAuthHeaders()
		if err != nil {
			return nil, fmt.Errorf("failed to create auth headers: %w", err)
		}
		if settleHeaders, ok := headers["settle"]; ok {
			for key, value := range settleHeaders {
				req.Header.Set(key, value)
			}
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send settle request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to settle payment: %s", resp.Status)
	}

	var settleResp types.SettleResponse
	if err := json.NewDecoder(resp.Body).Decode(&settleResp); err != nil {
		return nil, fmt.Errorf("failed to decode settle response: %w", err)
	}

	return &settleResp, nil
}

// Transfer is an enpoint for convenient transfers
func (c *HubClient) Transfer(payload *types.ExactEvmPayload, network string, asset string, confirm bool) (*types.SettleResponse, error) {
	reqBody := map[string]any{
		"payload": payload,
		"network": network,
		"asset":   asset,
		"confirm": confirm,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/transfer", c.URL), bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add auth headers if available
	if c.CreateAuthHeaders != nil {
		headers, err := c.CreateAuthHeaders()
		if err != nil {
			return nil, fmt.Errorf("failed to create auth headers: %w", err)
		}
		if settleHeaders, ok := headers["transfer"]; ok {
			for key, value := range settleHeaders {
				req.Header.Set(key, value)
			}
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send transfer request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to transfer payment: %s", resp.Status)
	}

	var settleResp types.SettleResponse
	if err := json.NewDecoder(resp.Body).Decode(&settleResp); err != nil {
		return nil, fmt.Errorf("failed to decode transfer response: %w", err)
	}

	return &settleResp, nil
}

func (c *HubClient) Supported() (*x402paytypes.SupportedResponse, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/supported", c.URL), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add supported headers if available
	if c.CreateAuthHeaders != nil {
		headers, err := c.CreateAuthHeaders()
		if err != nil {
			return nil, fmt.Errorf("failed to create auth headers: %w", err)
		}
		if supportedHeaders, ok := headers["supported"]; ok {
			for key, value := range supportedHeaders {
				req.Header.Set(key, value)
			}
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send supported request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get supported networks: %s", resp.Status)
	}

	var supportedResp x402paytypes.SupportedResponse
	if err := json.NewDecoder(resp.Body).Decode(&supportedResp); err != nil {
		return nil, fmt.Errorf("failed to decode supported response: %w", err)
	}
	return &supportedResp, nil
}
