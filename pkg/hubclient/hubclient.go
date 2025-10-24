package hubclient

// Based on facilitatorclient.FacilitatorClient
// https://github.com/coinbase/x402/blob/main/go/pkg/facilitatorclient/facilitatorclient.go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/coinbase/x402/go/pkg/types"
)

// DefaultFacilitatorURL is the default URL for the x402 facilitator service
const DefaultHubURL = "https://hub.sigwei.com"

type HubClient struct {
	URL               string
	HTTPClient        *http.Client
	CreateAuthHeaders func() (map[string]map[string]string, error)
}

func NewHubClient(config *types.FacilitatorConfig) *HubClient {
	if config == nil {
		config = &types.FacilitatorConfig{
			URL: DefaultHubURL,
		}
	}

	httpCli := &http.Client{}
	if config.Timeout != nil {
		httpCli.Timeout = config.Timeout()
	}

	return &HubClient{
		URL:               config.URL,
		HTTPClient:        httpCli,
		CreateAuthHeaders: config.CreateAuthHeaders,
	}
}

// Verify sends a payment verification request to the facilitator
func (c *HubClient) Verify(payload *types.PaymentPayload, requirements *types.PaymentRequirements) (*types.VerifyResponse, error) {

	reqBody := map[string]any{
		"x402Version":         1,
		"paymentPayload":      payload,
		"paymentRequirements": requirements,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/verify", c.URL), bytes.NewBuffer(jsonBody))
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
		if verifyHeaders, ok := headers["verify"]; ok {
			for key, value := range verifyHeaders {
				req.Header.Set(key, value)
			}
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send verify request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to verify payment: %s", resp.Status)
	}

	var verifyResp types.VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		return nil, fmt.Errorf("failed to decode verify response: %w", err)
	}

	return &verifyResp, nil
}

// Settle sends a payment settlement request to the facilitator
func (c *HubClient) Settle(payload *types.PaymentPayload, requirements *types.PaymentRequirements, confirm bool, useDbId bool) (*types.SettleResponse, error) {
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

func (c *HubClient) Transfer(payload *types.PaymentPayload, requirements *types.PaymentRequirements, confirm bool) (*types.SettleResponse, error) {
	return c.Settle(payload, requirements, confirm, false)
}
