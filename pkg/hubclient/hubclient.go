package hubclient

// Based on facilitatorclient.FacilitatorClient
// https://github.com/coinbase/x402/blob/main/go/pkg/facilitatorclient/facilitatorclient.go

import (
	"fmt"
	"net/http"

	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	"github.com/coinbase/x402/go/pkg/types"
	x402paytypes "github.com/sigweihq/x402pay/pkg/types"
	"github.com/sigweihq/x402pay/pkg/utils"
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

	// Validate URL security - fall back to default if invalid
	if err := utils.ValidateFacilitatorURL(config.URL); err != nil {
		config.URL = DefaultHubURL
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

	return utils.MakeJSONRequest[types.SettleResponse](
		c.HTTPClient,
		http.MethodPost,
		fmt.Sprintf("%s/settle", c.URL),
		reqBody,
		c.CreateAuthHeaders,
		"settle",
	)
}

// Transfer is an enpoint for convenient transfers
func (c *HubClient) Transfer(payload *types.ExactEvmPayload, network string, asset string, confirm bool) (*types.SettleResponse, error) {
	reqBody := map[string]any{
		"payload": payload,
		"network": network,
		"asset":   asset,
		"confirm": confirm,
	}

	return utils.MakeJSONRequest[types.SettleResponse](
		c.HTTPClient,
		http.MethodPost,
		fmt.Sprintf("%s/transfer", c.URL),
		reqBody,
		c.CreateAuthHeaders,
		"transfer",
	)
}

func (c *HubClient) Supported() (*x402paytypes.SupportedResponse, error) {
	return utils.MakeJSONRequest[x402paytypes.SupportedResponse](
		c.HTTPClient,
		http.MethodGet,
		fmt.Sprintf("%s/supported", c.URL),
		nil, // No request body for GET request
		c.CreateAuthHeaders,
		"supported",
	)
}

// VerifySolana verifies a Solana payment with the hub
func (c *HubClient) VerifySolana(payload *x402paytypes.SolanaPaymentPayload, requirements *types.PaymentRequirements) (*types.VerifyResponse, error) {
	reqBody := map[string]any{
		"x402Version":         1,
		"paymentPayload":      payload,
		"paymentRequirements": requirements,
	}

	return utils.MakeJSONRequest[types.VerifyResponse](
		c.HTTPClient,
		http.MethodPost,
		fmt.Sprintf("%s/verify", c.URL),
		reqBody,
		c.CreateAuthHeaders,
		"verify",
	)
}

// SettleSolana settles a Solana payment with the hub
func (c *HubClient) SettleSolana(payload *x402paytypes.SolanaPaymentPayload, requirements *types.PaymentRequirements) (*types.SettleResponse, error) {
	reqBody := map[string]any{
		"x402Version":         1,
		"paymentPayload":      payload,
		"paymentRequirements": requirements,
	}

	return utils.MakeJSONRequest[types.SettleResponse](
		c.HTTPClient,
		http.MethodPost,
		fmt.Sprintf("%s/settle", c.URL),
		reqBody,
		c.CreateAuthHeaders,
		"settle",
	)
}

// SettleWithOptionsSolana settles a Solana payment with additional options
func (c *HubClient) SettleWithOptionsSolana(payload *x402paytypes.SolanaPaymentPayload, requirements *types.PaymentRequirements, confirm bool, useDbId bool) (*types.SettleResponse, error) {
	reqBody := map[string]any{
		"x402Version":         1,
		"paymentPayload":      payload,
		"paymentRequirements": requirements,
		"confirm":             confirm,
		"useDbId":             useDbId,
	}

	return utils.MakeJSONRequest[types.SettleResponse](
		c.HTTPClient,
		http.MethodPost,
		fmt.Sprintf("%s/settle", c.URL),
		reqBody,
		c.CreateAuthHeaders,
		"settle",
	)
}

// TransferSolana is an endpoint for convenient Solana transfers
func (c *HubClient) TransferSolana(payload *x402paytypes.ExactSolanaPayload, network string, asset string, confirm bool) (*types.SettleResponse, error) {
	reqBody := map[string]any{
		"payload": payload,
		"network": network,
		"asset":   asset,
		"confirm": confirm,
	}

	return utils.MakeJSONRequest[types.SettleResponse](
		c.HTTPClient,
		http.MethodPost,
		fmt.Sprintf("%s/transfer", c.URL),
		reqBody,
		c.CreateAuthHeaders,
		"transfer",
	)
}
