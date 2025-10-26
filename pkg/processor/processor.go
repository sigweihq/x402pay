package processor

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/coinbase/x402/go/pkg/coinbasefacilitator"
	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/sigweihq/x402pay/pkg/constants"
	"github.com/sigweihq/x402pay/pkg/utils"
)

var (
	processorMap     sync.Map
	processorMapOnce sync.Once
)

// ProcessorConfig holds the configuration for payment processors
type ProcessorConfig struct {
	FacilitatorURLs []string
	CDPAPIKeyID     string // Optional: Coinbase CDP API key ID
	CDPAPIKeySecret string // Optional: Coinbase CDP API secret
}

// PaymentProcessor handles x402 payment verification and settlement with failover support
type PaymentProcessor struct {
	facilitatorClients []*facilitatorclient.FacilitatorClient
	logger             *slog.Logger
}

// InitProcessorMap initializes the processor map with the given configuration
// This should be called once at application startup
func InitProcessorMap(config *ProcessorConfig, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	processorMapOnce.Do(func() {
		networkToClients := bootstrapFacilitatorClients(config.FacilitatorURLs, config.CDPAPIKeyID, config.CDPAPIKeySecret)
		for network, facilitatorClients := range networkToClients {
			processor := &PaymentProcessor{
				facilitatorClients: facilitatorClients,
				logger:             logger,
			}
			logger.Info("Payment processor initialized", "network", network, "facilitators", len(facilitatorClients))
			for i, client := range facilitatorClients {
				logger.Info("Facilitator client initialized", "index", i+1, "url", client.URL)
			}
			processorMap.Store(network, processor)
		}
	})
}

func getProcessor(network string) *PaymentProcessor {
	processor, ok := processorMap.Load(network)
	if !ok {
		return nil
	}
	return processor.(*PaymentProcessor)
}

// bootstrapFacilitatorClients creates pre-configured facilitator clients from URLs or CDP credentials
func bootstrapFacilitatorClients(urls []string, cdpAPIKeyID, cdpAPIKeySecret string) map[string][]*facilitatorclient.FacilitatorClient {
	networkToClients := make(map[string][]*facilitatorclient.FacilitatorClient)
	// Create HTTP client with timeouts once, reused for all clients
	httpClient := utils.CreateHTTPClientWithTimeouts()

	// If CDP credentials are provided, only use CDP facilitator
	if cdpAPIKeyID != "" && cdpAPIKeySecret != "" {
		config := coinbasefacilitator.CreateFacilitatorConfig(cdpAPIKeyID, cdpAPIKeySecret)
		client := utils.NewFacilitatorClient(config, httpClient)
		supportedNetworks := []string{constants.NetworkBase, constants.NetworkBaseSepolia, constants.NetworkSolana, constants.NetworkSolanaDevnet}
		for _, network := range supportedNetworks {
			networkToClients[network] = append(networkToClients[network], client)
		}
	}

	// Create clients for each provided URL
	for _, url := range urls {
		// Validate URL security - skip invalid URLs
		if err := utils.ValidateFacilitatorURL(url); err != nil {
			continue
		}
		config := &x402types.FacilitatorConfig{URL: url}
		client := utils.NewFacilitatorClient(config, httpClient)
		supportedNetworks := DiscoverSupported(client)
		for _, network := range supportedNetworks {
			networkToClients[network] = append(networkToClients[network], client)
		}
	}

	return networkToClients
}

// shouldRetryWithNextFacilitator determines if we should try the next facilitator
func shouldRetryWithNextFacilitator(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Retry on network/infrastructure errors
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "context deadline exceeded") {
		return true
	}

	// Retry on HTTP 5xx server errors
	if strings.Contains(errStr, "500") ||
		strings.Contains(errStr, "502") ||
		strings.Contains(errStr, "503") ||
		strings.Contains(errStr, "504") {
		return true
	}

	// Retry on authentication failures (bad API keys)
	if strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "401") {
		return true
	}

	// Don't retry on client errors (invalid requests, insufficient funds, etc.)
	return false
}

// tryVerifyWithFacilitator attempts payment verification with a single facilitator
func (p *PaymentProcessor) tryVerifyWithFacilitator(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	onVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error,
) (*x402types.VerifyResponse, error) {

	verifyResp, err := client.Verify(paymentPayload, paymentRequirements)
	if err != nil {
		p.logger.Error("Payment verification failed", "error", err)
		return nil, fmt.Errorf("payment verification failed: %w", err)
	}

	if !verifyResp.IsValid {
		reason := "unknown"
		if verifyResp.InvalidReason != nil {
			reason = *verifyResp.InvalidReason
		}
		return nil, fmt.Errorf("payment verification failed: %s", reason)
	}

	// Call verification callback
	if onVerified != nil {
		if err := onVerified(paymentPayload, paymentRequirements); err != nil {
			return nil, fmt.Errorf("verification callback failed: %w", err)
		}
	}

	return verifyResp, nil
}

// tryFacilitatorWithCallback attempts payment verification and settlement with a single facilitator
func (p *PaymentProcessor) tryFacilitatorWithCallback(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	onVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error,
) (*x402types.SettleResponse, error) {
	_, err := p.tryVerifyWithFacilitator(client, paymentPayload, paymentRequirements, onVerified)
	if err != nil {
		return nil, err
	}

	// Settle payment
	settleResp, err := client.Settle(paymentPayload, paymentRequirements)
	if err != nil {
		p.logger.Error("Payment settlement failed", "error", err)
		return nil, fmt.Errorf("payment settlement failed: %w", err)
	}

	if !settleResp.Success {
		reason := "unknown"
		if settleResp.ErrorReason != nil {
			reason = *settleResp.ErrorReason
		}
		return nil, fmt.Errorf("payment settlement failed: %s", reason)
	}

	return settleResp, nil
}

// ProcessPayment verifies and settles a payment with failover support across multiple facilitators
func ProcessPayment(
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	confirm bool,
) (*x402types.SettleResponse, error) {
	return ProcessPaymentWithCallback(paymentPayload, paymentRequirements, confirm, nil, nil)
}

// ProcessPaymentWithCallback verifies and settles a payment with an optional verification callback
func ProcessPaymentWithCallback(
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	confirm bool,
	onVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error,
	onSettled func(*x402types.PaymentPayload, *x402types.PaymentRequirements, *x402types.SettleResponse) error,
) (*x402types.SettleResponse, error) {
	processor := getProcessor(paymentPayload.Network)
	if processor == nil {
		return nil, fmt.Errorf("no processor configured for network: %s", paymentPayload.Network)
	}

	if len(processor.facilitatorClients) == 0 {
		return nil, fmt.Errorf("no facilitator clients available")
	}

	var lastErr error
	for i, client := range processor.facilitatorClients {
		processor.logger.Info("Trying facilitator",
			"index", i+1,
			"total", len(processor.facilitatorClients),
			"url", client.URL,
			"network", paymentPayload.Network)

		settleResp, err := processor.tryFacilitatorWithCallback(client, paymentPayload, paymentRequirements, onVerified)
		if err == nil {
			processor.logger.Info("Facilitator succeeded", "url", client.URL)
			if confirm {
				if verifyErr := VerifySettledTransaction(settleResp, paymentPayload); verifyErr != nil {
					processor.logger.Error("Transaction verification failed", "error", verifyErr)
					return nil, verifyErr
				}
			}

			if onSettled != nil {
				if err := onSettled(paymentPayload, paymentRequirements, settleResp); err != nil {
					return settleResp, fmt.Errorf("settlement callback failed: %w", err)
				}
			}

			return settleResp, nil
		}

		processor.logger.Warn("Facilitator attempt failed",
			"url", client.URL,
			"error", err,
			"willRetry", shouldRetryWithNextFacilitator(err))

		lastErr = err

		// Don't retry for validation/client errors
		if !shouldRetryWithNextFacilitator(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("all facilitators failed, last error: %w", lastErr)
}

// VerifyPayment verifies a payment with failover support across multiple facilitators
func VerifyPayment(
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
) (*x402types.VerifyResponse, error) {
	return VerifyPaymentWithCallback(paymentPayload, paymentRequirements, nil)
}

// VerifyPaymentWithCallback verifies a payment with an optional verification callback
func VerifyPaymentWithCallback(
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	onVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error,
) (*x402types.VerifyResponse, error) {
	processor := getProcessor(paymentPayload.Network)
	if processor == nil {
		return nil, fmt.Errorf("no processor configured for network: %s", paymentPayload.Network)
	}

	if len(processor.facilitatorClients) == 0 {
		return nil, fmt.Errorf("no facilitator clients available")
	}

	var lastErr error
	for i, client := range processor.facilitatorClients {
		processor.logger.Info("Trying facilitator for verification",
			"index", i+1,
			"total", len(processor.facilitatorClients),
			"url", client.URL,
			"network", paymentPayload.Network)

		verifyResp, err := processor.tryVerifyWithFacilitator(client, paymentPayload, paymentRequirements, onVerified)
		if err == nil {
			processor.logger.Info("Facilitator verification succeeded", "url", client.URL)
			return verifyResp, nil
		}

		processor.logger.Warn("Facilitator verification attempt failed",
			"url", client.URL,
			"error", err,
			"willRetry", shouldRetryWithNextFacilitator(err))

		lastErr = err

		// Don't retry for validation/client errors
		if !shouldRetryWithNextFacilitator(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("all facilitators failed, last error: %w", lastErr)
}

func DiscoverSupported(c *facilitatorclient.FacilitatorClient) []string {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/supported", c.URL), nil)
	if err != nil {
		return []string{}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	networks := make([]string, 0)
	var supportedNetworks struct {
		Kinds []struct {
			Scheme  string `json:"scheme"`
			Network string `json:"network"`
		} `json:"kinds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&supportedNetworks); err != nil {
		return []string{}
	}
	for _, kind := range supportedNetworks.Kinds {
		networks = append(networks, kind.Network)
	}

	return networks
}

func GetSupportedNetworks() []string {
	// return keys of processorMap
	keys := make([]string, 0)
	processorMap.Range(func(key, _ interface{}) bool {
		keys = append(keys, key.(string))
		return true
	})
	return keys
}

func ProcessTransfer(paymentPayload *x402types.PaymentPayload, resourceURL, asset string) (*x402types.SettleResponse, error) {
	return ProcessTransferWithCallback(paymentPayload, resourceURL, asset, nil, nil)
}

func ProcessTransferWithCallback(
	paymentPayload *x402types.PaymentPayload,
	resourceURL string,
	asset string,
	onVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error,
	onSettled func(*x402types.PaymentPayload, *x402types.PaymentRequirements, *x402types.SettleResponse) error,
) (*x402types.SettleResponse, error) {
	paymentRequirements, err := utils.DerivePaymentRequirements(paymentPayload, resourceURL, asset)
	if err != nil {
		return nil, fmt.Errorf("failed to derive payment requirements: %w", err)
	}

	return ProcessPaymentWithCallback(paymentPayload, paymentRequirements, false, onVerified, onSettled)
}
