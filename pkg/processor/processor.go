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

// PaymentCallbacks provides hooks for monitoring payment processing operations
type PaymentCallbacks struct {
	// OnVerifyStart is called before each verification attempt
	// Returns error if operation should be aborted
	OnVerifyStart func(facilitatorURL string, attemptNumber int) error

	// OnVerifyComplete is called after each verification attempt
	// Parameters: facilitatorURL, attemptNumber, success, error, startTimeNanos, endTimeNanos
	OnVerifyComplete func(facilitatorURL string, attemptNumber int, success bool, err error, startTime, endTime int64) error

	// OnSettleStart is called before settlement attempt
	// Returns error if operation should be aborted
	OnSettleStart func(facilitatorURL string, attemptNumber int) error

	// OnSettleComplete is called after settlement attempt
	// Parameters: facilitatorURL, attemptNumber, success, error, startTimeNanos, endTimeNanos
	OnSettleComplete func(facilitatorURL string, attemptNumber int, success bool, err error, startTime, endTime int64) error

	// OnVerified is called after successful verification (before settlement)
	OnVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error

	// OnSettled is called after successful settlement
	OnSettled func(*x402types.PaymentPayload, *x402types.PaymentRequirements, *x402types.SettleResponse) error
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

// tryVerifyWithCallbacks attempts payment verification with a single facilitator
func (p *PaymentProcessor) tryVerifyWithCallbacks(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	attemptNumber int,
	callbacks *PaymentCallbacks,
) (*x402types.VerifyResponse, error) {
	// Call OnVerifyStart callback
	if callbacks != nil && callbacks.OnVerifyStart != nil {
		if err := callbacks.OnVerifyStart(client.URL, attemptNumber); err != nil {
			return nil, fmt.Errorf("verify start callback failed: %w", err)
		}
	}

	verifyStart := utils.GetCurrentTimeNanos()
	verifyResp, verifyErr := client.Verify(paymentPayload, paymentRequirements)
	verifyEnd := utils.GetCurrentTimeNanos()

	// Determine success
	verifySuccess := verifyErr == nil && verifyResp != nil && verifyResp.IsValid

	// Call OnVerifyComplete callback
	if callbacks != nil && callbacks.OnVerifyComplete != nil {
		if err := callbacks.OnVerifyComplete(client.URL, attemptNumber, verifySuccess, verifyErr, verifyStart, verifyEnd); err != nil {
			p.logger.Warn("Verify complete callback failed", "error", err)
		}
	}

	if verifyErr != nil {
		p.logger.Error("Payment verification failed", "error", verifyErr)
		return nil, fmt.Errorf("payment verification failed: %w", verifyErr)
	}

	if !verifyResp.IsValid {
		reason := "unknown"
		if verifyResp.InvalidReason != nil {
			reason = *verifyResp.InvalidReason
		}
		return nil, fmt.Errorf("payment verification failed: %s", reason)
	}

	// Call OnVerified callback after successful verification
	if callbacks != nil && callbacks.OnVerified != nil {
		if err := callbacks.OnVerified(paymentPayload, paymentRequirements); err != nil {
			return nil, fmt.Errorf("verification callback failed: %w", err)
		}
	}

	return verifyResp, nil
}

// tryFacilitatorWithCallbacks attempts payment verification and settlement with a single facilitator
func (p *PaymentProcessor) tryFacilitatorWithCallbacks(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	attemptNumber int,
	callbacks *PaymentCallbacks,
) (*x402types.SettleResponse, error) {
	// Verify payment with callbacks
	_, err := p.tryVerifyWithCallbacks(client, paymentPayload, paymentRequirements, attemptNumber, callbacks)
	if err != nil {
		return nil, err
	}

	// Call OnSettleStart callback
	if callbacks != nil && callbacks.OnSettleStart != nil {
		if err := callbacks.OnSettleStart(client.URL, attemptNumber); err != nil {
			return nil, fmt.Errorf("settle start callback failed: %w", err)
		}
	}

	settleStart := utils.GetCurrentTimeNanos()
	settleResp, settleErr := client.Settle(paymentPayload, paymentRequirements)
	settleEnd := utils.GetCurrentTimeNanos()

	// Determine success
	settleSuccess := settleErr == nil && settleResp != nil && settleResp.Success

	// Call OnSettleComplete callback
	if callbacks != nil && callbacks.OnSettleComplete != nil {
		if err := callbacks.OnSettleComplete(client.URL, attemptNumber, settleSuccess, settleErr, settleStart, settleEnd); err != nil {
			p.logger.Warn("Settle complete callback failed", "error", err)
		}
	}

	if settleErr != nil {
		p.logger.Error("Payment settlement failed", "error", settleErr)
		return nil, fmt.Errorf("payment settlement failed: %w", settleErr)
	}

	if !settleResp.Success {
		reason := "unknown"
		if settleResp.ErrorReason != nil {
			reason = *settleResp.ErrorReason
		}
		return nil, fmt.Errorf("payment settlement failed: %s", reason)
	}

	// Call OnSettled callback after successful settlement
	if callbacks != nil && callbacks.OnSettled != nil {
		if err := callbacks.OnSettled(paymentPayload, paymentRequirements, settleResp); err != nil {
			return settleResp, fmt.Errorf("settlement callback failed: %w", err)
		}
	}

	return settleResp, nil
}

// ProcessPayment verifies and settles a payment with failover support across multiple facilitators
func ProcessPayment(
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	confirm bool,
) (*x402types.SettleResponse, error) {
	return ProcessPaymentWithCallbacks(paymentPayload, paymentRequirements, confirm, nil)
}

// ProcessPaymentWithCallbacks verifies and settles a payment with comprehensive callback hooks for metrics collection
func ProcessPaymentWithCallbacks(
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	confirm bool,
	callbacks *PaymentCallbacks,
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
		attemptNumber := i + 1

		settleResp, err := processor.tryFacilitatorWithCallbacks(client, paymentPayload, paymentRequirements, attemptNumber, callbacks)
		if err == nil {
			if confirm {
				if verifyErr := VerifySettledTransaction(settleResp, paymentPayload); verifyErr != nil {
					processor.logger.Error("Transaction verification failed", "error", verifyErr)
					return nil, verifyErr
				}
			}

			return settleResp, nil
		}

		// If settlement succeeded but callback failed, return the response with error
		if settleResp != nil && settleResp.Success {
			processor.logger.Warn("Settlement succeeded but callback failed", "url", client.URL, "error", err)
			return settleResp, err
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
	return VerifyPaymentWithCallbacks(paymentPayload, paymentRequirements, nil)
}

// VerifyPaymentWithCallbacks verifies a payment with comprehensive callback hooks for metrics collection
func VerifyPaymentWithCallbacks(
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	callbacks *PaymentCallbacks,
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
		attemptNumber := i + 1
		processor.logger.Info("Trying facilitator for verification",
			"index", attemptNumber,
			"total", len(processor.facilitatorClients),
			"url", client.URL,
			"network", paymentPayload.Network)

		verifyResp, err := processor.tryVerifyWithCallbacks(client, paymentPayload, paymentRequirements, attemptNumber, callbacks)
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
	return ProcessTransferWithCallbacks(paymentPayload, resourceURL, asset, nil)
}

func ProcessTransferWithCallbacks(
	paymentPayload *x402types.PaymentPayload,
	resourceURL string,
	asset string,
	callbacks *PaymentCallbacks,
) (*x402types.SettleResponse, error) {
	paymentRequirements, err := utils.DerivePaymentRequirements(paymentPayload, resourceURL, asset)
	if err != nil {
		return nil, fmt.Errorf("failed to derive payment requirements: %w", err)
	}

	return ProcessPaymentWithCallbacks(paymentPayload, paymentRequirements, false, callbacks)
}
