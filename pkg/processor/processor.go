package processor

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/sigweihq/x402pay/pkg/constants"

	"github.com/coinbase/x402/go/pkg/coinbasefacilitator"
	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	x402types "github.com/coinbase/x402/go/pkg/types"
)

var (
	processorMap     sync.Map
	processorMapOnce sync.Once
)

// ProcessorConfig holds the configuration for payment processors
type ProcessorConfig struct {
	NetworkToFacilitatorURLs map[string][]string // Map of network name to facilitator URLs
	CDPAPIKeyID              string              // Optional: Coinbase CDP API key ID
	CDPAPIKeySecret          string              // Optional: Coinbase CDP API secret
}

// PaymentProcessor handles x402 payment verification and settlement with failover support
type PaymentProcessor struct {
	facilitatorConfigs []*x402types.FacilitatorConfig
	logger             *slog.Logger
}

// InitProcessorMap initializes the processor map with the given configuration
// This should be called once at application startup
func InitProcessorMap(config *ProcessorConfig, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	processorMapOnce.Do(func() {
		for network, urls := range config.NetworkToFacilitatorURLs {
			facilitatorConfigs := buildFacilitatorConfigs(urls, config.CDPAPIKeyID, config.CDPAPIKeySecret)
			processor := &PaymentProcessor{
				facilitatorConfigs: facilitatorConfigs,
				logger:             logger,
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

func GetFirstFacilitatorConfig(network string) *x402types.FacilitatorConfig {
	processor := getProcessor(network)
	if processor == nil {
		return nil
	}
	return processor.facilitatorConfigs[0]
}

// buildFacilitatorConfigs creates facilitator configurations from URLs or CDP credentials
func buildFacilitatorConfigs(urls []string, cdpAPIKeyID, cdpAPIKeySecret string) []*x402types.FacilitatorConfig {
	if cdpAPIKeyID != "" && cdpAPIKeySecret != "" {
		return []*x402types.FacilitatorConfig{
			coinbasefacilitator.CreateFacilitatorConfig(cdpAPIKeyID, cdpAPIKeySecret),
		}
	}

	configs := make([]*x402types.FacilitatorConfig, len(urls))
	for i, url := range urls {
		configs[i] = &x402types.FacilitatorConfig{URL: url}
	}
	return configs
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

// tryFacilitatorWithCallback attempts payment verification and settlement with a single facilitator
func (p *PaymentProcessor) tryFacilitatorWithCallback(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	onVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error,
) (*x402types.SettleResponse, error) {
	// Verify payment - safely log details with nil checks
	logAttrs := []any{"network", paymentPayload.Network}
	if paymentPayload.Payload != nil && paymentPayload.Payload.Authorization != nil {
		logAttrs = append(logAttrs,
			"from", paymentPayload.Payload.Authorization.From,
			"to", paymentPayload.Payload.Authorization.To,
			"value", paymentPayload.Payload.Authorization.Value)
	}
	p.logger.Info("Starting payment verification with facilitator", logAttrs...)

	verifyResp, err := client.Verify(paymentPayload, paymentRequirements)
	if err != nil {
		p.logger.Error("Payment verification failed", "error", err)
		return nil, fmt.Errorf("payment verification failed: %w", err)
	}

	p.logger.Info("Payment verification response received", "isValid", verifyResp.IsValid)

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

	// Settle payment
	p.logger.Info("Starting payment settlement")
	settleResp, err := client.Settle(paymentPayload, paymentRequirements)
	if err != nil {
		p.logger.Error("Payment settlement failed", "error", err)
		return nil, fmt.Errorf("payment settlement failed: %w", err)
	}

	p.logger.Info("Payment settlement response received", "success", settleResp.Success)

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
	skipVerification bool,
) (*x402types.SettleResponse, error) {
	return ProcessPaymentWithCallback(paymentPayload, paymentRequirements, skipVerification, nil)
}

// ProcessPaymentWithCallback verifies and settles a payment with an optional verification callback
func ProcessPaymentWithCallback(
	paymentPayload *x402types.PaymentPayload,
	paymentRequirements *x402types.PaymentRequirements,
	skipVerification bool,
	onVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error,
) (*x402types.SettleResponse, error) {
	processor := getProcessor(paymentPayload.Network)
	if processor == nil {
		return nil, fmt.Errorf("no processor configured for network: %s", paymentPayload.Network)
	}

	if len(processor.facilitatorConfigs) == 0 {
		return nil, fmt.Errorf("no facilitator configurations available")
	}

	var lastErr error
	for i, config := range processor.facilitatorConfigs {
		processor.logger.Info("Trying facilitator",
			"index", i+1,
			"total", len(processor.facilitatorConfigs),
			"url", config.URL,
			"network", paymentPayload.Network)

		// Create facilitator client with custom HTTP client that has timeouts
		// This prevents hanging indefinitely when facilitators are slow/unresponsive
		client := facilitatorclient.NewFacilitatorClient(config)
		client.HTTPClient = &http.Client{
			Timeout: constants.FacilitatorTimeout,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   constants.TLSHandshakeTimeout,
				ResponseHeaderTimeout: constants.ResponseHeaderTimeout,
				ExpectContinueTimeout: constants.ExpectContinueTimeout,
			},
		}

		settleResp, err := processor.tryFacilitatorWithCallback(client, paymentPayload, paymentRequirements, onVerified)
		if err == nil {
			processor.logger.Info("Facilitator succeeded", "url", config.URL)
			if !skipVerification {
				if verifyErr := VerifySettledTransaction(settleResp, paymentPayload); verifyErr != nil {
					processor.logger.Error("Transaction verification failed", "error", verifyErr)
					return nil, verifyErr
				}
			}
			return settleResp, nil
		}

		processor.logger.Warn("Facilitator attempt failed",
			"url", config.URL,
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
