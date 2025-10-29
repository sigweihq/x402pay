package processor

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/coinbase/x402/go/pkg/coinbasefacilitator"
	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/sigweihq/x402pay/pkg/constants"
	"github.com/sigweihq/x402pay/pkg/types"
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
	// Accepts any payload type (EVM or Solana)
	OnVerified func(paymentPayload any, paymentRequirements *x402types.PaymentRequirements) error

	// OnSettled is called after successful settlement
	// Accepts any payload type (EVM or Solana)
	OnSettled func(paymentPayload any, paymentRequirements *x402types.PaymentRequirements, settleResponse *x402types.SettleResponse) error
}

// PaymentProcessor handles x402 payment verification and settlement with failover support
type PaymentProcessor struct {
	// Maps feePayer address to facilitator clients
	// For EVM networks: key is "" (empty string)
	// For SVM networks: key is the feePayer address (or "" if no specific feePayer)
	feePayerToClients map[string][]*facilitatorclient.FacilitatorClient
	logger            *slog.Logger
}

// InitProcessorMap initializes the processor map with the given configuration
// This should be called once at application startup
func InitProcessorMap(config *ProcessorConfig, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	processorMapOnce.Do(func() {
		networkToFeePayerToClients := bootstrapFacilitatorClients(config.FacilitatorURLs, config.CDPAPIKeyID, config.CDPAPIKeySecret)
		discoveredNetworks := make([]string, 0, len(networkToFeePayerToClients))
		for network, feePayerToClients := range networkToFeePayerToClients {
			processor := &PaymentProcessor{
				feePayerToClients: feePayerToClients,
				logger:            logger,
			}
			// Count total facilitators across all fee payers
			totalFacilitators := 0
			for _, clients := range feePayerToClients {
				totalFacilitators += len(clients)
			}
			logger.Info("Payment processor initialized", "network", network, "facilitators", totalFacilitators, "feePayerGroups", len(feePayerToClients))
			for feePayer := range feePayerToClients {
				feePayerLabel := feePayer
				if feePayerLabel == "" {
					feePayerLabel = "<no-fee-payer>"
				}
			}
			processorMap.Store(network, processor)
			discoveredNetworks = append(discoveredNetworks, network)
		}
		// Store discovered networks for chain auto-discovery
		chains.SetDiscoveredNetworks(discoveredNetworks)
	})
}

func getProcessor(network string) *PaymentProcessor {
	processor, ok := processorMap.Load(network)
	if !ok {
		return nil
	}
	return processor.(*PaymentProcessor)
}

// registerClientForSupportedNetworks discovers supported networks for a client and registers it
func registerClientForSupportedNetworks(
	client *facilitatorclient.FacilitatorClient,
	networkToFeePayerToClients map[string]map[string][]*facilitatorclient.FacilitatorClient,
) {
	supportedKinds := DiscoverSupported(client)
	for _, kind := range supportedKinds {
		network := kind.Network
		feePayer := ""
		if kind.Extra != nil && kind.Extra.FeePayer != "" {
			feePayer = kind.Extra.FeePayer
		}

		if networkToFeePayerToClients[network] == nil {
			networkToFeePayerToClients[network] = make(map[string][]*facilitatorclient.FacilitatorClient)
		}
		networkToFeePayerToClients[network][feePayer] = append(networkToFeePayerToClients[network][feePayer], client)
	}
}

// bootstrapFacilitatorClients creates pre-configured facilitator clients from URLs or CDP credentials
// Returns a nested map: network -> feePayer -> []*FacilitatorClient
// For EVM networks, feePayer is "" (empty string)
func bootstrapFacilitatorClients(urls []string, cdpAPIKeyID, cdpAPIKeySecret string) map[string]map[string][]*facilitatorclient.FacilitatorClient {
	networkToFeePayerToClients := make(map[string]map[string][]*facilitatorclient.FacilitatorClient)
	// Create HTTP client with timeouts once, reused for all clients
	httpClient := utils.CreateHTTPClientWithTimeouts()

	// If CDP credentials are provided, only use CDP facilitator
	if cdpAPIKeyID != "" && cdpAPIKeySecret != "" {
		config := coinbasefacilitator.CreateFacilitatorConfig(cdpAPIKeyID, cdpAPIKeySecret)
		client := utils.NewFacilitatorClient(config, httpClient)
		// CDP facilitator supports these networks - discover their capabilities
		registerClientForSupportedNetworks(client, networkToFeePayerToClients)
	}

	// Create clients for each provided URL
	for _, url := range urls {
		// Validate URL security - skip invalid URLs
		if err := utils.ValidateFacilitatorURL(url); err != nil {
			continue
		}
		config := &x402types.FacilitatorConfig{URL: url}
		client := utils.NewFacilitatorClient(config, httpClient)
		registerClientForSupportedNetworks(client, networkToFeePayerToClients)
	}

	return networkToFeePayerToClients
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

// extractNetwork extracts the network field from any payment payload type
func extractNetwork(paymentPayload any) (string, error) {
	// Try x402 PaymentPayload first
	if p, ok := paymentPayload.(*x402types.PaymentPayload); ok {
		return p.Network, nil
	}

	// Try to marshal and extract from JSON
	data, err := json.Marshal(paymentPayload)
	if err != nil {
		return "", fmt.Errorf("failed to extract network from payload: %w", err)
	}
	var temp map[string]any
	if err := json.Unmarshal(data, &temp); err != nil {
		return "", fmt.Errorf("failed to parse payload: %w", err)
	}
	if network, ok := temp["network"].(string); ok {
		return network, nil
	}

	return "", fmt.Errorf("failed to extract network from payment payload")
}

// extractFeePayerFromSolanaPayload extracts the fee payer from a Solana transaction
// Returns empty string for non-Solana payloads or if extraction fails
func extractFeePayerFromSolanaPayload(paymentPayload any) string {
	// Try SolanaPaymentPayload first
	if p, ok := paymentPayload.(*types.SolanaPaymentPayload); ok {
		return utils.ExtractFeePayerFromSolanaTransaction(p.Payload.Transaction)
	}

	// Try to extract transaction from JSON for generic payloads
	data, err := json.Marshal(paymentPayload)
	if err != nil {
		return ""
	}
	var temp map[string]any
	if err := json.Unmarshal(data, &temp); err != nil {
		return ""
	}

	// Check if there's a nested payload with transaction
	if payload, ok := temp["payload"].(map[string]any); ok {
		if txBase64, ok := payload["transaction"].(string); ok {
			return utils.ExtractFeePayerFromSolanaTransaction(txBase64)
		}
	}

	return ""
}

// getFacilitatorClientsForPayment extracts network, gets processor, and returns facilitator clients for a payment
func getFacilitatorClientsForPayment(
	paymentPayload any,
) (*PaymentProcessor, []*facilitatorclient.FacilitatorClient, string, error) {
	network, err := extractNetwork(paymentPayload)
	if err != nil {
		return nil, nil, "", err
	}

	processor := getProcessor(network)
	if processor == nil {
		return nil, nil, "", fmt.Errorf("no processor configured for network: %s", network)
	}

	// Extract feePayer for routing (empty string for EVM or if not found)
	feePayer := extractFeePayerFromSolanaPayload(paymentPayload)

	// Get facilitator clients for this feePayer
	facilitatorClients := processor.feePayerToClients[feePayer]

	// Fallback to clients with no specific feePayer if none found
	if len(facilitatorClients) == 0 && feePayer != "" {
		facilitatorClients = processor.feePayerToClients[""]
	}

	if len(facilitatorClients) == 0 {
		if feePayer != "" {
			return nil, nil, "", fmt.Errorf("no facilitator clients available for network %s with feePayer %s", network, feePayer)
		}
		return nil, nil, "", fmt.Errorf("no facilitator clients available for network: %s", network)
	}

	return processor, facilitatorClients, network, nil
}

// verifyPaymentGeneric performs verification for any payload type (EVM or Solana)
// Uses the reusable HTTP helper to avoid code duplication
func verifyPaymentGeneric(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload any,
	paymentRequirements *x402types.PaymentRequirements,
) (*x402types.VerifyResponse, error) {
	requestBody := map[string]any{
		"x402Version":         1,
		"paymentPayload":      paymentPayload,
		"paymentRequirements": paymentRequirements,
	}

	return utils.MakeJSONRequest[x402types.VerifyResponse](
		client.HTTPClient,
		http.MethodPost,
		fmt.Sprintf("%s/verify", client.URL),
		requestBody,
		client.CreateAuthHeaders,
		"verify",
	)
}

// settlePaymentGeneric performs settlement for any payload type (EVM or Solana)
// Uses the reusable HTTP helper to avoid code duplication
func settlePaymentGeneric(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload any,
	paymentRequirements *x402types.PaymentRequirements,
) (*x402types.SettleResponse, error) {
	requestBody := map[string]any{
		"x402Version":         1,
		"paymentPayload":      paymentPayload,
		"paymentRequirements": paymentRequirements,
	}

	return utils.MakeJSONRequest[x402types.SettleResponse](
		client.HTTPClient,
		http.MethodPost,
		fmt.Sprintf("%s/settle", client.URL),
		requestBody,
		client.CreateAuthHeaders,
		"settle",
	)
}

// tryVerifyWithCallbacks attempts payment verification with a single facilitator
// Accepts any payload type (EVM or Solana)
func (p *PaymentProcessor) tryVerifyWithCallbacks(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload any,
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
	verifyResp, verifyErr := verifyPaymentGeneric(client, paymentPayload, paymentRequirements)
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
// Accepts any payload type (EVM or Solana)
func (p *PaymentProcessor) tryFacilitatorWithCallbacks(
	client *facilitatorclient.FacilitatorClient,
	paymentPayload any,
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
	settleResp, settleErr := settlePaymentGeneric(client, paymentPayload, paymentRequirements)
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

// retryWithFailover executes an operation with failover across multiple facilitators
func retryWithFailover[T any](
	processor *PaymentProcessor,
	facilitatorClients []*facilitatorclient.FacilitatorClient,
	operation func(*facilitatorclient.FacilitatorClient, int) (T, error),
	operationName string,
) (T, error) {
	var lastErr error
	var zeroValue T

	for i, client := range facilitatorClients {
		attemptNumber := i + 1
		result, err := operation(client, attemptNumber)
		if err == nil {
			return result, nil
		}

		processor.logger.Warn(fmt.Sprintf("Facilitator %s attempt failed", operationName),
			"url", client.URL,
			"error", err,
			"willRetry", shouldRetryWithNextFacilitator(err))

		lastErr = err

		if !shouldRetryWithNextFacilitator(err) {
			return zeroValue, err
		}
	}

	return zeroValue, fmt.Errorf("all facilitators failed, last error: %w", lastErr)
}

// ProcessPayment verifies and settles a payment with failover support across multiple facilitators
// Accepts any payload type (EVM or Solana)
func ProcessPayment(
	paymentPayload any,
	paymentRequirements *x402types.PaymentRequirements,
	confirm bool,
) (*x402types.SettleResponse, error) {
	return ProcessPaymentWithCallbacks(paymentPayload, paymentRequirements, confirm, nil)
}

// ProcessPaymentWithCallbacks verifies and settles a payment with comprehensive callback hooks for metrics collection
// Accepts any payload type (EVM or Solana)
func ProcessPaymentWithCallbacks(
	paymentPayload any,
	paymentRequirements *x402types.PaymentRequirements,
	confirm bool,
	callbacks *PaymentCallbacks,
) (*x402types.SettleResponse, error) {
	processor, facilitatorClients, _, err := getFacilitatorClientsForPayment(paymentPayload)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for i, client := range facilitatorClients {
		attemptNumber := i + 1

		settleResp, err := processor.tryFacilitatorWithCallbacks(client, paymentPayload, paymentRequirements, attemptNumber, callbacks)
		if err == nil {
			if confirm {
				if verifyErr := VerifySettledTransactionGeneric(settleResp, paymentPayload, paymentRequirements); verifyErr != nil {
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
// Accepts any payload type (EVM or Solana)
func VerifyPayment(
	paymentPayload any,
	paymentRequirements *x402types.PaymentRequirements,
) (*x402types.VerifyResponse, error) {
	return VerifyPaymentWithCallbacks(paymentPayload, paymentRequirements, nil)
}

// VerifyPaymentWithCallbacks verifies a payment with comprehensive callback hooks for metrics collection
// Accepts any payload type (EVM or Solana)
func VerifyPaymentWithCallbacks(
	paymentPayload any,
	paymentRequirements *x402types.PaymentRequirements,
	callbacks *PaymentCallbacks,
) (*x402types.VerifyResponse, error) {
	processor, facilitatorClients, _, err := getFacilitatorClientsForPayment(paymentPayload)
	if err != nil {
		return nil, err
	}

	return retryWithFailover(
		processor,
		facilitatorClients,
		func(client *facilitatorclient.FacilitatorClient, attemptNumber int) (*x402types.VerifyResponse, error) {
			return processor.tryVerifyWithCallbacks(client, paymentPayload, paymentRequirements, attemptNumber, callbacks)
		},
		"verification",
	)
}

func DiscoverSupported(c *facilitatorclient.FacilitatorClient) []types.NetworkKind {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/supported", c.URL), nil)
	if err != nil {
		return []types.NetworkKind{}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return []types.NetworkKind{}
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return []types.NetworkKind{}
	}

	limitedReader := io.LimitReader(resp.Body, int64(constants.MaxResponseBodySize))

	var supportedNetworks struct {
		Kinds []types.NetworkKind `json:"kinds"`
	}
	if err := json.NewDecoder(limitedReader).Decode(&supportedNetworks); err != nil {
		return []types.NetworkKind{}
	}

	return supportedNetworks.Kinds
}

// GetSupportedNetworks returns all supported network kinds with extra information
// including fee payers for Solana networks
func GetSupportedNetworks() []types.NetworkKind {
	kinds := make([]types.NetworkKind, 0)

	processorMap.Range(func(key, value any) bool {
		network := key.(string)
		processor := value.(*PaymentProcessor)

		if len(processor.feePayerToClients) == 0 {
			// No processor clients, skip
			return true
		}

		// Create NetworkKind for each fee payer combination
		// For EVM: one entry with feePayer=""
		// For SVM: one entry per feePayer address
		for feePayer := range processor.feePayerToClients {
			kind := types.NetworkKind{
				X402Version: 1,
				Scheme:      "exact",
				Network:     network,
			}
			if feePayer != "" {
				kind.Extra = &types.NetworkKindExtra{FeePayer: feePayer}
			}
			kinds = append(kinds, kind)
		}

		return true
	})

	return kinds
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
