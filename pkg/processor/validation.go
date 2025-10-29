package processor

import (
	"fmt"

	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/sigweihq/x402pay/pkg/chains"
)

// extractTransactionHash extracts the transaction hash from a settle response
func extractTransactionHash(settleResponse *x402types.SettleResponse) (string, error) {
	if settleResponse.Network == "" {
		return "", fmt.Errorf("settle response missing network field")
	}

	registry := chains.GetGlobalRegistry()
	if registry == nil {
		return "", fmt.Errorf("chain registry not initialized")
	}

	adapter, err := registry.Get(settleResponse.Network)
	if err != nil {
		return "", fmt.Errorf("no chain adapter for network %s: %w", settleResponse.Network, err)
	}

	return adapter.TransactionValidator().ExtractTransactionHash(settleResponse)
}

// VerifySettledTransactionGeneric verifies that the facilitator-settled transaction actually occurred on blockchain
// Works with any payload type (EVM or Solana) by delegating to chain-specific validators
func VerifySettledTransactionGeneric(
	settleResponse *x402types.SettleResponse,
	paymentPayload any,
	paymentRequirements *x402types.PaymentRequirements,
) error {
	// Validate that settle response network matches payment requirements network
	if settleResponse.Network != paymentRequirements.Network {
		return fmt.Errorf("network mismatch: settle response has %s but payment requirements has %s",
			settleResponse.Network, paymentRequirements.Network)
	}

	processor := getProcessor(paymentRequirements.Network)
	if processor == nil {
		return fmt.Errorf("no processor configured for network: %s", paymentRequirements.Network)
	}

	// Extract transaction hash using chain-specific validator
	txHash, err := extractTransactionHash(settleResponse)
	if err != nil {
		return fmt.Errorf("failed to extract transaction hash: %w", err)
	}

	// Get chain adapter from registry
	registry := chains.GetGlobalRegistry()
	if registry == nil {
		return fmt.Errorf("chain registry not initialized - initialize chains at startup (e.g., svm.InitSVMChains(logger))")
	}

	adapter, err := registry.Get(paymentRequirements.Network)
	if err != nil {
		return fmt.Errorf("no chain adapter registered for network %s: %w", paymentRequirements.Network, err)
	}

	// Get transaction receipt using chain-specific RPC client
	receipt, err := adapter.RPCClient().GetTransactionReceipt(txHash)
	if err != nil {
		return fmt.Errorf("blockchain verification failed: %w", err)
	}

	if receipt == nil {
		processor.logger.Warn("skipping blockchain verification - no RPC endpoints available")
		return nil
	}

	validator := adapter.TransactionValidator()
	if err := validator.ValidateTransaction(receipt, paymentPayload, paymentRequirements); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	return nil
}
