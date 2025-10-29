package svm

import (
	"fmt"
	"strings"

	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/sigweihq/x402pay/pkg/types"
	"github.com/sigweihq/x402pay/pkg/utils"
)

// TransactionValidator implements chains.TransactionValidator for SVM chains
type TransactionValidator struct{}

// NewTransactionValidator creates a new SVM transaction validator
func NewTransactionValidator() *TransactionValidator {
	return &TransactionValidator{}
}

// ValidateTransaction implements chains.TransactionValidator
// This is the primary validation method that checks all transaction parameters
func (v *TransactionValidator) ValidateTransaction(
	receipt chains.TransactionReceipt,
	paymentPayload any,
	paymentRequirements *x402types.PaymentRequirements,
) error {
	// Verify transaction succeeded
	if !receipt.IsSuccessful() {
		return fmt.Errorf("transaction failed on blockchain")
	}

	// Get transfer event from receipt
	transferEvent, err := receipt.GetTransferEvent()
	if err != nil {
		return fmt.Errorf("no token transfer found in transaction: %w", err)
	}

	// Extract "from" address (fee payer) from Solana payment payload
	solanaPayload, ok := paymentPayload.(*types.SolanaPaymentPayload)
	if !ok {
		return fmt.Errorf("invalid payment payload type for SVM: %T", paymentPayload)
	}

	expectedFrom := utils.ExtractFeePayerFromSolanaTransaction(solanaPayload.Payload.Transaction)
	if expectedFrom == "" {
		return fmt.Errorf("failed to extract fee payer from Solana transaction")
	}

	// Note: transferEvent.From is the source ATA, but for wallet-level validation,
	// we validate the signer (fee payer), not the ATA.
	// The fee payer is the wallet that authorized the transaction.
	// For now, we skip strict From validation since the transfer instruction source
	// is an ATA, not a wallet address. The important validation is:
	// 1. The transaction was signed by the expected wallet (fee payer)
	// 2. The destination wallet matches
	// 3. The amount and asset match

	// Verify TO address (from payment requirements)
	// transferEvent.To is already the wallet owner (not ATA) per GetTransferEvent()
	if !v.AddressesEqual(transferEvent.To, paymentRequirements.PayTo) {
		return fmt.Errorf("transfer destination mismatch: expected %s, got %s",
			paymentRequirements.PayTo, transferEvent.To)
	}

	// Verify VALUE (from payment requirements)
	if transferEvent.Value != paymentRequirements.MaxAmountRequired {
		return fmt.Errorf("transfer amount mismatch: expected %s, got %s",
			paymentRequirements.MaxAmountRequired, transferEvent.Value)
	}

	// Verify ASSET (from payment requirements)
	if paymentRequirements.Asset == "" {
		return fmt.Errorf("asset not specified in payment requirements")
	}
	if !v.AddressesEqual(transferEvent.Asset, paymentRequirements.Asset) {
		return fmt.Errorf("token asset mismatch: expected %s, got %s",
			paymentRequirements.Asset, transferEvent.Asset)
	}

	// Additional validation: Verify the transaction was signed by the expected wallet
	// This ensures the fee payer matches what we expect
	// TODO: For stricter validation, we could verify the fee payer matches some expected value
	// from the payment requirements or payload. For now, we trust the signature verification
	// was done by the facilitator.
	_ = expectedFrom // Acknowledge we extracted it but aren't using it yet

	return nil
}

// ExtractTransactionHash implements chains.TransactionValidator
func (v *TransactionValidator) ExtractTransactionHash(settleResponse *x402types.SettleResponse) (string, error) {
	signature := settleResponse.Transaction
	if signature == "" {
		return "", fmt.Errorf("no transaction signature in settle response")
	}

	// SVM signatures are base58-encoded and typically 87-88 characters
	// Basic validation: check it's a reasonable length and doesn't contain invalid characters
	if len(signature) < 80 || len(signature) > 90 {
		return "", fmt.Errorf("invalid SVM transaction signature format: %s", signature)
	}

	// SVM signatures should not have 0x prefix
	if strings.HasPrefix(signature, "0x") {
		return "", fmt.Errorf("invalid SVM transaction signature (has 0x prefix): %s", signature)
	}

	return signature, nil
}

// AddressesEqual implements chains.TransactionValidator
// SVM addresses are case-sensitive (base58 encoding)
func (v *TransactionValidator) AddressesEqual(addr1, addr2 string) bool {
	return addr1 == addr2
}
