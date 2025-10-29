package evm

import (
	"fmt"
	"math/big"
	"strings"

	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sigweihq/x402pay/pkg/chains"
)

// TransactionValidator implements chains.TransactionValidator for EVM chains
type TransactionValidator struct{}

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
		return fmt.Errorf("no transfer event found in transaction: %w", err)
	}

	// Extract "from" address from EVM payment payload
	evmPayload, ok := paymentPayload.(*x402types.PaymentPayload)
	if !ok {
		return fmt.Errorf("invalid payment payload type for EVM: %T", paymentPayload)
	}
	expectedFrom := common.HexToAddress(evmPayload.Payload.Authorization.From)

	// Extract actual values from transfer event
	actualFrom := common.HexToAddress(transferEvent.From)
	actualTo := common.HexToAddress(transferEvent.To)
	actualValue, ok := new(big.Int).SetString(transferEvent.Value, 10)
	if !ok {
		return fmt.Errorf("invalid value format in transfer event: %s", transferEvent.Value)
	}

	// Verify FROM address (from signed payload)
	if actualFrom != expectedFrom {
		return fmt.Errorf("transaction from address mismatch: got %s, expected %s",
			actualFrom.Hex(), expectedFrom.Hex())
	}

	// Verify TO address (from payment requirements)
	expectedTo := common.HexToAddress(paymentRequirements.PayTo)
	if actualTo != expectedTo {
		return fmt.Errorf("transaction to address mismatch: got %s, expected %s",
			actualTo.Hex(), expectedTo.Hex())
	}

	// Verify VALUE (from payment requirements)
	expectedValue, ok := new(big.Int).SetString(paymentRequirements.MaxAmountRequired, 10)
	if !ok {
		return fmt.Errorf("invalid value format in payment requirements: %s", paymentRequirements.MaxAmountRequired)
	}
	if actualValue.Cmp(expectedValue) != 0 {
		return fmt.Errorf("transaction value mismatch: got %s, expected %s",
			actualValue.String(), expectedValue.String())
	}

	// Verify ASSET (from payment requirements)
	if paymentRequirements.Asset == "" {
		return fmt.Errorf("asset not specified in payment requirements")
	}
	expectedAsset := common.HexToAddress(paymentRequirements.Asset)
	actualAsset := common.HexToAddress(transferEvent.Asset)
	if actualAsset != expectedAsset {
		return fmt.Errorf("token contract mismatch: got %s, expected %s",
			actualAsset.Hex(), expectedAsset.Hex())
	}

	return nil
}

// ExtractTransactionHash implements chains.TransactionValidator
func (v *TransactionValidator) ExtractTransactionHash(settleResponse *x402types.SettleResponse) (string, error) {
	txHash := settleResponse.Transaction
	if txHash == "" {
		return "", fmt.Errorf("no transaction hash in settle response")
	}

	if !strings.HasPrefix(txHash, "0x") {
		txHash = "0x" + txHash
	}

	if len(txHash) != 66 { // 0x + 64 hex chars
		return "", fmt.Errorf("invalid transaction hash format: %s", txHash)
	}

	return txHash, nil
}

// AddressesEqual implements chains.TransactionValidator
// EVM addresses are case-insensitive due to EIP-55 checksumming
func (v *TransactionValidator) AddressesEqual(addr1, addr2 string) bool {
	return strings.EqualFold(addr1, addr2)
}
