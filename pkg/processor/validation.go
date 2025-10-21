package processor

import (
	"fmt"
	"math/big"
	"strings"

	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// extractTransactionHash extracts the transaction hash from a settle response
func (p *PaymentProcessor) extractTransactionHash(settleResponse *x402types.SettleResponse) (string, error) {
	// The settle response contains transaction hash in the Transaction field
	txHash := settleResponse.Transaction
	if txHash == "" {
		return "", fmt.Errorf("no transaction hash in settle response")
	}

	if !strings.HasPrefix(txHash, "0x") {
		txHash = "0x" + txHash
	}

	// Validate hex format
	if len(txHash) != 66 { // 0x + 64 hex chars
		return "", fmt.Errorf("invalid transaction hash format: %s", txHash)
	}

	return txHash, nil
}

// validateTransactionParameters verifies the transaction matches the signed payload
func (p *PaymentProcessor) validateTransactionParameters(
	receipt *ethtypes.Receipt,
	paymentPayload *x402types.PaymentPayload,
) error {
	// Check transaction succeeded
	if receipt.Status != ethtypes.ReceiptStatusSuccessful {
		return fmt.Errorf("transaction failed on blockchain")
	}

	// For USDC transfers, we need to parse the Transfer event
	// Transfer(address indexed from, address indexed to, uint256 value)
	transferEventSignature := crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))

	var transferFound bool
	for _, log := range receipt.Logs {
		if len(log.Topics) >= 3 && log.Topics[0] == transferEventSignature {
			// Extract from, to, and value from the log
			from := common.HexToAddress(log.Topics[1].Hex())
			to := common.HexToAddress(log.Topics[2].Hex())
			value := new(big.Int).SetBytes(log.Data)

			// Get expected values from payment payload
			expectedFrom := common.HexToAddress(paymentPayload.Payload.Authorization.From)
			expectedTo := common.HexToAddress(paymentPayload.Payload.Authorization.To)
			expectedValue, ok := new(big.Int).SetString(paymentPayload.Payload.Authorization.Value, 10)
			if !ok {
				return fmt.Errorf("invalid value format in payment payload")
			}

			// Verify parameters match
			if from != expectedFrom {
				return fmt.Errorf("transaction from address mismatch: got %s, expected %s",
					from.Hex(), expectedFrom.Hex())
			}
			if to != expectedTo {
				return fmt.Errorf("transaction to address mismatch: got %s, expected %s",
					to.Hex(), expectedTo.Hex())
			}
			if value.Cmp(expectedValue) != 0 {
				return fmt.Errorf("transaction value mismatch: got %s, expected %s",
					value.String(), expectedValue.String())
			}

			transferFound = true
			break
		}
	}

	if !transferFound {
		return fmt.Errorf("no USDC transfer event found in transaction")
	}

	return nil
}

// VerifySettledTransaction verifies that the facilitator-settled transaction actually occurred on blockchain
func (p *PaymentProcessor) VerifySettledTransaction(
	settleResponse *x402types.SettleResponse,
	paymentPayload *x402types.PaymentPayload,
) error {
	// Extract transaction hash from settle response
	txHash, err := p.extractTransactionHash(settleResponse)
	if err != nil {
		return fmt.Errorf("failed to extract transaction hash: %w", err)
	}

	// Get transaction receipt with RPC failover using global manager
	rpcManager := GetGlobalRPCManager()
	receipt, err := rpcManager.GetTransactionReceipt(paymentPayload.Network, txHash)
	if err != nil {
		return fmt.Errorf("blockchain verification failed: %w", err)
	}

	if receipt == nil {
		// No RPC endpoints available - skip verification
		p.logger.Warn("skipping blockchain verification - no RPC endpoints available")
		return nil
	}

	// Verify transaction parameters match what was signed
	if err := p.validateTransactionParameters(receipt, paymentPayload); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	p.logger.Info("blockchain verification successful")

	return nil
}
