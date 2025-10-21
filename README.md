# x402pay

A Go library for processing x402 payments with facilitator aggregation and blockchain verification.

## Features

- **Facilitator Aggregation**: Automatically failover between multiple x402 facilitators for high availability
- **Blockchain Verification**: Verify settled transactions on-chain to ensure payment integrity
- **CDP Integration**: Built-in support for Coinbase Developer Platform facilitators
- **RPC Failover**: Automatic RPC endpoint failover with health checking
- **Stateless**: No dependencies on web frameworks - pure business logic

## Installation

```bash
go get github.com/sigweihq/x402pay
```

## Quick Start

```go
package main

import (
    "log/slog"
    "os"

    "github.com/sigweihq/x402pay/pkg/processor"
    x402types "github.com/coinbase/x402/go/pkg/types"
)

func main() {
    // Initialize logger
    logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

    // Initialize RPC manager for blockchain verification
    processor.InitGlobalRPCManager(logger)

    // Configure facilitators
    config := &processor.FacilitatorConfig{
        FacilitatorURLs:        []string{"https://facilitator1.com"},
        FacilitatorTestnetURLs: []string{"https://testnet-facilitator.com"},
        // Optional: Use Coinbase CDP
        CDPAPIKeyID:     os.Getenv("CDP_API_KEY_ID"),
        CDPAPIKeySecret: os.Getenv("CDP_API_KEY_SECRET"),
    }

    // Create payment processor
    paymentProcessor := processor.NewPaymentProcessor(config, logger)

    // Process a payment
    settleResp, err := paymentProcessor.ProcessPayment(
        paymentPayload,      // *x402types.PaymentPayload
        paymentRequirements, // *x402types.PaymentRequirements
        true,                // isTest (testnet)
        false,               // skipVerification
    )
    if err != nil {
        logger.Error("Payment failed", "error", err)
        return
    }

    logger.Info("Payment successful", "txHash", settleResp.Transaction)
}
```

## Architecture

### Components

1. **PaymentProcessor** (`pkg/processor/processor.go`)
   - Orchestrates payment verification and settlement
   - Handles facilitator failover automatically
   - Supports optional verification callbacks

2. **RPCManager** (`pkg/processor/rpc.go`)
   - Manages blockchain RPC endpoints
   - Automatic health checking and prioritization
   - Fetches additional endpoints from chainlist.org

3. **Blockchain Verification** (`pkg/processor/validation.go`)
   - Verifies transactions on-chain
   - Validates transaction parameters match signed payload
   - Ensures payment integrity

4. **Constants** (`pkg/constants/constants.go`)
   - Network definitions (Base, Base Sepolia)
   - USDC token addresses
   - Chain IDs (CAIP-2 format)

### Facilitator Failover

The library automatically tries multiple facilitators in sequence:

1. First facilitator attempt
2. If it fails with retryable error (timeout, 5xx, auth), try next
3. If it fails with client error (4xx, invalid signature), return error immediately
4. Continue until success or all facilitators exhausted

### Optional Blockchain Verification

After facilitator settlement, the library:

1. Extracts transaction hash from settle response
2. Fetches transaction receipt from blockchain (with RPC failover)
3. Validates transaction parameters:
   - Transaction succeeded (status == 1)
   - From/to addresses match signed payload
   - Amount matches signed payload
   - USDC Transfer event is present

## API Reference

### PaymentProcessor

```go
// Create a new payment processor
func NewPaymentProcessor(config *FacilitatorConfig, logger *slog.Logger) *PaymentProcessor

// Process payment without callback
func (p *PaymentProcessor) ProcessPayment(
    paymentPayload *x402types.PaymentPayload,
    paymentRequirements *x402types.PaymentRequirements,
    isTest bool,
    skipVerification bool,
) (*x402types.SettleResponse, error)

// Process payment with verification callback
func (p *PaymentProcessor) ProcessPaymentWithCallback(
    paymentPayload *x402types.PaymentPayload,
    paymentRequirements *x402types.PaymentRequirements,
    isTest bool,
    skipVerification bool,
    onVerified func(*x402types.PaymentPayload, *x402types.PaymentRequirements) error,
) (*x402types.SettleResponse, error)
```

### RPCManager

```go
// Initialize global RPC manager (call once at startup)
func InitGlobalRPCManager(logger *slog.Logger)

// Get singleton instance
func GetGlobalRPCManager() *RPCManager

// Get transaction receipt with failover
func (r *RPCManager) GetTransactionReceipt(network, txHash string) (*ethtypes.Receipt, error)
```

### Configuration

```go
type FacilitatorConfig struct {
    FacilitatorURLs        []string // Mainnet facilitator URLs
    FacilitatorTestnetURLs []string // Testnet facilitator URLs
    CDPAPIKeyID            string   // Optional: Coinbase CDP API key ID
    CDPAPIKeySecret        string   // Optional: Coinbase CDP API secret
}
```

## Development

```bash
# Run tests
go test ./...

# Build
go build ./...

# Run tests with coverage
go test -cover ./...
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or pull request.
