# x402pay

A high-level Go SDK for processing x402 payments with multi-network support, facilitator aggregation, load balancing, and blockchain verification.

Built on top of [coinbase/x402](https://github.com/coinbase/x402), this SDK provides production-ready payment processing with load balancing, automatic failover, blockchain verification, and simplified integration.

## Features

- **Multi-Network Support**: Support for EVM (Ethereum, Base, etc.) and SVM (Solana) chains
- **Automatic Network Discovery**: Facilitators automatically discover and register supported networks via `/supported` endpoint
- **Multi-Fee-Payer Support**: Route Solana transactions to the correct facilitator based on fee payer address
- **Load Balancing & Failover**: Random start + round-robin load balancing across facilitators with automatic failover for high availability
- **RPC Load Balancing**: Load-balanced blockchain verification across multiple RPC endpoints to avoid rate limits and optimize costs
- **Blockchain Verification**: Verify settled transactions on-chain to ensure payment integrity
- **CDP Integration**: Built-in support for Coinbase Developer Platform facilitators
- **RPC Failover**: Automatic RPC endpoint discovery and health checking for EVM chains
- **Stateless**: No dependencies on web frameworks - pure business logic

## What is x402?

[x402](https://github.com/coinbase/x402) is an HTTP payment protocol that enables paid API endpoints using blockchain-based payments. This SDK builds on the official protocol implementation to provide:

- **Higher-level abstractions** - Simple payment processing without managing low-level protocol details
- **Production features** - Facilitator failover, health checking, and blockchain verification
- **Developer experience** - Minimal configuration with sensible defaults

Use this SDK if you need to process x402 payments in your Go application. Use [coinbase/x402](https://github.com/coinbase/x402) directly if you're building protocol-level tooling or need low-level control.

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
    "github.com/sigweihq/x402pay/pkg/chains/evm"
    "github.com/sigweihq/x402pay/pkg/chains/svm"
    "github.com/sigweihq/x402pay/pkg/constants"
)

func main() {
    // Initialize logger
    logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

    // Configure payment processors
    // Networks are automatically discovered via facilitator /supported endpoints
    config := &processor.ProcessorConfig{
        FacilitatorURLs: []string{
            "https://facilitator1.com",
            "https://facilitator2.com",
        },
        // Optional: Use Coinbase CDP (supports both EVM and SVM)
        CDPAPIKeyID:     os.Getenv("CDP_API_KEY_ID"),
        CDPAPIKeySecret: os.Getenv("CDP_API_KEY_SECRET"),
    }

    // Initialize processor map once at startup
    // Each facilitator's /supported endpoint is queried to discover networks
    processor.InitProcessorMap(config, logger)

    // Initialize chains - will auto-discover networks from facilitators above
    // EVM chains use automatic endpoint discovery from chainlist.org
    err := evm.InitEVMChains(logger)
    if err != nil {
        logger.Error("Failed to initialize EVM chains", "error", err)
        return
    }

    // SVM chains use official RPC endpoints
    err = svm.InitSVMChains(logger)
    if err != nil {
        logger.Error("Failed to initialize SVM chains", "error", err)
        return
    }

    // Process a payment - processor is automatically selected based on network
    settleResp, err := processor.ProcessPayment(
        paymentPayload,      // any (EVM or Solana payment payload with Network field)
        paymentRequirements, // *x402types.PaymentRequirements
        true,                // confirm on the blockchain
    )
    if err != nil {
        logger.Error("Payment failed", "error", err)
        return
    }

    logger.Info("Payment successful", "txHash", settleResp.Transaction)
}
```

## Chain Initialization

The SDK uses a chain abstraction layer to support multiple blockchains. You can initialize chains in two ways:

### Option 1: Auto-Discovery (Recommended)

Initialize the processor map first, then chains will automatically discover which networks to support:

```go
// 1. Initialize processor map to discover supported networks
processor.InitProcessorMap(config, logger)

// 2. Initialize chains - they auto-discover networks from step 1
evm.InitEVMChains(logger)  // Auto-discovers EVM networks (base, polygon, etc.)
svm.InitSVMChains(logger)  // Auto-discovers SVM networks (solana, solana-devnet, etc.)
```

This approach ensures you only initialize RPC clients for networks your facilitators actually support.

### Option 2: Manual Network Selection

Specify exactly which networks to initialize:

### EVM Chains (Automatic Endpoint Discovery)

```go
// Initialize with automatic endpoint discovery from chainlist.org
err := evm.InitEVMChains(logger, "base", "base-sepolia", "ethereum")
```

This will:
- Fetch RPC endpoints from chainlist.org
- Perform health checks and prioritize working endpoints
- Register chain adapters in the global registry
- Start background refresh (every 6 hours)

### EVM Chains (User-Provided Endpoints)

```go
// Initialize with your own RPC endpoints
endpoints := map[string][]string{
    "base":         {"https://mainnet.base.org", "https://base.llamarpc.com"},
    "base-sepolia": {"https://sepolia.base.org"},
}
err := evm.InitEVMChainsWithEndpoints(logger, endpoints)
```

This is useful when:
- You have private RPC endpoints
- You want full control over endpoint selection
- You're in a restricted network environment

### SVM Chains (Solana)

```go
// Option 1: Initialize with default official RPC endpoints (recommended)
// This initializes both Solana mainnet and devnet
err := svm.InitSVMChains(logger)

// Option 2: Initialize specific networks with official RPC endpoints
err := svm.InitSVMChains(logger, "solana", "solana-devnet")

// Option 3: Initialize with custom RPC endpoints
endpoints := map[string][]string{
    "solana":         {"https://api.mainnet-beta.solana.com"},
    "solana-devnet":  {"https://api.devnet.solana.com"},
}
err := svm.InitSVMChainsWithEndpoints(logger, endpoints)
```

**Auto-Discovery Behavior:**
- If called **after** `InitProcessorMap`: Auto-discovers SVM networks from facilitator `/supported` endpoints
- If called **before** `InitProcessorMap`: Falls back to both Solana mainnet and devnet
- With explicit networks: Uses those specific networks with official RPC endpoints

Each network is registered with its own adapter in the global chain registry.

## Architecture

### Chain Abstraction Layer

The SDK provides a pluggable architecture for blockchain support:

```
pkg/chains/
├── chain.go              # Core interfaces (ChainAdapter, RPCClient, etc.)
├── registry.go           # Global chain registry
├── evm/                  # EVM chain implementation
│   ├── base_adapter.go   # EVM chain adapter
│   ├── rpc.go            # RPC client with failover
│   ├── signer.go         # EIP-712/EIP-3009 signatures
│   ├── validator.go      # Transaction validation
│   ├── init.go           # Initialization functions
│   └── endpoint_provider.go  # Chainlist.org integration
└── svm/                  # SVM chain implementation (Solana)
    ├── adapter.go        # SVM chain adapter
    ├── rpc.go            # Solana RPC client
    ├── validator.go      # Solana transaction validation
    └── init.go           # Initialization functions
```

**Core Interfaces:**

- **ChainAdapter** - Provides blockchain-specific operations (RPC, signing, validation)
- **RPCClient** - Handles RPC operations with automatic failover
- **SignatureScheme** - Creates chain-specific signatures (EIP-712, EIP-3009)
- **TransactionValidator** - Validates transactions match payment payloads

**Optional Interfaces:**

- **EIP3009Signer** - For USDC TransferWithAuthorization (EVM only)
- **EIP3009Checker** - For checking nonce usage on-chain (EVM only)
- **EIP712TypedDataProvider** - For EIP-712 typed data (EVM only)

### Components

1. **PaymentProcessor** (`pkg/processor/processor.go`)
   - Orchestrates payment verification and settlement
   - Handles facilitator failover automatically
   - Supports optional verification callbacks

2. **Chain Adapters** (`pkg/chains/`)
   - Manages blockchain RPC endpoints with load balancing
   - Random start + round-robin selection across RPC endpoints
   - Automatic health checking and prioritization
   - Chain-specific transaction validation

3. **Blockchain Verification** (`pkg/processor/validation.go`)
   - Verifies transactions on-chain
   - Validates transaction parameters match signed payload
   - Ensures payment integrity

4. **Constants** (`pkg/constants/constants.go`)
   - Network definitions (Base, Base Sepolia, Ethereum, etc.)
   - USDC token addresses
   - Chain IDs (CAIP-2 format)

### Processor Map Architecture

The library uses an internal map of network → `PaymentProcessor`:

1. At startup, `InitProcessorMap()` queries each facilitator's `/supported` endpoint to discover networks
2. Creates one processor per network, each with its own list of facilitator clients
3. For Solana networks, processors maintain a `feePayerToClients` map to route transactions to the correct facilitator based on fee payer address
4. When processing a payment, the correct processor is automatically selected based on `paymentPayload.Network`
5. For Solana transactions, the fee payer is extracted and used to select the appropriate facilitator client
6. All facilitator configs are created once during initialization, eliminating overhead on payment processing

### Facilitator Failover & Load Balancing

The payment processor provides automatic load balancing and failover across multiple facilitators:

**Load Balancing:**
- Uses random start position with round-robin selection
- Distributes requests evenly across all configured facilitators
- Improves throughput and resource utilization
- Example: With facilitators [A, B, C], requests might start at B→C→A, A→B→C, or C→A→B

**Failover Logic:**
1. Determines the network from `paymentPayload.Network`
2. Retrieves the pre-configured processor for that network
3. For Solana: Extracts the fee payer address and selects matching facilitators
4. Picks a random facilitator to start (for load balancing)
5. If it fails with retryable error (timeout, 5xx, auth), tries next facilitator
6. If it fails with client error (4xx, invalid signature), returns error immediately
7. Continues round-robin through all facilitators until success or all exhausted

This approach ensures both high availability (failover) and efficient resource usage (load balancing).

### Blockchain Verification

After facilitator settlement, the library verifies transactions on-chain with automatic load balancing and failover:

**Load Balancing:**
- Uses random start position with round-robin selection for RPC endpoints
- Distributes verification requests evenly across all configured RPC endpoints
- Prevents rate limiting on individual endpoints
- Optimizes cost for paid RPC services (Alchemy, Infura, QuickNode)

**Verification Process:**
1. Validates settle response network matches payment payload network
2. Extracts transaction hash from settle response
3. Fetches transaction receipt from blockchain (with load-balanced RPC failover)
4. Validates transaction parameters using chain-specific validator:
   - Transaction succeeded (status == 1)
   - From/to addresses match signed payload
   - Amount matches signed payload
   - Token transfer event is present

## Payment Types

### EVM Payments

Use the standard x402 `PaymentPayload` type for EVM chains:

```go
import x402types "github.com/coinbase/x402/go/pkg/types"

payload := &x402types.PaymentPayload{
    X402Version: 1,
    Scheme:      "eip3009",
    Network:     "base",
    Payload: &x402types.ExactEvmPayload{
        From:             senderAddress,
        To:               receiverAddress,
        Value:            amount,
        ValidAfter:       0,
        ValidBefore:      validBefore,
        Nonce:            nonce,
        V:                v,
        R:                r,
        S:                s,
    },
}
```

### Solana Payments

Use the SDK's `SolanaPaymentPayload` type for Solana chains:

```go
import "github.com/sigweihq/x402pay/pkg/types"

payload := &types.SolanaPaymentPayload{
    X402Version: 1,
    Scheme:      "solana-transfer",
    Network:     "solana",
    Payload: &types.ExactSolanaPayload{
        Transaction: base64EncodedSignedTransaction,
    },
}
```

The SDK will automatically:
- Extract the network from the payload
- Route to the appropriate processor
- For Solana: Extract the fee payer and route to the correct facilitator

## API Reference

### Chain Initialization

```go
// Initialize EVM chains with automatic endpoint discovery
// - With networks: Initializes specified networks with chainlist.org endpoints
// - Without networks after InitProcessorMap: Auto-discovers networks from facilitators
// - Without networks before InitProcessorMap: Initializes registry only (no chains)
func evm.InitEVMChains(logger *slog.Logger, networksToMonitor ...string) error

// Initialize EVM chains with user-provided endpoints
func evm.InitEVMChainsWithEndpoints(logger *slog.Logger, endpoints map[string][]string) error

// Initialize SVM chains with official RPC endpoints
// - With networks: Initializes specified networks with official endpoints
// - Without networks after InitProcessorMap: Auto-discovers networks from facilitators
// - Without networks before InitProcessorMap: Defaults to solana and solana-devnet
func svm.InitSVMChains(logger *slog.Logger, networksToMonitor ...string) error

// Initialize SVM chains with custom endpoints (with fallback to official)
func svm.InitSVMChainsWithEndpoints(logger *slog.Logger, endpoints map[string][]string) error
```

### Processor Initialization

```go
// Initialize processor map once at startup
// Networks are automatically discovered via facilitator /supported endpoints
func InitProcessorMap(config *ProcessorConfig, logger *slog.Logger)
```

### Payment Processing

```go
// Process payment without callback
// Automatically selects the correct processor based on paymentPayload.Network
// Accepts both EVM and Solana payment payloads
func ProcessPayment(
    paymentPayload any,  // *x402types.PaymentPayload or *types.SolanaPaymentPayload
    paymentRequirements *x402types.PaymentRequirements,
    confirm bool,
) (*x402types.SettleResponse, error)

// Process payment with callbacks for metrics and custom logic
func ProcessPaymentWithCallbacks(
    paymentPayload any,
    paymentRequirements *x402types.PaymentRequirements,
    confirm bool,
    callbacks *PaymentCallbacks,
) (*x402types.SettleResponse, error)

// Verify payment without settlement
func VerifyPayment(
    paymentPayload any,
    paymentRequirements *x402types.PaymentRequirements,
) (*x402types.VerifyResponse, error)

// Verify payment with callbacks
func VerifyPaymentWithCallbacks(
    paymentPayload any,
    paymentRequirements *x402types.PaymentRequirements,
    callbacks *PaymentCallbacks,
) (*x402types.VerifyResponse, error)

// PaymentCallbacks allows custom logic during payment flow
type PaymentCallbacks struct {
    OnVerifyStart    func(facilitatorURL string, attemptNumber int) error
    OnVerifyComplete func(facilitatorURL string, attemptNumber int, success bool, err error, startTime, endTime int64) error
    OnSettleStart    func(facilitatorURL string, attemptNumber int) error
    OnSettleComplete func(facilitatorURL string, attemptNumber int, success bool, err error, startTime, endTime int64) error
    OnVerified       func(paymentPayload any, paymentRequirements *x402types.PaymentRequirements) error
    OnSettled        func(paymentPayload any, paymentRequirements *x402types.PaymentRequirements, settleResponse *x402types.SettleResponse) error
}
```

### HubClient (Solana Methods)

```go
// Verify Solana payment
func (c *HubClient) VerifySolana(
    payload *types.SolanaPaymentPayload,
    requirements *x402types.PaymentRequirements,
) (*x402types.VerifyResponse, error)

// Settle Solana payment
func (c *HubClient) SettleSolana(
    payload *types.SolanaPaymentPayload,
    requirements *x402types.PaymentRequirements,
) (*x402types.SettleResponse, error)

// Settle Solana payment with options
func (c *HubClient) SettleWithOptionsSolana(
    payload *types.SolanaPaymentPayload,
    requirements *x402types.PaymentRequirements,
    confirm bool,
    useDbId bool,
) (*x402types.SettleResponse, error)

// Convenient Solana transfer endpoint
func (c *HubClient) TransferSolana(
    payload *types.ExactSolanaPayload,
    network string,
    asset string,
    confirm bool,
) (*x402types.SettleResponse, error)
```

### Configuration

```go
type ProcessorConfig struct {
    FacilitatorURLs []string // List of facilitator URLs (networks auto-discovered)
    CDPAPIKeyID     string   // Optional: Coinbase CDP API key ID
    CDPAPIKeySecret string   // Optional: Coinbase CDP API secret
}
```

**Note**:
- Initialize chains before initializing the processor map
- Networks are automatically discovered by querying each facilitator's `/supported` endpoint
- Each network gets its own `PaymentProcessor` with pre-built facilitator configurations
- For Solana: Fee payer address is extracted and used to route to the correct facilitator
- The correct processor is automatically selected based on the `Network` field in the payment payload

## Supported Networks

### EVM Networks
- Ethereum
- Base
- Base Sepolia
- (Any EVM-compatible network via chainlist.org or custom RPC endpoints)

### SVM Networks
- Solana Mainnet
- Solana Devnet
- Solana Testnet

## Adding New Chains

To add support for a new blockchain (e.g., Cosmos, Aptos):

1. Create a new package: `pkg/chains/newchain/`
2. Implement the core interfaces:
   - `ChainAdapter`
   - `RPCClient`
   - `SignatureScheme` (if applicable)
   - `TransactionValidator`
3. Create initialization function: `newchain.InitNewChains()`
4. Register adapters in the global chain registry
5. Add network constants to `pkg/constants/`

The payment processor will automatically work with the new chain once registered. The processor uses duck typing to accept any payload type with a `Network` field.

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
