package chains

import (
	x402types "github.com/coinbase/x402/go/pkg/types"
)

// Design inspired by renproject/multichain with x402-specific extensions
// https://github.com/renproject/multichain

// ChainAdapter provides blockchain-specific operations for payment verification
type ChainAdapter interface {
	// Network returns the network name (e.g., "base", "solana")
	Network() string

	// RPCClient returns the RPC client manager for this chain
	RPCClient() RPCClient

	// SignatureScheme returns the signature scheme for this chain
	SignatureScheme() SignatureScheme

	// TransactionValidator returns the transaction validator for this chain
	TransactionValidator() TransactionValidator
}

// RPCClient handles blockchain RPC operations
type RPCClient interface {
	// GetTransactionReceipt retrieves a transaction receipt with failover
	GetTransactionReceipt(txHash string) (TransactionReceipt, error)

	// IsHealthy performs a health check on the RPC endpoint
	IsHealthy(endpoint string) bool
}

// EIP3009Checker is an optional interface for checking EIP-3009 nonce usage on-chain
// Implemented by: RPCClient
// Part of: EIP-3009 (USDC TransferWithAuthorization standard)
type EIP3009Checker interface {
	// IsNonceAlreadyUsed checks if a nonce has been used on-chain
	// Only relevant for EVM chains with EIP-3009 compliant contracts
	IsNonceAlreadyUsed(nonce, authorizer, asset string) (bool, error)
}

// TransactionReceipt is a chain-agnostic transaction receipt
type TransactionReceipt interface {
	// IsSuccessful returns whether the transaction succeeded
	IsSuccessful() bool

	// GetTransferEvent returns transfer event data if present
	GetTransferEvent() (*TransferEvent, error)
}

// TransferEvent represents a token transfer event
type TransferEvent struct {
	From  string // Sender wallet address
	To    string // Recipient wallet address (for SVM, this is the owner of the ATA, not the ATA itself)
	Value string
	Asset string // Token contract address (EVM) or mint address (SVM)
}

// SignatureScheme handles basic signature operations (all chains must implement)
type SignatureScheme interface {
	// DeriveAddress derives the address from a private key
	DeriveAddress(privateKey interface{}) (string, error)
}

// EIP3009Signer is an optional interface for creating EIP-3009 signatures
// Implemented by: SignatureScheme
// Part of: EIP-3009 (USDC TransferWithAuthorization standard)
type EIP3009Signer interface {
	// CreateSignature creates an EIP-3009 signature for TransferWithAuthorization
	CreateSignature(privateKey interface{}, authorization interface{}, network, asset, domainName string) (string, error)
}

// EIP712TypedDataProvider is an optional interface for creating EIP-712 typed data
// Implemented by: SignatureScheme
// Part of: EIP-712 (Ethereum typed structured data hashing and signing)
type EIP712TypedDataProvider interface {
	// CreateTypedData converts authorization to EIP-712 typed data JSON
	CreateTypedData(paymentRequirements *x402types.PaymentRequirements, authorization interface{}, domainName string) (string, error)
}

// TransactionValidator validates transaction parameters
type TransactionValidator interface {
	// ValidateTransaction verifies transaction matches both the payment payload and requirements
	// This is the primary validation method used by the processor
	// - receipt: The blockchain transaction receipt
	// - paymentPayload: The original payment payload (chain-specific type: *x402types.PaymentPayload or *types.SolanaPaymentPayload)
	// - paymentRequirements: The payment requirements (chain-agnostic)
	ValidateTransaction(receipt TransactionReceipt, paymentPayload any, paymentRequirements *x402types.PaymentRequirements) error

	// ExtractTransactionHash extracts the transaction hash from a settle response
	ExtractTransactionHash(settleResponse *x402types.SettleResponse) (string, error)

	// AddressesEqual compares two addresses using chain-specific rules
	// For EVM: case-insensitive (due to EIP-55 checksumming)
	// For SVM: case-sensitive (base58 encoding)
	AddressesEqual(addr1, addr2 string) bool
}
