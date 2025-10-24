package types

import "time"

// SupportedResponse represents the supported networks and payment schemes
// Matches x402 protocol specification
type SupportedResponse struct {
	Kinds []NetworkKind `json:"kinds"`
}

// NetworkKind contains information about a supported scheme/network combination
type NetworkKind struct {
	X402Version int    `json:"x402Version"`
	Scheme      string `json:"scheme"`  // Payment scheme (e.g., "exact")
	Network     string `json:"network"` // Network name (e.g., "base", "base-sepolia")
}

// MessageResponse represents the auth message response
type MessageResponse struct {
	Message string `json:"message"`
}

// AuthRequest represents a wallet authentication request
type AuthRequest struct {
	Message   string `json:"message" binding:"required"`
	Signature string `json:"signature"`
}

// User represents a user in the system
type User struct {
	ID            uint64 `json:"id"`
	WalletAddress string `json:"walletAddress"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// TokenPair represents access and refresh token pair
type TokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// HistoryParams represents parameters for transaction history queries
type HistoryParams struct {
	Network string `json:"network,omitempty"`
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
}

// HistoryResponse represents the transaction history response
type HistoryResponse struct {
	Transactions []*TransactionHistoryItem `json:"transactions"`
	Total        int                       `json:"total"`
	Limit        int                       `json:"limit"`
	Offset       int                       `json:"offset"`
}

// TransactionHistoryItem represents a single transaction in the history response
// Matches the base type from sigwei/packages/common/pkg/transactions
type TransactionHistoryItem struct {
	ID              int64            `json:"id"`
	CreatedAt       time.Time        `json:"createdAt"`
	UpdatedAt       time.Time        `json:"updatedAt"`
	SignerAddress   string           `json:"signerAddress"`
	Amount          string           `json:"amount"` // Wei units as string
	Network         string           `json:"network"`
	TransactionHash *string          `json:"transactionHash,omitempty"`
	Status          string           `json:"status"`
	Error           *string          `json:"error,omitempty"`
	X402Data        *X402DataHistory `json:"x402Data,omitempty"`
}

// X402DataHistory represents the x402 protocol specific data in history responses
type X402DataHistory struct {
	PaymentRequirementsJson *string `json:"paymentRequirements,omitempty"`
	PaymentPayload          []byte  `json:"paymentPayload,omitempty"`
	PaymentHeader           *string `json:"paymentHeader,omitempty"`
	SettleResponse          *string `json:"settleResponse,omitempty"`
	TypedData               *string `json:"typedData,omitempty"`
}
