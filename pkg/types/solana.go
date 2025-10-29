package types

import (
	"encoding/json"

	x402types "github.com/coinbase/x402/go/pkg/types"
)

// ExactSolanaPayload represents the Solana-specific payment payload
// This is a local extension until official x402 Go types support Solana
type ExactSolanaPayload struct {
	Transaction string `json:"transaction"` // Base64-encoded signed transaction
}

// SolanaPaymentPayload is a wrapper for Solana payment payloads
// that includes the proper structure expected by Solana facilitators
type SolanaPaymentPayload struct {
	X402Version int                 `json:"x402Version"`
	Scheme      string              `json:"scheme"`
	Network     string              `json:"network"`
	Payload     *ExactSolanaPayload `json:"payload"`
}

// ToJSON converts SolanaPaymentPayload to JSON bytes
func (p *SolanaPaymentPayload) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// FromX402PaymentPayload attempts to extract Solana payload from generic x402 payload
// Returns nil if the payload is not a Solana payload
func FromX402PaymentPayload(p *x402types.PaymentPayload) *SolanaPaymentPayload {
	// This is a compatibility helper - in practice, we should create SolanaPaymentPayload directly
	return nil
}
