package types

// SupportedResponse represents the supported networks and payment schemes
// Matches x402 protocol specification
type SupportedResponse struct {
	Kinds []NetworkKind `json:"kinds"`
}

// NetworkKind contains information about a supported scheme/network combination
type NetworkKind struct {
	Scheme  string `json:"scheme"`  // Payment scheme (e.g., "exact")
	Network string `json:"network"` // Network name (e.g., "base", "base-sepolia")
}
