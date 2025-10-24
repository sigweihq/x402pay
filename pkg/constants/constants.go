package constants

import "time"

const (
	DelayBetweenRPCCalls      = 200              // delay in milliseconds between RPC calls
	TransactionReceiptTimeout = 2 * time.Second  // timeout for transaction receipt
	CallContractTimeout       = 10 * time.Second // timeout for contract call
	FacilitatorTimeout        = 30 * time.Second // timeout for facilitator
	TLSHandshakeTimeout       = 10 * time.Second // timeout for TLS handshake
	ResponseHeaderTimeout     = 20 * time.Second // timeout for response header
	ExpectContinueTimeout     = 1 * time.Second  // timeout for expect continue
)

const (
	USDCDecimals = 6
)

// Network Types
const (
	NetworkBase         = "base"
	NetworkBaseSepolia  = "base-sepolia"
	NetworkSolana       = "solana"
	NetworkSolanaDevnet = "solana-devnet"
)

const (
	USDCAddressBase        = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	USDCAddressBaseSepolia = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
)

var NetworkToUSDCAddress = map[string]string{
	NetworkBase:        USDCAddressBase,
	NetworkBaseSepolia: USDCAddressBaseSepolia,
}

// mapping from network name to CAIP-2 chain ID
var NetworkToCAIP2ChainID = map[string]string{
	NetworkBase:        "eip155:8453",
	NetworkBaseSepolia: "eip155:84532",
}

// mapping from network name to numeric chain ID
var NetworkToChainID = map[string]int64{
	NetworkBase:        8453,
	NetworkBaseSepolia: 84532,
}

var USDCName = map[string]string{
	USDCAddressBase:        "USD Coin",
	USDCAddressBaseSepolia: "USDC",
}

var OfficialRPCEndpoints = map[string][]string{
	NetworkBase:        {"https://mainnet.base.org", "https://base.llamarpc.com"},
	NetworkBaseSepolia: {"https://sepolia.base.org"},
}
