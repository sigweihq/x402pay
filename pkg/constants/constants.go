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
	MaxRetries                = 10               // maximum number of retries for RPC calls
	MaxResponseBodySize       = 10 * 1024 * 1024 // maximum response body size in bytes (10MB)
)

const (
	USDCDecimals = 6
)

// Network Types
const (
	NetworkBase          = "base"
	NetworkBaseSepolia   = "base-sepolia"
	NetworkAvalanche     = "avalance"
	NetworkAvalancheFuji = "avalance-fuji"
	NetworkXDC           = "xdc"
	NetworkIoTeX         = "iotex"
	NetworkSei           = "sei"
	NetworkSeiTestnet    = "sei-testnet"
	NetworkPolygon       = "polygon"
	NetworkPolygonAmoy   = "polygon-amoy"
	NetworkPeaq          = "peaq"
	NetworkSolana        = "solana"
	NetworkSolanaDevnet  = "solana-devnet"
)

const (
	USDCAddressBase          = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	USDCAddressBaseSepolia   = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	USDCAddressAvalanche     = "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"
	USDCAddressAvalancheFuji = "0x5425890298aed601595a70AB815c96711a31Bc65"
	USDCAddressXDC           = "0xfA2958CB79b0491CC627c1557F441eF849Ca8eb1"
	USDCAddressIoTeX         = "0xcdf79194c6c285077a58da47641d4dbe51f63542"
	USDCAddressSei           = "0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392"
	USDCAddressSeiTestnet    = "0x4fCF1784B31630811181f670Aea7A7bEF803eaED"
	USDCAddressPolygon       = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"
	USDCAddressPolygonAmoy   = "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582"
	USDCAddressPeaq          = "0xBBA60da06C2c5424f03f7434542280FCAd453d10"
	USDCAddressSolana        = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	USDCAddressSolanaDevnet  = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
)

var NetworkToUSDCAddress = map[string]string{
	NetworkBase:          USDCAddressBase,
	NetworkBaseSepolia:   USDCAddressBaseSepolia,
	NetworkAvalanche:     USDCAddressAvalanche,
	NetworkAvalancheFuji: USDCAddressAvalancheFuji,
	NetworkXDC:           USDCAddressXDC,
	NetworkIoTeX:         USDCAddressIoTeX,
	NetworkSei:           USDCAddressSei,
	NetworkSeiTestnet:    USDCAddressSeiTestnet,
	NetworkPolygon:       USDCAddressPolygon,
	NetworkPolygonAmoy:   USDCAddressPolygonAmoy,
	NetworkPeaq:          USDCAddressPeaq,
	NetworkSolana:        USDCAddressSolana,
	NetworkSolanaDevnet:  USDCAddressSolanaDevnet,
}

// mapping from network name to numeric chain ID
var NetworkToChainID = map[string]int64{
	NetworkBase:          8453,
	NetworkBaseSepolia:   84532,
	NetworkAvalanche:     43114,
	NetworkAvalancheFuji: 43113,
	NetworkXDC:           50,
	NetworkIoTeX:         4689,
	NetworkSei:           1329,
	NetworkSeiTestnet:    1328,
	NetworkPolygon:       80001,
	NetworkPolygonAmoy:   80002,
	NetworkPeaq:          3338,
}

var USDCName = map[string]string{
	NetworkBase:          "USD Coin",
	NetworkBaseSepolia:   "USDC",
	NetworkAvalanche:     "USD Coin",
	NetworkAvalancheFuji: "USD Coin",
	NetworkXDC:           "USDC",
	NetworkIoTeX:         "", // TODO: add USDC name for IoTeX
	NetworkSei:           "USDC",
	NetworkSeiTestnet:    "USDC",
	NetworkPolygon:       "USD Coin",
	NetworkPolygonAmoy:   "USDC",
	NetworkPeaq:          "USDC",
}

var OfficialRPCEndpoints = map[string][]string{
	NetworkBase:         {"https://mainnet.base.org"},
	NetworkBaseSepolia:  {"https://sepolia.base.org"},
	NetworkSolana:       {"https://api.mainnet-beta.solana.com"},
	NetworkSolanaDevnet: {"https://api.devnet.solana.com"},
}
