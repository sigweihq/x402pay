# HubClient Package

The `hubclient` package provides a Go client for interacting with the x402-hub service. It supports both standard x402 protocol endpoints and hub-specific features like wallet authentication and transaction history.

## Architecture

The `HubClient` is designed with clean separation of concerns:

```
HubClient
├─ FacilitatorClient (embedded)  → Standard x402 protocol
│  ├─ Verify()
│  └─ Settle()
├─ Auth                          → Wallet authentication
│  ├─ GetAuthMessage()
│  ├─ Login()
│  ├─ RefreshToken()
│  ├─ GetMe()
│  └─ Logout()
└─ History                       → Transaction history
   ├─ GetHistory()
   └─ GetHistoryWithAutoRefresh()
```

### Hub-Specific Extensions

In addition to standard x402 endpoints, HubClient adds:
- **SettleWithOptions()** - Enhanced settle with `confirm` and `useDbId` parameters
- **Transfer()** - Convenient endpoint for EVM transfers
- **Supported()** - Query supported networks and schemes

## Installation

```bash
go get github.com/sigweihq/x402pay
```

## Quick Start

```go
import (
    "github.com/sigweihq/x402pay/pkg/hubclient"
    x402paytypes "github.com/sigweihq/x402pay/pkg/types"
)

// Create client
client := hubclient.NewHubClient(nil) // Uses default hub URL

// 1. Get authentication message
msg, _ := client.Auth.GetAuthMessage("0xYourWalletAddress")

// 2. Sign message with wallet (user does this)
signature := signWithWallet(msg.Message)

// 3. Login
auth, _ := client.Auth.Login(msg.Message, signature)
// Tokens are now stored in client.Auth

// 4. Get transaction history
history, _ := client.History.GetHistory(&x402paytypes.HistoryParams{
    Network: "base",
    Limit:   50,
})
```

## Authentication Flow

### 1. Get Auth Message

```go
msg, err := client.Auth.GetAuthMessage("0x1234...")
if err != nil {
    log.Fatal(err)
}
// msg.Message = "Sign this message to authenticate with x402-hub.\n\nNonce: abc123\nTimestamp: 1234567890"
```

### 2. Login

```go
// User signs the message with their wallet
signature := "0x..." // From wallet software

auth, err := client.Auth.Login(msg.Message, signature)
if err != nil {
    log.Fatal(err)
}

// Tokens are automatically stored
fmt.Println("Access Token:", auth.AccessToken)
fmt.Println("User:", auth.User.WalletAddress)
```

### 3. Check Authentication Status

```go
if client.Auth.IsAuthenticated() {
    fmt.Println("User is authenticated")
}
```

### 4. Get Current User

```go
user, err := client.Auth.GetMe()
if err != nil {
    log.Fatal(err)
}
fmt.Println("Current user:", user.WalletAddress)
```

### 5. Refresh Token

```go
// When access token expires
newTokens, err := client.Auth.RefreshToken()
if err != nil {
    log.Fatal(err)
}
```

### 6. Logout

```go
if err := client.Auth.Logout(); err != nil {
    log.Fatal(err)
}
// Tokens are cleared
```

## Transaction History

### Basic Query

```go
history, err := client.History.GetHistory(&x402paytypes.HistoryParams{
    Network: "base",    // Optional: filter by network
    Limit:   50,        // 1-100, defaults to 50
    Offset:  0,         // For pagination
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Total: %d, Returned: %d\n", history.Total, len(history.Transactions))

for _, tx := range history.Transactions {
    fmt.Printf("Transaction %d: %s (%s)\n", tx.ID, tx.Status, tx.Network)
    if tx.TransactionHash != nil {
        fmt.Printf("  Hash: %s\n", *tx.TransactionHash)
    }
    fmt.Printf("  Amount: %s wei\n", tx.Amount)
}
```

### Auto-Refresh

Use `GetHistoryWithAutoRefresh()` to automatically refresh expired tokens:

```go
history, err := client.History.GetHistoryWithAutoRefresh(&x402paytypes.HistoryParams{
    Limit: 50,
})
// If token is expired, it will automatically refresh and retry
```

### Pagination

```go
// Page 1
page1, _ := client.History.GetHistory(&x402paytypes.HistoryParams{
    Limit:  20,
    Offset: 0,
})

// Page 2
page2, _ := client.History.GetHistory(&x402paytypes.HistoryParams{
    Limit:  20,
    Offset: 20,
})
```

## Standard x402 Protocol

### Check Supported Networks

```go
supported, err := client.Supported()
if err != nil {
    log.Fatal(err)
}

for _, kind := range supported.Kinds {
    fmt.Printf("%s on %s\n", kind.Scheme, kind.Network)
}
```

### Verify Payment

```go
resp, err := client.Verify(paymentPayload, paymentRequirements)
if err != nil {
    log.Fatal(err)
}

if resp.IsValid {
    fmt.Println("Payment is valid")
} else {
    fmt.Println("Invalid:", resp.InvalidReason)
}
```

### Settle Payment (Standard)

```go
// Standard settle (from FacilitatorClient)
resp, err := client.Settle(paymentPayload, paymentRequirements)

// Hub-enhanced settle with options
resp, err := client.SettleWithOptions(
    paymentPayload,
    paymentRequirements,
    true,  // confirm: enable on-chain verification
    false, // useDbId: return DB ID instead of tx hash
)
```

### Transfer (Hub-Specific)

```go
resp, err := client.Transfer(
    exactEvmPayload,
    "base",                                    // network
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC contract
    true,                                      // confirm
)
```

## Configuration

### Default Configuration

```go
// Uses default hub URL: https://hub.sigwei.com
client := hubclient.NewHubClient(nil)
```

### Custom Configuration

```go
import (
    "time"
    "github.com/coinbase/x402/go/pkg/types"
)

config := &types.FacilitatorConfig{
    URL: "https://custom-hub.example.com",
    Timeout: func() time.Duration {
        return 30 * time.Second
    },
}

client := hubclient.NewHubClient(config)
```

### Manual Token Management

```go
// Set tokens manually (e.g., from storage)
client.Auth.SetTokens("access-token", "refresh-token")

// Get tokens (e.g., to persist)
accessToken := client.Auth.GetAccessToken()
refreshToken := client.Auth.GetRefreshToken()

// Clear tokens
client.Auth.ClearTokens()
```

## Error Handling

### HTTP Errors

```go
_, err := client.Auth.Login("invalid", "invalid")
if err != nil {
    if httpErr, ok := err.(*hubclient.HTTPError); ok {
        fmt.Printf("HTTP %d: %s\n", httpErr.StatusCode, httpErr.Error())

        if httpErr.IsUnauthorized() {
            fmt.Println("Authentication failed")
        }
    }
}
```

### Common Errors

- **401 Unauthorized**: Invalid credentials or expired token
  - Solution: Refresh token or re-authenticate
- **403 Forbidden**: Insufficient permissions
- **400 Bad Request**: Invalid parameters
- **500 Internal Server Error**: Server error

## Type Reference

### Auth Types

```go
type MessageResponse struct {
    Message string `json:"message"`
}

type AuthResponse struct {
    User         *User  `json:"user"`
    AccessToken  string `json:"accessToken"`
    RefreshToken string `json:"refreshToken"`
}

type User struct {
    ID            uint64 `json:"id"`
    WalletAddress string `json:"walletAddress"`
    CreatedAt     string `json:"createdAt"`
    UpdatedAt     string `json:"updatedAt"`
}

type TokenPair struct {
    AccessToken  string `json:"accessToken"`
    RefreshToken string `json:"refreshToken"`
}
```

### History Types

```go
type HistoryParams struct {
    Network string `json:"network,omitempty"` // Optional filter
    Limit   int    `json:"limit"`             // 1-100
    Offset  int    `json:"offset"`            // For pagination
}

type HistoryResponse struct {
    Transactions []*TransactionHistoryItem `json:"transactions"`
    Total        int                       `json:"total"`
    Limit        int                       `json:"limit"`
    Offset       int                       `json:"offset"`
}

type TransactionHistoryItem struct {
    ID              int64     `json:"id"`
    CreatedAt       time.Time `json:"createdAt"`
    UpdatedAt       time.Time `json:"updatedAt"`
    SignerAddress   string    `json:"signerAddress"`
    Amount          string    `json:"amount"` // Wei units
    Network         string    `json:"network"`
    TransactionHash *string   `json:"transactionHash,omitempty"`
    Status          string    `json:"status"`
    Error           *string   `json:"error,omitempty"`
    X402Data        *X402DataHistory `json:"x402Data,omitempty"`
}
```

## Thread Safety

- **Auth token management** is thread-safe (uses `sync.RWMutex`)
- **HTTP client** is thread-safe (from `net/http`)
- Multiple goroutines can safely share a single `HubClient` instance

## Best Practices

1. **Reuse client instances** - Create once, use throughout your application
2. **Handle token refresh** - Use `GetHistoryWithAutoRefresh()` or implement refresh logic
3. **Store tokens securely** - Persist tokens in secure storage between sessions
4. **Validate parameters** - Check limits and offsets before making requests
5. **Handle errors properly** - Check for `HTTPError` type for detailed error info

## Examples

See [example_test.go](./example_test.go) for comprehensive examples including:
- Full authentication workflow
- Transaction history queries
- Error handling
- Token refresh
- Protocol endpoints

## Related Packages

- **x402pay/pkg/types** - Shared types for auth, history, and protocol
- **x402/go/pkg/types** - Standard x402 protocol types
- **x402/go/pkg/facilitatorclient** - Base facilitator client

## License

See the main x402pay repository for license information.
