package hubclient_test

import (
	"fmt"
	"log"

	"github.com/coinbase/x402/go/pkg/types"
	"github.com/sigweihq/x402pay/pkg/hubclient"
	x402paytypes "github.com/sigweihq/x402pay/pkg/types"
)

// Example_fullWorkflow demonstrates a complete workflow using HubClient
// including authentication and transaction history retrieval
func Example_fullWorkflow() {
	// 1. Create a new hub client
	client := hubclient.NewHubClient(&types.FacilitatorConfig{
		URL: "https://hub.sigwei.com",
	})

	walletAddress := "0x1234567890123456789012345678901234567890"

	// 2. Get authentication message
	msgResp, err := client.Auth.GetAuthMessage(walletAddress)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Message to sign: %s\n", msgResp.Message)

	// 3. User signs the message (this would be done with wallet software)
	signature := "0x..." // Signature from wallet

	// 4. Login with signed message
	authResp, err := client.Auth.Login(msgResp.Message, signature)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Logged in as: %s\n", authResp.User.WalletAddress)

	// 5. Get transaction history
	history, err := client.History.GetHistory(&x402paytypes.HistoryParams{
		Network: "base",
		Limit:   50,
		Offset:  0,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found %d transactions (total: %d)\n", len(history.Transactions), history.Total)

	// 6. Access standard x402 protocol endpoints
	// These work without authentication
	supported, err := client.Supported()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Supported networks: %d\n", len(supported.Kinds))
}

// Example_authenticationFlow demonstrates the authentication workflow
func Example_authenticationFlow() {
	client := hubclient.NewHubClient(nil) // Uses default URL

	// Step 1: Get authentication message
	walletAddress := "0x1234567890123456789012345678901234567890"
	msg, err := client.Auth.GetAuthMessage(walletAddress)
	if err != nil {
		log.Fatal(err)
	}

	// Step 2: Sign the message (user does this with their wallet)
	signature := "0xabc123..." // From wallet

	// Step 3: Login
	auth, err := client.Auth.Login(msg.Message, signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Access Token: %s\n", auth.AccessToken)
	// Tokens are automatically stored in client.Auth

	// Step 4: Check if authenticated
	if client.Auth.IsAuthenticated() {
		fmt.Println("User is authenticated")
	}

	// Step 5: Get current user info
	user, err := client.Auth.GetMe()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Current user: %s\n", user.WalletAddress)

	// Step 6: Refresh token when needed
	newTokens, err := client.Auth.RefreshToken()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("New access token: %s\n", newTokens.AccessToken)

	// Step 7: Logout
	if err := client.Auth.Logout(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Logged out successfully")
}

// Example_historyQuery demonstrates querying transaction history
func Example_historyQuery() {
	client := hubclient.NewHubClient(nil)

	// Assume user is already authenticated
	client.Auth.SetTokens("access-token", "refresh-token")

	// Query with filters
	history, err := client.History.GetHistory(&x402paytypes.HistoryParams{
		Network: "base",      // Filter by network
		Limit:   20,          // Max 100
		Offset:  0,           // For pagination
	})
	if err != nil {
		log.Fatal(err)
	}

	// Process transactions
	for _, tx := range history.Transactions {
		fmt.Printf("Transaction %d: %s (%s)\n", tx.ID, tx.Status, tx.Network)
		if tx.TransactionHash != nil {
			fmt.Printf("  Hash: %s\n", *tx.TransactionHash)
		}
		fmt.Printf("  Amount: %s wei\n", tx.Amount)
		fmt.Printf("  Signer: %s\n", tx.SignerAddress)

		// Access x402 specific data
		if tx.X402Data != nil && tx.X402Data.PaymentRequirementsJson != nil {
			fmt.Printf("  Payment Requirements: %s\n", *tx.X402Data.PaymentRequirementsJson)
		}
	}

	// Pagination
	nextPage, err := client.History.GetHistory(&x402paytypes.HistoryParams{
		Network: "base",
		Limit:   20,
		Offset:  history.Offset + history.Limit, // Next page
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Next page has %d transactions\n", len(nextPage.Transactions))
}

// Example_autoRefresh demonstrates automatic token refresh
func Example_autoRefresh() {
	client := hubclient.NewHubClient(nil)

	// Set tokens (assume from previous login)
	client.Auth.SetTokens("expired-access-token", "valid-refresh-token")

	// GetHistoryWithAutoRefresh will automatically refresh the token if it's expired
	history, err := client.History.GetHistoryWithAutoRefresh(&x402paytypes.HistoryParams{
		Limit:  50,
		Offset: 0,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Retrieved %d transactions (token auto-refreshed if needed)\n", len(history.Transactions))
}

// Example_protocolEndpoints demonstrates using standard x402 protocol endpoints
func Example_protocolEndpoints() {
	client := hubclient.NewHubClient(nil)

	// These methods come from the embedded FacilitatorClient
	// They work without authentication

	// 1. Check supported networks
	supported, err := client.Supported()
	if err != nil {
		log.Fatal(err)
	}
	for _, kind := range supported.Kinds {
		fmt.Printf("Supported: %s on %s\n", kind.Scheme, kind.Network)
	}

	// 2. Verify a payment (example)
	// verifyResp, err := client.Verify(payload, requirements)

	// 3. Settle a payment with hub-specific options
	// settleResp, err := client.SettleWithOptions(payload, requirements, true, false)

	// 4. Transfer (hub-specific convenience method)
	// transferResp, err := client.Transfer(exactEvmPayload, "base", "0xAssetAddress", true)
}

// Example_errorHandling demonstrates proper error handling
func Example_errorHandling() {
	client := hubclient.NewHubClient(nil)

	// Handle authentication errors
	_, err := client.Auth.Login("invalid message", "invalid signature")
	if err != nil {
		// Check if it's an HTTP error
		if httpErr, ok := err.(*hubclient.HTTPError); ok {
			fmt.Printf("HTTP %d: %s\n", httpErr.StatusCode, httpErr.Error())
			if httpErr.IsUnauthorized() {
				fmt.Println("Authentication failed - invalid signature")
			}
		}
	}

	// Handle history errors
	client.Auth.SetTokens("expired-token", "refresh-token")
	_, err = client.History.GetHistory(&x402paytypes.HistoryParams{
		Limit:  50,
		Offset: 0,
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		// Hint: Use GetHistoryWithAutoRefresh to automatically handle expired tokens
	}
}
