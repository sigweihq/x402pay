package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/sigweihq/x402pay/pkg/chains/svm"
	"github.com/sigweihq/x402pay/pkg/constants"
	"github.com/sigweihq/x402pay/pkg/processor"
	"github.com/sigweihq/x402pay/pkg/utils"
	"github.com/stretchr/testify/suite"
)

// RealTransferSolanaE2ETestSuite tests real USDC transfers on Solana using the bare SDK
type RealTransferSolanaE2ETestSuite struct {
	suite.Suite
	senderPrivateKeyHex string
	senderAddress       string
	solanaRPC           string
	usdcMintAddress     string
	facilitatorFeePayer string
	logger              *slog.Logger
	httpClient          *http.Client
	facilitatorURLs     []string
}

// SetupSuite initializes the test suite
func (suite *RealTransferSolanaE2ETestSuite) SetupSuite() {
	// Setup logger
	suite.logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Setup HTTP client
	suite.httpClient = &http.Client{
		Timeout: constants.FacilitatorTimeout,
	}

	// Check for private key
	suite.senderPrivateKeyHex = os.Getenv("E2E_SENDER_PRIVATE_KEY_SVM")
	if suite.senderPrivateKeyHex == "" {
		suite.T().Skip("E2E_SENDER_PRIVATE_KEY_SVM not set, skipping real Solana blockchain E2E tests")
	}

	// Check for facilitator configuration
	facilitatorURLs := os.Getenv("X402_FACILITATOR_URLS")
	cdpAPIKeyID := os.Getenv("CDP_API_KEY_ID")
	cdpAPIKeySecret := os.Getenv("CDP_API_KEY_SECRET")

	if facilitatorURLs == "" && (cdpAPIKeyID == "" || cdpAPIKeySecret == "") {
		suite.T().Skip("Neither X402_FACILITATOR_URLS nor CDP credentials (CDP_API_KEY_ID, CDP_API_KEY_SECRET) set, skipping E2E tests")
	}

	if facilitatorURLs != "" {
		suite.facilitatorURLs = strings.Split(facilitatorURLs, ",")
	}

	suite.solanaRPC = "https://api.devnet.solana.com"

	// Derive sender address
	address, err := utils.DeriveSolanaAddress(suite.senderPrivateKeyHex)
	suite.Require().NoError(err, "Failed to derive sender address")
	suite.senderAddress = address

	// Solana Devnet USDC mint address
	suite.usdcMintAddress = constants.NetworkToUSDCAddress[constants.NetworkSolanaDevnet]

	suite.T().Logf("Sender account: %s", suite.senderAddress)

	// Check sender USDC balance
	balance, err := suite.getUSDCBalance(suite.senderAddress)
	suite.Require().NoError(err, "Failed to get sender balance")

	minRequiredBalance := uint64(500000) // 0.5 USDC (6 decimals)
	if balance < minRequiredBalance {
		suite.T().Skipf("Insufficient sender balance: has %d USDC base units, needs at least %d",
			balance, minRequiredBalance)
	}

	suite.T().Logf("Sender USDC balance: %d base units (%.6f USDC)",
		balance, float64(balance)/1000000.0)

	// Fetch facilitator fee payer address from /supported endpoint
	if len(suite.facilitatorURLs) > 0 {
		suite.T().Log("Fetching facilitator fee payer from /supported endpoint...")
		facilitatorFeePayer, err := suite.getFacilitatorFeePayer(suite.facilitatorURLs[0])
		suite.Require().NoError(err, "Failed to fetch facilitator fee payer")
		suite.facilitatorFeePayer = facilitatorFeePayer
		suite.T().Logf("Facilitator fee payer: %s", suite.facilitatorFeePayer)
	} else {
		suite.T().Skip("No facilitator URLs configured for Solana")
	}

	// Initialize SVM chain registry
	err = svm.InitSVMChainsWithEndpoints(suite.logger, map[string][]string{
		constants.NetworkSolanaDevnet: {suite.solanaRPC},
	})
	suite.Require().NoError(err, "Failed to initialize SVM chains")

	// Initialize processor map
	var facilitatorURLsList []string
	if facilitatorURLs != "" {
		facilitatorURLsList = strings.Split(facilitatorURLs, ",")
	}

	processorConfig := &processor.ProcessorConfig{
		FacilitatorURLs: facilitatorURLsList,
	}
	processor.InitProcessorMap(processorConfig, suite.logger)

	suite.T().Log("SDK initialized successfully")
}

// getFacilitatorFeePayer fetches the fee payer address from the facilitator's /supported endpoint
func (suite *RealTransferSolanaE2ETestSuite) getFacilitatorFeePayer(facilitatorURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query /supported endpoint
	supportedURL := fmt.Sprintf("%s/supported", facilitatorURL)
	req, err := http.NewRequestWithContext(ctx, "GET", supportedURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := suite.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch supported info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var supportedResp struct {
		Kinds []struct {
			Network string `json:"network"`
			Extra   struct {
				FeePayer string `json:"feePayer"`
			} `json:"extra"`
		} `json:"kinds"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&supportedResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	// Find the entry for solana-devnet
	for _, kind := range supportedResp.Kinds {
		if kind.Network == constants.NetworkSolanaDevnet {
			if kind.Extra.FeePayer == "" {
				return "", fmt.Errorf("feePayer is empty for %s", constants.NetworkSolanaDevnet)
			}
			return kind.Extra.FeePayer, nil
		}
	}

	return "", fmt.Errorf("network %s not found in supported kinds", constants.NetworkSolanaDevnet)
}

// getUSDCBalance retrieves USDC balance for an SPL token account
func (suite *RealTransferSolanaE2ETestSuite) getUSDCBalance(ownerAddress string) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Convert owner address to public key
	ownerPubkey, err := solana.PublicKeyFromBase58(ownerAddress)
	if err != nil {
		return 0, fmt.Errorf("invalid owner address: %w", err)
	}

	mintPubkey, err := solana.PublicKeyFromBase58(suite.usdcMintAddress)
	if err != nil {
		return 0, fmt.Errorf("invalid mint address: %w", err)
	}

	// Call getTokenAccountsByOwner RPC method
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getTokenAccountsByOwner",
		"params": []interface{}{
			ownerPubkey.String(),
			map[string]string{
				"mint": mintPubkey.String(),
			},
			map[string]interface{}{
				"encoding": "jsonParsed",
			},
		},
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", suite.solanaRPC, bytes.NewReader(reqBytes))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := suite.httpClient.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp struct {
		Result struct {
			Value []struct {
				Account struct {
					Data struct {
						Parsed struct {
							Info struct {
								TokenAmount struct {
									Amount         string  `json:"amount"`
									Decimals       int     `json:"decimals"`
									UIAmount       float64 `json:"uiAmount"`
									UIAmountString string  `json:"uiAmountString"`
								} `json:"tokenAmount"`
							} `json:"info"`
						} `json:"parsed"`
					} `json:"data"`
				} `json:"account"`
			} `json:"value"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return 0, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return 0, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	// If no token accounts found, balance is 0
	if len(rpcResp.Result.Value) == 0 {
		return 0, nil
	}

	// Get balance from first token account
	var balance uint64
	fmt.Sscanf(rpcResp.Result.Value[0].Account.Data.Parsed.Info.TokenAmount.Amount, "%d", &balance)

	return balance, nil
}

// TestRealUSDCTransferWithSDKSolana tests complete USDC transfer on Solana using the bare SDK
func (suite *RealTransferSolanaE2ETestSuite) TestRealUSDCTransferWithSDKSolana() {
	suite.Run("Complete USDC transfer with SDK on Solana (A->B->A)", func() {
		suite.T().Log("Starting real Solana USDC transfer test with bare SDK...")

		// Generate receiver account
		receiverPrivateKeyHex, receiverAddress, err := utils.GenerateSolanaKeypair()
		suite.Require().NoError(err)
		suite.T().Logf("Generated receiver: %s", receiverAddress)

		// Check initial balances
		initialSenderBalance, err := suite.getUSDCBalance(suite.senderAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Initial sender balance: %d USDC base units (%.6f USDC)",
			initialSenderBalance, float64(initialSenderBalance)/1000000.0)

		initialReceiverBalance, err := suite.getUSDCBalance(receiverAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Initial receiver balance: %d USDC base units (%.6f USDC)",
			initialReceiverBalance, float64(initialReceiverBalance)/1000000.0)

		// Transfer amount: 0.0003 USDC
		transferAmount := uint64(300) // 300 USDC base units

		// STEP 1: Transfer from sender to receiver
		// First, ensure the receiver's token account exists
		suite.T().Log("Ensuring receiver's token account exists...")
		err = utils.EnsureSolanaTokenAccount(
			suite.solanaRPC,
			suite.senderPrivateKeyHex, // Sender pays for ATA creation
			receiverAddress,
			suite.usdcMintAddress,
		)
		suite.Require().NoError(err, "Failed to ensure receiver token account")

		// Wait a bit for account creation to finalize
		time.Sleep(2 * time.Second)

		suite.T().Log("Creating payment payload for sender -> receiver transfer...")

		paymentPayload1, senderAddress, err := utils.CreateSolanaPaymentPayload(
			suite.solanaRPC,
			suite.senderPrivateKeyHex,
			receiverAddress,
			constants.NetworkSolanaDevnet,
			suite.usdcMintAddress,
			transferAmount,
			suite.facilitatorFeePayer,
		)
		suite.Require().NoError(err)
		suite.Require().NotNil(paymentPayload1)
		suite.Require().Equal(suite.senderAddress, senderAddress, "Derived sender address should match")

		paymentRequirements1, err := utils.DerivePaymentRequirementsSolana(
			constants.NetworkSolanaDevnet,
			receiverAddress,
			transferAmount,
			"https://test.example.com/resource",
			suite.usdcMintAddress,
			senderAddress, // fee payer
		)
		suite.Require().NoError(err)
		suite.Require().NotNil(paymentRequirements1)

		suite.T().Log("Processing payment (sender -> receiver) with confirm=true...")
		settleResponse1, err := processor.ProcessPayment(paymentPayload1, paymentRequirements1, true)
		suite.Require().NoError(err)
		suite.Require().NotNil(settleResponse1)
		suite.Require().True(settleResponse1.Success, "Transfer should succeed")
		suite.Require().NotEmpty(settleResponse1.Transaction, "Transaction signature should not be empty")

		suite.T().Logf("Transfer successful! Transaction signature: %s", settleResponse1.Transaction)

		// Check balances after first transfer
		senderBalanceAfter1, err := suite.getUSDCBalance(suite.senderAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Sender balance after transfer 1: %d USDC base units (%.6f USDC)",
			senderBalanceAfter1, float64(senderBalanceAfter1)/1000000.0)

		receiverBalanceAfter1, err := suite.getUSDCBalance(receiverAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Receiver balance after transfer 1: %d USDC base units (%.6f USDC)",
			receiverBalanceAfter1, float64(receiverBalanceAfter1)/1000000.0)

		// Verify sender balance decreased
		expectedSenderBalance := initialSenderBalance - transferAmount
		suite.Equal(expectedSenderBalance, senderBalanceAfter1,
			"Sender balance should decrease by transfer amount")

		// Verify receiver balance increased
		expectedReceiverBalance := initialReceiverBalance + transferAmount
		suite.Equal(expectedReceiverBalance, receiverBalanceAfter1,
			"Receiver balance should increase by transfer amount")

		suite.T().Log("✅ First transfer verified successfully!")

		// STEP 2: Return transfer from receiver back to sender
		suite.T().Log("Creating payment payload for receiver -> sender transfer...")

		paymentPayload2, receiverAddressConfirm, err := utils.CreateSolanaPaymentPayload(
			suite.solanaRPC,
			receiverPrivateKeyHex,
			suite.senderAddress,
			constants.NetworkSolanaDevnet,
			suite.usdcMintAddress,
			transferAmount,
			suite.facilitatorFeePayer,
		)
		suite.Require().NoError(err)
		suite.Require().NotNil(paymentPayload2)
		suite.Require().Equal(receiverAddress, receiverAddressConfirm, "Derived receiver address should match")

		paymentRequirements2, err := utils.DerivePaymentRequirementsSolana(
			constants.NetworkSolanaDevnet,
			suite.senderAddress,
			transferAmount,
			"https://test.example.com/resource",
			suite.usdcMintAddress,
			receiverAddress, // fee payer
		)
		suite.Require().NoError(err)
		suite.Require().NotNil(paymentRequirements2)

		suite.T().Log("Processing return payment (receiver -> sender) with confirm=true...")
		settleResponse2, err := processor.ProcessPayment(paymentPayload2, paymentRequirements2, true)
		suite.Require().NoError(err)
		suite.Require().NotNil(settleResponse2)
		suite.Require().True(settleResponse2.Success, "Return transfer should succeed")
		suite.Require().NotEmpty(settleResponse2.Transaction, "Transaction signature should not be empty")

		suite.T().Logf("Return transfer successful! Transaction signature: %s", settleResponse2.Transaction)

		// Check final balances
		finalSenderBalance, err := suite.getUSDCBalance(suite.senderAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Final sender balance: %d USDC base units (%.6f USDC)",
			finalSenderBalance, float64(finalSenderBalance)/1000000.0)

		finalReceiverBalance, err := suite.getUSDCBalance(receiverAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Final receiver balance: %d USDC base units (%.6f USDC)",
			finalReceiverBalance, float64(finalReceiverBalance)/1000000.0)

		// Verify sender balance is back to initial
		suite.Equal(initialSenderBalance, finalSenderBalance,
			"Sender balance should be back to initial amount")

		// Verify receiver balance is back to initial
		suite.Equal(initialReceiverBalance, finalReceiverBalance,
			"Receiver balance should be back to initial amount")

		suite.T().Log("✅ Return transfer verified successfully!")
		suite.T().Log("✅ Complete round-trip transfer test passed!")
	})
}

// TestRealTransferSolanaE2E is the test runner
func TestRealTransferSolanaE2E(t *testing.T) {
	suite.Run(t, new(RealTransferSolanaE2ETestSuite))
}
