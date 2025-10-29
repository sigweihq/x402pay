package processor

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sigweihq/x402pay/pkg/chains/evm"
	"github.com/sigweihq/x402pay/pkg/constants"
	"github.com/sigweihq/x402pay/pkg/processor"
	"github.com/sigweihq/x402pay/pkg/utils"
	"github.com/stretchr/testify/suite"
)

// RealTransferE2ETestSuite tests real USDC transfers using the bare SDK
type RealTransferE2ETestSuite struct {
	suite.Suite
	senderPrivateKey *ecdsa.PrivateKey
	senderAddress    string
	ethClient        *ethclient.Client
	usdcContractAddr common.Address
	baseSepoliaRPC   string
	logger           *slog.Logger
}

// SetupSuite initializes the test suite
func (suite *RealTransferE2ETestSuite) SetupSuite() {
	// Setup logger
	suite.logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Check for private key
	senderPrivateKeyHex := os.Getenv("E2E_SENDER_PRIVATE_KEY")
	if senderPrivateKeyHex == "" {
		suite.T().Skip("E2E_SENDER_PRIVATE_KEY not set, skipping real blockchain E2E tests")
	}

	// Check for facilitator configuration
	facilitatorURLs := os.Getenv("X402_FACILITATOR_URLS")
	cdpAPIKeyID := os.Getenv("CDP_API_KEY_ID")
	cdpAPIKeySecret := os.Getenv("CDP_API_KEY_SECRET")

	if facilitatorURLs == "" && (cdpAPIKeyID == "" || cdpAPIKeySecret == "") {
		suite.T().Skip("Neither X402_FACILITATOR_URLS nor CDP credentials (CDP_API_KEY_ID, CDP_API_KEY_SECRET) set, skipping E2E tests")
	}

	suite.baseSepoliaRPC = "https://sepolia.base.org"

	// Parse private key
	senderPrivateKeyHex = strings.TrimPrefix(senderPrivateKeyHex, "0x")
	privateKeyBytes, err := hex.DecodeString(senderPrivateKeyHex)
	suite.Require().NoError(err, "Failed to decode sender private key")

	suite.senderPrivateKey, err = crypto.ToECDSA(privateKeyBytes)
	suite.Require().NoError(err, "Failed to parse sender private key")

	// Get sender address
	publicKey := suite.senderPrivateKey.Public().(*ecdsa.PublicKey)
	suite.senderAddress = crypto.PubkeyToAddress(*publicKey).Hex()

	// Connect to Ethereum client
	suite.ethClient, err = ethclient.Dial(suite.baseSepoliaRPC)
	suite.Require().NoError(err, "Failed to connect to Base Sepolia")

	// Base Sepolia USDC contract address
	suite.usdcContractAddr = common.HexToAddress(constants.NetworkToUSDCAddress[constants.NetworkBaseSepolia])

	// Check sender balance
	balance, err := suite.getUSDCBalance(suite.senderAddress)
	suite.Require().NoError(err, "Failed to get sender balance")

	minRequiredBalance := big.NewInt(500000) // 0.5 USDC
	if balance.Cmp(minRequiredBalance) < 0 {
		suite.T().Skipf("Insufficient sender balance: has %s USDC wei, needs at least %s",
			balance.String(), minRequiredBalance.String())
	}

	suite.T().Logf("Sender account: %s, Balance: %s USDC wei (%.6f USDC)",
		suite.senderAddress, balance.String(),
		float64(balance.Int64())/1000000.0)

	// Initialize EVM chain registry
	err = evm.InitEVMChainsWithEndpoints(suite.logger, map[string][]string{
		constants.NetworkBaseSepolia: {suite.baseSepoliaRPC},
	})
	suite.Require().NoError(err, "Failed to initialize EVM chains")

	// Initialize processor map
	var facilitatorURLsList []string
	if facilitatorURLs != "" {
		facilitatorURLsList = strings.Split(facilitatorURLs, ",")
	}

	processorConfig := &processor.ProcessorConfig{
		FacilitatorURLs: facilitatorURLsList,
		CDPAPIKeyID:     cdpAPIKeyID,
		CDPAPIKeySecret: cdpAPIKeySecret,
	}
	processor.InitProcessorMap(processorConfig, suite.logger)

	suite.T().Log("SDK initialized successfully")
}

// getUSDCBalance retrieves USDC balance for an address
func (suite *RealTransferE2ETestSuite) getUSDCBalance(address string) (*big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	balanceOfSelector := crypto.Keccak256([]byte("balanceOf(address)"))[:4]
	addressParam := common.LeftPadBytes(common.HexToAddress(address).Bytes(), 32)
	callData := append(balanceOfSelector, addressParam...)

	msg := ethereum.CallMsg{
		To:   &suite.usdcContractAddr,
		Data: callData,
	}

	result, err := suite.ethClient.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to call balanceOf for %s: %w", address, err)
	}

	if len(result) != 32 {
		return nil, fmt.Errorf("unexpected balanceOf result length: %d", len(result))
	}

	return new(big.Int).SetBytes(result), nil
}

// generateSecureNonce generates a cryptographically secure nonce for EIP-3009
func (suite *RealTransferE2ETestSuite) generateSecureNonce() string {
	bytes := make([]byte, 32) // 256 bits
	_, err := rand.Read(bytes)
	suite.Require().NoError(err, "Failed to generate secure random bytes")
	return "0x" + hex.EncodeToString(bytes)
}

// generateTestAccount generates a new test account
func (suite *RealTransferE2ETestSuite) generateTestAccount(label string) (*ecdsa.PrivateKey, string) {
	privateKey, err := crypto.GenerateKey()
	suite.Require().NoError(err, "Failed to generate private key for %s", label)

	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKey).Hex()

	suite.T().Logf("Generated %s: %s", label, address)
	return privateKey, address
}

// TestRealUSDCTransferWithSDK tests complete USDC transfer using the bare SDK
func (suite *RealTransferE2ETestSuite) TestRealUSDCTransferWithSDK() {
	suite.Run("Complete USDC transfer with SDK (A->B->A)", func() {
		suite.T().Log("Starting real USDC transfer test with bare SDK...")

		// Generate receiver account
		receiverPrivateKey, receiverAddress := suite.generateTestAccount("e2e-receiver")

		// Check initial balances
		initialSenderBalance, err := suite.getUSDCBalance(suite.senderAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Initial sender balance: %s USDC wei (%.6f USDC)",
			initialSenderBalance.String(), float64(initialSenderBalance.Int64())/1000000.0)

		initialReceiverBalance, err := suite.getUSDCBalance(receiverAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Initial receiver balance: %s USDC wei (%.6f USDC)",
			initialReceiverBalance.String(), float64(initialReceiverBalance.Int64())/1000000.0)

		// Transfer amount: 0.0003 USDC
		transferAmount := uint64(300) // 300 USDC wei

		// STEP 1: Transfer from sender to receiver
		suite.T().Log("Creating payment payload for sender -> receiver transfer...")

		nonce1 := suite.generateSecureNonce()
		senderPrivateKeyHex := hex.EncodeToString(crypto.FromECDSA(suite.senderPrivateKey))

		paymentPayload1, err := utils.CreatePaymentPayload(
			senderPrivateKeyHex,
			receiverAddress,
			constants.NetworkBaseSepolia,
			suite.usdcContractAddr.Hex(),
			constants.USDCName[constants.NetworkBaseSepolia],
			transferAmount,
			nonce1,
		)
		suite.Require().NoError(err)
		suite.Require().NotNil(paymentPayload1)

		paymentRequirements1, err := utils.DerivePaymentRequirements(
			paymentPayload1,
			"https://test.example.com/resource",
			suite.usdcContractAddr.Hex(),
		)
		suite.Require().NoError(err)
		suite.Require().NotNil(paymentRequirements1)

		suite.T().Log("Processing payment (sender -> receiver) with confirm=true...")
		settleResponse1, err := processor.ProcessPayment(paymentPayload1, paymentRequirements1, true)
		suite.Require().NoError(err)
		suite.Require().NotNil(settleResponse1)
		suite.Require().True(settleResponse1.Success, "Transfer should succeed")
		suite.Require().True(strings.HasPrefix(settleResponse1.Transaction, "0x"), "Transaction hash should start with 0x")

		suite.T().Logf("Transfer successful! Transaction hash: %s", settleResponse1.Transaction)

		// Wait for transaction to be processed
		suite.T().Log("Waiting for transaction to be processed...")
		time.Sleep(5 * time.Second)

		// Check balances after first transfer
		senderBalanceAfter1, err := suite.getUSDCBalance(suite.senderAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Sender balance after transfer 1: %s USDC wei (%.6f USDC)",
			senderBalanceAfter1.String(), float64(senderBalanceAfter1.Int64())/1000000.0)

		receiverBalanceAfter1, err := suite.getUSDCBalance(receiverAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Receiver balance after transfer 1: %s USDC wei (%.6f USDC)",
			receiverBalanceAfter1.String(), float64(receiverBalanceAfter1.Int64())/1000000.0)

		// Verify sender balance decreased
		expectedSenderBalance := new(big.Int).Sub(initialSenderBalance, big.NewInt(int64(transferAmount)))
		suite.Equal(expectedSenderBalance.String(), senderBalanceAfter1.String(),
			"Sender balance should decrease by transfer amount")

		// Verify receiver balance increased
		expectedReceiverBalance := new(big.Int).Add(initialReceiverBalance, big.NewInt(int64(transferAmount)))
		suite.Equal(expectedReceiverBalance.String(), receiverBalanceAfter1.String(),
			"Receiver balance should increase by transfer amount")

		suite.T().Log("✅ First transfer verified successfully!")

		// STEP 2: Return transfer from receiver back to sender
		suite.T().Log("Creating payment payload for receiver -> sender transfer...")

		nonce2 := suite.generateSecureNonce()
		receiverPrivateKeyHex := hex.EncodeToString(crypto.FromECDSA(receiverPrivateKey))

		paymentPayload2, err := utils.CreatePaymentPayload(
			receiverPrivateKeyHex,
			suite.senderAddress,
			constants.NetworkBaseSepolia,
			suite.usdcContractAddr.Hex(),
			constants.USDCName[constants.NetworkBaseSepolia],
			transferAmount,
			nonce2,
		)
		suite.Require().NoError(err)
		suite.Require().NotNil(paymentPayload2)

		paymentRequirements2, err := utils.DerivePaymentRequirements(
			paymentPayload2,
			"https://test.example.com/resource",
			suite.usdcContractAddr.Hex(),
		)
		suite.Require().NoError(err)
		suite.Require().NotNil(paymentRequirements2)

		suite.T().Log("Processing return payment (receiver -> sender) with confirm=true...")
		settleResponse2, err := processor.ProcessPayment(paymentPayload2, paymentRequirements2, true)
		suite.Require().NoError(err)
		suite.Require().NotNil(settleResponse2)
		suite.Require().True(settleResponse2.Success, "Return transfer should succeed")
		suite.Require().True(strings.HasPrefix(settleResponse2.Transaction, "0x"), "Transaction hash should start with 0x")

		suite.T().Logf("Return transfer successful! Transaction hash: %s", settleResponse2.Transaction)

		// Wait for transaction to be processed
		suite.T().Log("Waiting for return transaction to be processed...")
		time.Sleep(5 * time.Second)

		// Check final balances
		finalSenderBalance, err := suite.getUSDCBalance(suite.senderAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Final sender balance: %s USDC wei (%.6f USDC)",
			finalSenderBalance.String(), float64(finalSenderBalance.Int64())/1000000.0)

		finalReceiverBalance, err := suite.getUSDCBalance(receiverAddress)
		suite.Require().NoError(err)
		suite.T().Logf("Final receiver balance: %s USDC wei (%.6f USDC)",
			finalReceiverBalance.String(), float64(finalReceiverBalance.Int64())/1000000.0)

		// Verify sender balance is back to initial (assuming no gas fees since this is USDC transfer with authorization)
		suite.Equal(initialSenderBalance.String(), finalSenderBalance.String(),
			"Sender balance should be back to initial amount")

		// Verify receiver balance is back to initial
		suite.Equal(initialReceiverBalance.String(), finalReceiverBalance.String(),
			"Receiver balance should be back to initial amount")

		suite.T().Log("✅ Return transfer verified successfully!")
		suite.T().Log("✅ Complete round-trip transfer test passed!")
	})
}

// TestRealTransferE2E is the test runner
func TestRealTransferE2E(t *testing.T) {
	suite.Run(t, new(RealTransferE2ETestSuite))
}
