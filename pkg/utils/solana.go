package utils

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	associatedtokenaccount "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/compute-budget"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"

	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/gagliardetto/solana-go"
	"github.com/sigweihq/x402pay/pkg/constants"
	localtypes "github.com/sigweihq/x402pay/pkg/types"
)

// DeriveSolanaAddress derives a Solana address from a private key
func DeriveSolanaAddress(privateKeyHex string) (string, error) {
	// Remove 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Decode private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}

	// Solana Ed25519 private keys are 64 bytes (32-byte seed + 32-byte public key)
	// But we support providing just the 32-byte seed
	var privateKey ed25519.PrivateKey
	if len(privateKeyBytes) == 32 {
		// Derive full private key from seed
		privateKey = ed25519.NewKeyFromSeed(privateKeyBytes)
	} else if len(privateKeyBytes) == 64 {
		privateKey = ed25519.PrivateKey(privateKeyBytes)
	} else {
		return "", fmt.Errorf("invalid private key length: %d (expected 32 or 64 bytes)", len(privateKeyBytes))
	}

	// Get public key and convert to Solana address
	publicKey := privateKey.Public().(ed25519.PublicKey)
	solanaPubKey := solana.PublicKeyFromBytes(publicKey)

	return solanaPubKey.String(), nil
}

// EnsureSolanaTokenAccount creates an associated token account if it doesn't exist
func EnsureSolanaTokenAccount(
	rpcEndpoint string,
	payerPrivateKeyHex string,
	walletAddress string,
	mintAddress string,
) error {
	// Parse private key
	privateKeyHex := strings.TrimPrefix(payerPrivateKeyHex, "0x")
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}

	var solanaPrivateKey solana.PrivateKey
	if len(privateKeyBytes) == 32 {
		fullKey := ed25519.NewKeyFromSeed(privateKeyBytes)
		solanaPrivateKey = solana.PrivateKey(fullKey)
	} else if len(privateKeyBytes) == 64 {
		solanaPrivateKey = solana.PrivateKey(privateKeyBytes)
	} else {
		return fmt.Errorf("invalid private key length: %d (expected 32 or 64 bytes)", len(privateKeyBytes))
	}

	payerPubkey := solanaPrivateKey.PublicKey()
	walletPubkey, err := solana.PublicKeyFromBase58(walletAddress)
	if err != nil {
		return fmt.Errorf("invalid wallet address: %w", err)
	}

	mintPubkey, err := solana.PublicKeyFromBase58(mintAddress)
	if err != nil {
		return fmt.Errorf("invalid mint address: %w", err)
	}

	tokenAccount, _, err := solana.FindAssociatedTokenAddress(walletPubkey, mintPubkey)
	if err != nil {
		return fmt.Errorf("failed to derive token account: %w", err)
	}

	// Create RPC client
	client := rpc.New(rpcEndpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if account exists
	accountInfo, err := client.GetAccountInfo(ctx, tokenAccount)
	if err == nil && accountInfo != nil && accountInfo.Value != nil {
		// Account already exists
		return nil
	}

	// Get latest blockhash
	latestBlockhash, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return fmt.Errorf("failed to get latest blockhash: %w", err)
	}

	// Create the ATA
	createInstruction := associatedtokenaccount.NewCreateInstruction(
		payerPubkey,
		walletPubkey,
		mintPubkey,
	).Build()

	tx, err := solana.NewTransaction(
		[]solana.Instruction{createInstruction},
		latestBlockhash.Value.Blockhash,
		solana.TransactionPayer(payerPubkey),
	)
	if err != nil {
		return fmt.Errorf("failed to build transaction: %w", err)
	}

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(payerPubkey) {
			return &solanaPrivateKey
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction
	sig, err := client.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
		SkipPreflight: false,
	})
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	// Wait for confirmation
	for i := 0; i < 30; i++ {
		status, err := client.GetSignatureStatuses(ctx, true, sig)
		if err == nil && status != nil && len(status.Value) > 0 && status.Value[0] != nil {
			if status.Value[0].ConfirmationStatus == rpc.ConfirmationStatusFinalized {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("transaction not confirmed after 30 seconds")
}

// BuildSolanaTransferTransaction builds a complete Solana SPL token transfer transaction
// facilitatorFeePayer is the facilitator's address that will pay for transaction fees
func BuildSolanaTransferTransaction(
	rpcEndpoint string,
	privateKeyHex string,
	fromAddress string,
	toAddress string,
	mintAddress string,
	amount uint64,
	facilitatorFeePayer string,
) (string, error) {
	// Parse private key
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}

	// Create solana PrivateKey
	var solanaPrivateKey solana.PrivateKey
	if len(privateKeyBytes) == 32 {
		// Convert seed to full 64-byte private key
		fullKey := ed25519.NewKeyFromSeed(privateKeyBytes)
		solanaPrivateKey = solana.PrivateKey(fullKey)
	} else if len(privateKeyBytes) == 64 {
		solanaPrivateKey = solana.PrivateKey(privateKeyBytes)
	} else {
		return "", fmt.Errorf("invalid private key length: %d (expected 32 or 64 bytes)", len(privateKeyBytes))
	}

	// Parse addresses
	fromPubkey, err := solana.PublicKeyFromBase58(fromAddress)
	if err != nil {
		return "", fmt.Errorf("invalid from address: %w", err)
	}

	toPubkey, err := solana.PublicKeyFromBase58(toAddress)
	if err != nil {
		return "", fmt.Errorf("invalid to address: %w", err)
	}

	mintPubkey, err := solana.PublicKeyFromBase58(mintAddress)
	if err != nil {
		return "", fmt.Errorf("invalid mint address: %w", err)
	}

	// Parse facilitator fee payer address
	facilitatorPubkey, err := solana.PublicKeyFromBase58(facilitatorFeePayer)
	if err != nil {
		return "", fmt.Errorf("invalid facilitator address: %w", err)
	}

	// Get associated token accounts
	fromTokenAccount, _, err := solana.FindAssociatedTokenAddress(fromPubkey, mintPubkey)
	if err != nil {
		return "", fmt.Errorf("failed to derive from token account: %w", err)
	}

	toTokenAccount, _, err := solana.FindAssociatedTokenAddress(toPubkey, mintPubkey)
	if err != nil {
		return "", fmt.Errorf("failed to derive to token account: %w", err)
	}

	// Create RPC client
	client := rpc.New(rpcEndpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get latest blockhash (getRecentBlockhash is deprecated)
	latestBlockhash, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return "", fmt.Errorf("failed to get latest blockhash: %w", err)
	}

	// Build transaction instructions
	// The x402-rs facilitator expects EXACTLY this structure:
	// 1. Compute unit limit instruction
	// 2. Compute unit price instruction
	// 3. TransferChecked instruction
	instructions := make([]solana.Instruction, 0)

	// 1. Set compute unit limit
	instructions = append(instructions,
		computebudget.NewSetComputeUnitLimitInstruction(200_000).Build(),
	)

	// 2. Set compute unit price (max 5,000,000 microlamports per compute unit)
	instructions = append(instructions,
		computebudget.NewSetComputeUnitPriceInstruction(5_000_000).Build(),
	)

	// 3. SPL Token TransferChecked instruction (facilitator specifically checks for TransferChecked)
	transferInstruction := token.NewTransferCheckedInstruction(
		amount,
		6, // USDC decimals
		fromTokenAccount,
		mintPubkey,
		toTokenAccount,
		fromPubkey,
		[]solana.PublicKey{}, // No additional signers
	).Build()
	instructions = append(instructions, transferInstruction)

	// Build transaction with facilitator as fee payer
	// The facilitator will sign this transaction, so it must be listed as fee payer
	// We create a partially-signed transaction:
	// - Facilitator is fee payer (first signature slot - will be filled by facilitator)
	// - Sender signs the transfer instruction (second signature slot - we fill this)
	tx, err := solana.NewTransaction(
		instructions,
		latestBlockhash.Value.Blockhash,
		solana.TransactionPayer(facilitatorPubkey),
	)
	if err != nil {
		return "", fmt.Errorf("failed to build transaction: %w", err)
	}

	// Get the message to sign
	messageContent, err := tx.Message.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal message: %w", err)
	}

	// Sign the message with sender's private key
	senderSignature := ed25519.Sign(ed25519.PrivateKey(solanaPrivateKey), messageContent)

	// Find the position of the sender in the account keys
	// The facilitator is first (fee payer), sender should be second
	accountKeys := tx.Message.AccountKeys
	senderPosition := -1
	for i, key := range accountKeys {
		if key.Equals(fromPubkey) {
			senderPosition = i
			break
		}
	}
	if senderPosition == -1 {
		return "", fmt.Errorf("sender not found in transaction account keys")
	}

	// Initialize signatures array
	// First signature (index 0) is for facilitator - leave as zero/default
	// Second signature (index 1) is for sender - add our signature
	numSigners := tx.Message.Header.NumRequiredSignatures
	tx.Signatures = make([]solana.Signature, numSigners)

	// Set sender's signature at the appropriate position
	copy(tx.Signatures[senderPosition][:], senderSignature)

	// Serialize transaction
	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %w", err)
	}

	// Encode to base64
	return base64.StdEncoding.EncodeToString(txBytes), nil
}

// CreateSolanaPaymentPayload creates a signed payment payload for Solana
// Returns a SolanaPaymentPayload with a complete signed transaction
// Also returns the sender address for use in payment requirements
// facilitatorFeePayer is the facilitator's address that will pay transaction fees
func CreateSolanaPaymentPayload(
	rpcEndpoint string,
	privateKeyHex string,
	toAddress string,
	network string,
	mintAddress string,
	value uint64,
	facilitatorFeePayer string,
) (*localtypes.SolanaPaymentPayload, string, error) {
	// Derive from address (sender of tokens)
	fromAddress, err := DeriveSolanaAddress(privateKeyHex)
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive address: %w", err)
	}

	// Build complete signed transaction
	signedTx, err := BuildSolanaTransferTransaction(
		rpcEndpoint,
		privateKeyHex,
		fromAddress,
		toAddress,
		mintAddress,
		value,
		facilitatorFeePayer,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build transaction: %w", err)
	}

	// Create Solana payment payload
	paymentPayload := &localtypes.SolanaPaymentPayload{
		X402Version: 1,
		Scheme:      "exact",
		Network:     network,
		Payload: &localtypes.ExactSolanaPayload{
			Transaction: signedTx,
		},
	}

	return paymentPayload, fromAddress, nil
}

// GenerateSolanaKeypair generates a new Solana keypair
func GenerateSolanaKeypair() (privateKeyHex, address string, err error) {
	// Generate new keypair
	account := solana.NewWallet()

	// Get private key (64 bytes: 32-byte seed + 32-byte public key)
	privateKey := account.PrivateKey

	// For storage, we typically only need the 32-byte seed
	// PrivateKey is 64 bytes, first 32 bytes are the seed
	seed := privateKey[:32]
	privateKeyHex = "0x" + hex.EncodeToString(seed)

	// Get address
	address = account.PublicKey().String()

	return privateKeyHex, address, nil
}

// DerivePaymentRequirementsSolana creates payment requirements for Solana
func DerivePaymentRequirementsSolana(
	network string,
	toAddress string,
	amount uint64,
	resourceURL string,
	asset string,
	feePayer string,
) (*x402types.PaymentRequirements, error) {
	// For Solana x402-rs facilitator:
	// - payTo should be the WALLET address (not ATA)
	// - The facilitator derives the ATA from payTo and validates the transaction destination matches it
	// - feePayer must be in extra field

	// Create Extra field with feePayer information
	extraData := map[string]interface{}{
		"feePayer": feePayer,
	}
	extraJSON, err := json.Marshal(extraData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal extra data: %w", err)
	}
	extraRaw := json.RawMessage(extraJSON)

	paymentRequirements := &x402types.PaymentRequirements{
		Scheme:            "exact",
		Network:           network,
		MaxAmountRequired: fmt.Sprintf("%d", amount),
		Resource:          resourceURL,
		Description:       fmt.Sprintf("Payment for POST %s", resourceURL),
		MimeType:          "application/json",
		PayTo:             toAddress, // Use wallet address, facilitator derives ATA
		MaxTimeoutSeconds: 60,
		Asset:             asset,
		Extra:             &extraRaw,
	}

	return paymentRequirements, nil
}

// GetSolanaUSDCMintAddress returns the USDC mint address for a Solana network
func GetSolanaUSDCMintAddress(network string) (string, error) {
	address, ok := constants.NetworkToUSDCAddress[network]
	if !ok {
		return "", fmt.Errorf("no USDC address configured for network %s", network)
	}
	return address, nil
}

// ExtractFeePayerFromSolanaTransaction extracts the fee payer (first account) from a base64-encoded Solana transaction
// Returns empty string if extraction fails
func ExtractFeePayerFromSolanaTransaction(txBase64 string) string {
	tx, err := solana.TransactionFromBase64(txBase64)
	if err != nil {
		return ""
	}

	// The fee payer is always the first account key in a Solana transaction
	if len(tx.Message.AccountKeys) == 0 {
		return ""
	}

	return tx.Message.AccountKeys[0].String()
}
