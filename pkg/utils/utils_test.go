package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/sigweihq/x402pay/pkg/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test private key (DO NOT USE IN PRODUCTION)
const testPrivateKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func TestAuthorizationToTypedData(t *testing.T) {
	tests := []struct {
		name                string
		paymentRequirements *x402types.PaymentRequirements
		authorization       *x402types.ExactEvmPayloadAuthorization
		expectedError       bool
		validateTypedData   func(*testing.T, string)
	}{
		{
			name: "successful conversion for Base network",
			paymentRequirements: &x402types.PaymentRequirements{
				Network: constants.NetworkBase,
				Asset:   constants.USDCAddressBase,
			},
			authorization: &x402types.ExactEvmPayloadAuthorization{
				From:        "0x1234567890123456789012345678901234567890",
				To:          "0x0987654321098765432109876543210987654321",
				Value:       "1000000",
				ValidAfter:  "0",
				ValidBefore: "999999999999",
				Nonce:       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			expectedError: false,
			validateTypedData: func(t *testing.T, typedDataJSON string) {
				var typedData apitypes.TypedData
				err := json.Unmarshal([]byte(typedDataJSON), &typedData)
				require.NoError(t, err)

				// Verify domain
				assert.Equal(t, constants.USDCName[constants.NetworkBase], typedData.Domain.Name)
				assert.Equal(t, "2", typedData.Domain.Version)
				expectedChainId := math.NewHexOrDecimal256(8453)
				assert.Equal(t, (*big.Int)(expectedChainId), (*big.Int)(typedData.Domain.ChainId))
				assert.Equal(t, strings.ToLower(constants.NetworkToUSDCAddress[constants.NetworkBase]), typedData.Domain.VerifyingContract)

				// Verify primary type
				assert.Equal(t, "TransferWithAuthorization", typedData.PrimaryType)

				// Verify message
				assert.Equal(t, "0x1234567890123456789012345678901234567890", typedData.Message["from"])
				assert.Equal(t, "0x0987654321098765432109876543210987654321", typedData.Message["to"])
				assert.Equal(t, "1000000", typedData.Message["value"])
				assert.Equal(t, "0", typedData.Message["validAfter"])
				assert.Equal(t, "999999999999", typedData.Message["validBefore"])
			},
		},
		{
			name: "successful conversion for Base Sepolia network",
			paymentRequirements: &x402types.PaymentRequirements{
				Network: constants.NetworkBaseSepolia,
				Asset:   constants.NetworkToUSDCAddress[constants.NetworkBaseSepolia],
			},
			authorization: &x402types.ExactEvmPayloadAuthorization{
				From:        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
				To:          "0x1111111111111111111111111111111111111111",
				Value:       "5000000",
				ValidAfter:  "0",
				ValidBefore: "2000000000",
				Nonce:       "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			},
			expectedError: false,
			validateTypedData: func(t *testing.T, typedDataJSON string) {
				var typedData apitypes.TypedData
				err := json.Unmarshal([]byte(typedDataJSON), &typedData)
				require.NoError(t, err)

				// Verify domain
				assert.Equal(t, constants.USDCName[constants.NetworkBaseSepolia], typedData.Domain.Name)
				expectedChainId := math.NewHexOrDecimal256(84532)
				assert.Equal(t, (*big.Int)(expectedChainId), (*big.Int)(typedData.Domain.ChainId))
				assert.Equal(t, strings.ToLower(constants.NetworkToUSDCAddress[constants.NetworkBaseSepolia]), typedData.Domain.VerifyingContract)
			},
		},
		{
			name: "handles mixed case addresses correctly",
			paymentRequirements: &x402types.PaymentRequirements{
				Network: constants.NetworkBase,
				Asset:   constants.NetworkToUSDCAddress[constants.NetworkBase],
			},
			authorization: &x402types.ExactEvmPayloadAuthorization{
				From:        "0xAABBCCDDEEFF00112233445566778899AABBCCDD",
				To:          "0x1122334455667788990011223344556677889900",
				Value:       "1000000",
				ValidAfter:  "0",
				ValidBefore: "999999999999",
				Nonce:       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			expectedError: false,
			validateTypedData: func(t *testing.T, typedDataJSON string) {
				var typedData apitypes.TypedData
				err := json.Unmarshal([]byte(typedDataJSON), &typedData)
				require.NoError(t, err)

				// Verify addresses are lowercased
				assert.Equal(t, strings.ToLower(constants.NetworkToUSDCAddress[constants.NetworkBase]), typedData.Domain.VerifyingContract)
				assert.Equal(t, "0xaabbccddeeff00112233445566778899aabbccdd", typedData.Message["from"])
				assert.Equal(t, "0x1122334455667788990011223344556677889900", typedData.Message["to"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typedDataJSON, err := AuthorizationToTypedData(tt.paymentRequirements, tt.authorization, constants.USDCName[tt.paymentRequirements.Network])

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, typedDataJSON)
				if tt.validateTypedData != nil {
					tt.validateTypedData(t, typedDataJSON)
				}
			}
		})
	}
}

func TestCreateSignatureForTransfer(t *testing.T) {
	// Create a test private key
	privateKey, err := crypto.HexToECDSA(testPrivateKeyHex)
	require.NoError(t, err)

	tests := []struct {
		name          string
		privateKey    *ecdsa.PrivateKey
		authorization *x402types.ExactEvmPayloadAuthorization
		network       string
		validate      func(*testing.T, string)
	}{
		{
			name:       "creates valid signature for Base network",
			privateKey: privateKey,
			authorization: &x402types.ExactEvmPayloadAuthorization{
				From:        crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
				To:          "0x0987654321098765432109876543210987654321",
				Value:       "1000000",
				ValidAfter:  "0",
				ValidBefore: "999999999999",
				Nonce:       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			network: constants.NetworkBase,
			validate: func(t *testing.T, signature string) {
				// Verify signature format
				assert.True(t, strings.HasPrefix(signature, "0x"), "signature should start with 0x")
				assert.Equal(t, 132, len(signature), "signature should be 132 characters (0x + 65 bytes * 2)")

				// Verify it's not all zeros
				assert.NotEqual(t, "0x"+strings.Repeat("0", 130), signature, "signature should not be all zeros")

				// Verify it's valid hex
				_, err := hex.DecodeString(signature[2:])
				assert.NoError(t, err, "signature should be valid hex")
			},
		},
		{
			name:       "creates valid signature for Base Sepolia network",
			privateKey: privateKey,
			authorization: &x402types.ExactEvmPayloadAuthorization{
				From:        crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
				To:          "0x1111111111111111111111111111111111111111",
				Value:       "5000000",
				ValidAfter:  "0",
				ValidBefore: "2000000000",
				Nonce:       "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			},
			network: constants.NetworkBaseSepolia,
			validate: func(t *testing.T, signature string) {
				// Verify signature format
				assert.True(t, strings.HasPrefix(signature, "0x"))
				assert.Equal(t, 132, len(signature))
				assert.NotEqual(t, "0x"+strings.Repeat("0", 130), signature)
			},
		},
		{
			name:       "different values produce different signatures",
			privateKey: privateKey,
			authorization: &x402types.ExactEvmPayloadAuthorization{
				From:        crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
				To:          "0x0987654321098765432109876543210987654321",
				Value:       "2000000", // Different value
				ValidAfter:  "0",
				ValidBefore: "999999999999",
				Nonce:       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			network: constants.NetworkBase,
			validate: func(t *testing.T, signature string) {
				// Create another signature with different value
				differentAuth := &x402types.ExactEvmPayloadAuthorization{
					From:        crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
					To:          "0x0987654321098765432109876543210987654321",
					Value:       "1000000", // Different value
					ValidAfter:  "0",
					ValidBefore: "999999999999",
					Nonce:       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				}
				differentSig := CreateSignatureForTransfer(privateKey, differentAuth, constants.NetworkBase, constants.USDCAddressBase, constants.USDCName[constants.NetworkBase])

				assert.NotEqual(t, signature, differentSig, "different values should produce different signatures")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := constants.NetworkToUSDCAddress[tt.network]
			signature := CreateSignatureForTransfer(tt.privateKey, tt.authorization, tt.network, asset, constants.USDCName[tt.network])

			if tt.validate != nil {
				tt.validate(t, signature)
			}
		})
	}
}

func TestToPaymentPayload(t *testing.T) {
	tests := []struct {
		name        string
		signature   string
		fromAddress string
		toAddress   string
		network     string
		value       uint64
		nonce       string
		validBefore string
		validate    func(*testing.T, *x402types.PaymentPayload)
	}{
		{
			name:        "creates valid payment payload with all fields",
			signature:   "0x1234567890abcdef",
			fromAddress: "0x1234567890123456789012345678901234567890",
			toAddress:   "0x0987654321098765432109876543210987654321",
			network:     constants.NetworkBase,
			value:       1000000,
			nonce:       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			validBefore: "999999999999",
			validate: func(t *testing.T, payload *x402types.PaymentPayload) {
				assert.Equal(t, 1, payload.X402Version)
				assert.Equal(t, "exact", payload.Scheme)
				assert.Equal(t, constants.NetworkBase, payload.Network)

				assert.NotNil(t, payload.Payload)
				assert.Equal(t, "0x1234567890abcdef", payload.Payload.Signature)

				assert.NotNil(t, payload.Payload.Authorization)
				assert.Equal(t, "0x1234567890123456789012345678901234567890", payload.Payload.Authorization.From)
				assert.Equal(t, "0x0987654321098765432109876543210987654321", payload.Payload.Authorization.To)
				assert.Equal(t, "1000000", payload.Payload.Authorization.Value)
				assert.Equal(t, "0", payload.Payload.Authorization.ValidAfter)
				assert.Equal(t, "999999999999", payload.Payload.Authorization.ValidBefore)
				assert.Equal(t, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", payload.Payload.Authorization.Nonce)
			},
		},
		{
			name:        "handles mixed case addresses correctly",
			signature:   "0xabcdef",
			fromAddress: "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
			toAddress:   "0xAABBCCDDEEFF00112233445566778899AABBCCDD",
			network:     constants.NetworkBaseSepolia,
			value:       5000000,
			nonce:       "0xabcd",
			validBefore: "2000000000",
			validate: func(t *testing.T, payload *x402types.PaymentPayload) {
				// Verify addresses are lowercased
				assert.Equal(t, "0xabcdef1234567890abcdef1234567890abcdef12", payload.Payload.Authorization.From)
				assert.Equal(t, "0xaabbccddeeff00112233445566778899aabbccdd", payload.Payload.Authorization.To)
			},
		},
		{
			name:        "handles large values correctly",
			signature:   "0xsig",
			fromAddress: "0x1234567890123456789012345678901234567890",
			toAddress:   "0x0987654321098765432109876543210987654321",
			network:     constants.NetworkBase,
			value:       18446744073709551615, // Max uint64
			nonce:       "0x1",
			validBefore: "999999999999",
			validate: func(t *testing.T, payload *x402types.PaymentPayload) {
				assert.Equal(t, "18446744073709551615", payload.Payload.Authorization.Value)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := ToPaymentPayload(
				tt.signature,
				tt.fromAddress,
				tt.toAddress,
				tt.network,
				tt.value,
				tt.nonce,
				tt.validBefore,
			)

			assert.NotNil(t, payload)
			if tt.validate != nil {
				tt.validate(t, payload)
			}
		})
	}
}

func TestCreatePaymentPayload(t *testing.T) {
	tests := []struct {
		name          string
		privateKeyHex string
		toAddress     string
		network       string
		value         uint64
		nonce         string
		validBefore   string
		expectedError bool
		errorContains string
		validate      func(*testing.T, *x402types.PaymentPayload)
	}{
		{
			name:          "creates valid payment payload for Base network",
			privateKeyHex: testPrivateKeyHex,
			toAddress:     "0x0987654321098765432109876543210987654321",
			network:       constants.NetworkBase,
			value:         1000000,
			nonce:         "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			validBefore:   "999999999999",
			expectedError: false,
			validate: func(t *testing.T, payload *x402types.PaymentPayload) {
				assert.Equal(t, 1, payload.X402Version)
				assert.Equal(t, "exact", payload.Scheme)
				assert.Equal(t, constants.NetworkBase, payload.Network)

				assert.NotNil(t, payload.Payload)
				assert.NotNil(t, payload.Payload.Authorization)

				// Verify from address matches private key
				privateKey, _ := crypto.HexToECDSA(testPrivateKeyHex)
				expectedFrom := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
				assert.Equal(t, expectedFrom, payload.Payload.Authorization.From)

				// Verify signature is valid (not all zeros)
				assert.True(t, strings.HasPrefix(payload.Payload.Signature, "0x"))
				assert.NotEqual(t, "0x"+strings.Repeat("0", 130), payload.Payload.Signature)
			},
		},
		{
			name:          "creates valid payment payload for Base Sepolia network",
			privateKeyHex: testPrivateKeyHex,
			toAddress:     "0x1111111111111111111111111111111111111111",
			network:       constants.NetworkBaseSepolia,
			value:         5000000,
			nonce:         "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			validBefore:   "2000000000",
			expectedError: false,
			validate: func(t *testing.T, payload *x402types.PaymentPayload) {
				assert.Equal(t, constants.NetworkBaseSepolia, payload.Network)
				assert.Equal(t, "5000000", payload.Payload.Authorization.Value)
			},
		},
		{
			name:          "handles private key with 0x prefix",
			privateKeyHex: "0x" + testPrivateKeyHex,
			toAddress:     "0x0987654321098765432109876543210987654321",
			network:       constants.NetworkBase,
			value:         1000000,
			nonce:         "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			validBefore:   "999999999999",
			expectedError: false,
			validate: func(t *testing.T, payload *x402types.PaymentPayload) {
				assert.NotNil(t, payload)
				assert.NotEmpty(t, payload.Payload.Signature)
			},
		},
		{
			name:          "returns error for invalid private key",
			privateKeyHex: "invalid_key",
			toAddress:     "0x0987654321098765432109876543210987654321",
			network:       constants.NetworkBase,
			value:         1000000,
			nonce:         "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			validBefore:   "999999999999",
			expectedError: true,
			errorContains: "invalid private key",
		},
		{
			name:          "returns error for empty private key",
			privateKeyHex: "",
			toAddress:     "0x0987654321098765432109876543210987654321",
			network:       constants.NetworkBase,
			value:         1000000,
			nonce:         "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			validBefore:   "999999999999",
			expectedError: true,
			errorContains: "invalid private key",
		},
		{
			name:          "returns error for short private key",
			privateKeyHex: "1234",
			toAddress:     "0x0987654321098765432109876543210987654321",
			network:       constants.NetworkBase,
			value:         1000000,
			nonce:         "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			validBefore:   "999999999999",
			expectedError: true,
			errorContains: "invalid private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := constants.NetworkToUSDCAddress[tt.network]
			payload, err := CreatePaymentPayload(
				tt.privateKeyHex,
				tt.toAddress,
				tt.network,
				asset,
				constants.USDCName[tt.network],
				tt.value,
				tt.nonce,
			)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, payload)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, payload)
				if tt.validate != nil {
					tt.validate(t, payload)
				}
			}
		})
	}
}

// TestSignatureConsistency verifies that the same inputs always produce the same signature
func TestSignatureConsistency(t *testing.T) {
	privateKey, err := crypto.HexToECDSA(testPrivateKeyHex)
	require.NoError(t, err)

	authorization := &x402types.ExactEvmPayloadAuthorization{
		From:        crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
		To:          "0x0987654321098765432109876543210987654321",
		Value:       "1000000",
		ValidAfter:  "0",
		ValidBefore: "999999999999",
		Nonce:       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}

	// Create signature multiple times
	sig1 := CreateSignatureForTransfer(privateKey, authorization, constants.NetworkBase, constants.USDCAddressBase, constants.USDCName[constants.NetworkBase])
	sig2 := CreateSignatureForTransfer(privateKey, authorization, constants.NetworkBase, constants.USDCAddressBase, constants.USDCName[constants.NetworkBase])
	sig3 := CreateSignatureForTransfer(privateKey, authorization, constants.NetworkBase, constants.USDCAddressBase, constants.USDCName[constants.NetworkBase])

	// All signatures should be identical
	assert.Equal(t, sig1, sig2)
	assert.Equal(t, sig2, sig3)
}

// TestCreatePaymentPayloadEndToEnd tests the full flow of creating a payment payload
func TestCreatePaymentPayloadEndToEnd(t *testing.T) {
	payload, err := CreatePaymentPayload(
		testPrivateKeyHex,
		"0x0987654321098765432109876543210987654321",
		constants.NetworkBase,
		constants.USDCAddressBase,
		constants.USDCName[constants.NetworkBase],
		1000000,
		"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	)

	require.NoError(t, err)
	require.NotNil(t, payload)

	// Verify all fields are populated correctly
	assert.Equal(t, 1, payload.X402Version)
	assert.Equal(t, "exact", payload.Scheme)
	assert.Equal(t, constants.NetworkBase, payload.Network)
	assert.NotNil(t, payload.Payload)
	assert.NotNil(t, payload.Payload.Authorization)

	// Verify signature is valid
	assert.True(t, strings.HasPrefix(payload.Payload.Signature, "0x"))
	assert.Equal(t, 132, len(payload.Payload.Signature))
	assert.NotEqual(t, "0x"+strings.Repeat("0", 130), payload.Payload.Signature)

	// Verify authorization
	privateKey, _ := crypto.HexToECDSA(testPrivateKeyHex)
	expectedFrom := strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	assert.Equal(t, expectedFrom, payload.Payload.Authorization.From)
	assert.Equal(t, "0x0987654321098765432109876543210987654321", payload.Payload.Authorization.To)
	assert.Equal(t, "1000000", payload.Payload.Authorization.Value)
	assert.Equal(t, "0", payload.Payload.Authorization.ValidAfter)
	// ValidBefore should be a timestamp approximately 10 minutes in the future
	assert.NotEmpty(t, payload.Payload.Authorization.ValidBefore)

	// Verify the signature can be recreated
	expectedSignature := CreateSignatureForTransfer(
		privateKey,
		payload.Payload.Authorization,
		constants.NetworkBase,
		constants.USDCAddressBase,
		constants.USDCName[constants.NetworkBase],
	)
	assert.Equal(t, expectedSignature, payload.Payload.Signature)
}
