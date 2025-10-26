package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/sigweihq/x402pay/pkg/constants"
)

// AuthorizationToTypedData converts an x402 authorization to EIP-712 typed data JSON
func AuthorizationToTypedData(paymentRequirements *x402types.PaymentRequirements, authorization *x402types.ExactEvmPayloadAuthorization, domainName string) (string, error) {
	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"TransferWithAuthorization": []apitypes.Type{
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"},
				{Name: "nonce", Type: "bytes32"},
			},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{
			Name:              domainName,
			Version:           "2",
			ChainId:           math.NewHexOrDecimal256(constants.NetworkToChainID[paymentRequirements.Network]),
			VerifyingContract: strings.ToLower(paymentRequirements.Asset),
		},
		Message: apitypes.TypedDataMessage{
			"from":        strings.ToLower(authorization.From),
			"to":          strings.ToLower(authorization.To),
			"value":       authorization.Value,
			"validAfter":  authorization.ValidAfter,
			"validBefore": authorization.ValidBefore,
			"nonce":       authorization.Nonce,
		},
	}

	typedDataJSON, err := json.Marshal(typedData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal typed data: %w", err)
	}

	return string(typedDataJSON), nil
}

// CreateSignatureForTransfer creates a signature for the server-side transfer
func CreateSignatureForTransfer(privateKey *ecdsa.PrivateKey, authorization *x402types.ExactEvmPayloadAuthorization, network, asset, domainName string) string {
	// Create payment requirements - reuse existing structures
	paymentRequirements := &x402types.PaymentRequirements{
		Network: network,
		Asset:   asset,
	}

	// Use the existing authorizationToTypedData function from transactions package
	typedDataJSON, err := AuthorizationToTypedData(paymentRequirements, authorization, domainName)
	if err != nil {
		return "0x" + strings.Repeat("0", 130)
	}

	// Parse the typed data and sign it
	var typedData apitypes.TypedData
	if err := json.Unmarshal([]byte(typedDataJSON), &typedData); err != nil {
		return "0x" + strings.Repeat("0", 130)
	}

	// Hash the structured data
	hash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return "0x" + strings.Repeat("0", 130)
	}

	// Create domain separator
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return "0x" + strings.Repeat("0", 130)
	}

	// Create final hash with EIP-712 prefix
	finalHash := crypto.Keccak256([]byte("\x19\x01"), domainSeparator, hash)

	// Sign the hash
	signature, err := crypto.Sign(finalHash, privateKey)
	if err != nil {
		return "0x" + strings.Repeat("0", 130)
	}

	// Convert v from recovery id to ethereum format (27/28)
	if len(signature) == 65 {
		signature[64] += 27
	}

	return "0x" + hex.EncodeToString(signature)
}

// ToPaymentPayload converts payment data to an x402 payment payload
func ToPaymentPayload(signature, fromAddress, toAddress, network string, value uint64, nonce string, validBefore string) *x402types.PaymentPayload {
	// Create the payment payload for the original price amount
	originalPriceStr := fmt.Sprintf("%d", value)

	// Create authorization first
	authorization := &x402types.ExactEvmPayloadAuthorization{
		From:        strings.ToLower(fromAddress),
		To:          strings.ToLower(toAddress),
		Value:       originalPriceStr,
		ValidAfter:  "0",
		ValidBefore: validBefore,
		Nonce:       nonce,
	}
	return WrapExactEvmPayload(&x402types.ExactEvmPayload{
		Signature:     signature,
		Authorization: authorization,
	}, network)
}

// CreatePaymentPayload creates a signed payment payload
func CreatePaymentPayload(privateKeyHex, toAddress, network, asset, domainName string, value uint64, nonce string) (*x402types.PaymentPayload, error) {
	// Remove 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	validBefore := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
	paymentPayload := ToPaymentPayload("", fromAddress, toAddress, network, value, nonce, validBefore)
	paymentPayload.Payload.Signature = CreateSignatureForTransfer(privateKey, paymentPayload.Payload.Authorization, network, asset, domainName)

	return paymentPayload, nil
}

func DerivePaymentRequirements(
	paymentPayload *x402types.PaymentPayload,
	resourceURL string,
	asset string,
) (*x402types.PaymentRequirements, error) {
	assetLower := strings.ToLower(asset)

	paymentRequirements := &x402types.PaymentRequirements{
		Scheme:            paymentPayload.Scheme,
		Network:           paymentPayload.Network,
		MaxAmountRequired: paymentPayload.Payload.Authorization.Value,
		Resource:          resourceURL,
		Description:       fmt.Sprintf("Payment for POST %s", resourceURL),
		MimeType:          "application/json",
		PayTo:             paymentPayload.Payload.Authorization.To,
		MaxTimeoutSeconds: 60,
		Asset:             asset,
		Extra:             nil,
	}

	if assetLower == strings.ToLower(constants.USDCAddressBase) || assetLower == strings.ToLower(constants.USDCAddressBaseSepolia) {
		if err := paymentRequirements.SetUSDCInfo(paymentPayload.Network == constants.NetworkBaseSepolia); err != nil {
			return nil, fmt.Errorf("failed to set USDC info: %w", err)
		}
	}

	return paymentRequirements, nil
}

func CreateHTTPClientWithTimeouts() *http.Client {
	return &http.Client{
		Timeout: constants.FacilitatorTimeout,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   constants.TLSHandshakeTimeout,
			ResponseHeaderTimeout: constants.ResponseHeaderTimeout,
			ExpectContinueTimeout: constants.ExpectContinueTimeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Disable redirects to prevent redirect-based SSRF
		},
	}
}

// ValidateFacilitatorURL validates that a facilitator URL is secure
// Returns error if URL doesn't use HTTPS (except for localhost/127.0.0.1 for testing)
func ValidateFacilitatorURL(url string) error {
	if !strings.HasPrefix(url, "https://") {
		// Allow http://localhost and http://127.0.0.1 for testing
		if strings.HasPrefix(url, "http://localhost") ||
		   strings.HasPrefix(url, "http://127.0.0.1") ||
		   strings.HasPrefix(url, "http://[::1]") {
			return nil
		}
		return fmt.Errorf("facilitator URL must use HTTPS: %s", url)
	}
	return nil
}

func NewFacilitatorClient(config *x402types.FacilitatorConfig, httpClient *http.Client) *facilitatorclient.FacilitatorClient {
	client := facilitatorclient.NewFacilitatorClient(config)
	client.HTTPClient = httpClient
	return client
}

func WrapExactEvmPayload(payload *x402types.ExactEvmPayload, network string) *x402types.PaymentPayload {
	return &x402types.PaymentPayload{
		X402Version: 1,
		Scheme:      "exact",
		Network:     network,
		Payload:     payload,
	}
}

func ExtractExtraData(paymentRequirements *x402types.PaymentRequirements) (string, string, error) {
	// extract "name" from Extra JSON on paymentRequirements
	var extraData map[string]any
	if paymentRequirements.Extra != nil {
		if err := json.Unmarshal(*paymentRequirements.Extra, &extraData); err != nil {
			return "", "", fmt.Errorf("failed to unmarshal Extra: %w", err)
		}
	}
	return extraData["name"].(string), extraData["version"].(string), nil
}

// GetCurrentTimeNanos returns the current time in Unix nanoseconds
func GetCurrentTimeNanos() int64 {
	return time.Now().UnixNano()
}
