package utils

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coinbase/x402/go/pkg/facilitatorclient"
	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sigweihq/x402pay/pkg/chains/evm"
	"github.com/sigweihq/x402pay/pkg/constants"
)

// AuthorizationToTypedData converts an x402 authorization to EIP-712 typed data JSON
// This function is EVM-specific and only works with ExactEvmPayloadAuthorization
func AuthorizationToTypedData(paymentRequirements *x402types.PaymentRequirements, authorization *x402types.ExactEvmPayloadAuthorization, domainName string) (string, error) {
	evmScheme := evm.NewSignatureScheme()
	return evmScheme.CreateTypedData(paymentRequirements, authorization, domainName)
}

// CreateSignatureForTransfer creates an EIP-3009 signature for USDC TransferWithAuthorization
// This function is EVM-specific and only works with ExactEvmPayloadAuthorization
func CreateSignatureForTransfer(privateKey *ecdsa.PrivateKey, authorization *x402types.ExactEvmPayloadAuthorization, network, asset, domainName string) string {
	evmScheme := evm.NewSignatureScheme()
	signature, err := evmScheme.CreateSignature(privateKey, authorization, network, asset, domainName)
	if err != nil {
		return "0x" + strings.Repeat("0", 130)
	}
	return signature
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

	usdcAddress := constants.NetworkToUSDCAddress[paymentPayload.Network]

	if assetLower == strings.ToLower(usdcAddress) {
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

	if extraData == nil {
		return "", "", fmt.Errorf("Extra data is nil")
	}

	name, ok := extraData["name"].(string)
	if !ok {
		return "", "", fmt.Errorf("name field missing or not a string")
	}

	version, ok := extraData["version"].(string)
	if !ok {
		return "", "", fmt.Errorf("version field missing or not a string")
	}

	return name, version, nil
}

// GetCurrentTimeNanos returns the current time in Unix nanoseconds
func GetCurrentTimeNanos() int64 {
	return time.Now().UnixNano()
}

// MakeJSONRequest is a generic helper for making HTTP requests with JSON payloads
// It handles marshaling, auth headers, and response decoding
func MakeJSONRequest[T any](
	client *http.Client,
	method string,
	url string,
	requestBody any,
	createAuthHeaders func() (map[string]map[string]string, error),
	endpointName string, // e.g., "verify", "settle" - used to look up auth headers
) (*T, error) {
	// Marshal request body
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add auth headers if available
	if createAuthHeaders != nil {
		headers, err := createAuthHeaders()
		if err != nil {
			return nil, fmt.Errorf("failed to create auth headers: %w", err)
		}
		if endpointHeaders, ok := headers[endpointName]; ok {
			for key, value := range endpointHeaders {
				req.Header.Set(key, value)
			}
		}
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send %s request: %w", endpointName, err)
	}
	defer resp.Body.Close()

	limitedReader := io.LimitReader(resp.Body, int64(constants.MaxResponseBodySize))

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(limitedReader)
		return nil, fmt.Errorf("%s request failed with status %d: %s", endpointName, resp.StatusCode, string(body))
	}

	// Decode response
	var result T
	if err := json.NewDecoder(limitedReader).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode %s response: %w", endpointName, err)
	}

	return &result, nil
}
