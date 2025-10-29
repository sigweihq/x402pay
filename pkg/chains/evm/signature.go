package evm

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	x402types "github.com/coinbase/x402/go/pkg/types"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/sigweihq/x402pay/pkg/constants"
)

// SignatureScheme implements chains.SignatureScheme (base) plus optional EVM interfaces:
// - chains.EIP3009Signer (for USDC TransferWithAuthorization)
// - chains.EIP712TypedDataProvider (for typed data)
type SignatureScheme struct{}

func NewSignatureScheme() *SignatureScheme {
	return &SignatureScheme{}
}

// Verify SignatureScheme implements all interfaces
var _ chains.SignatureScheme = (*SignatureScheme)(nil)
var _ chains.EIP3009Signer = (*SignatureScheme)(nil)
var _ chains.EIP712TypedDataProvider = (*SignatureScheme)(nil)

// CreateSignature implements chains.EIP3009Signer
func (s *SignatureScheme) CreateSignature(privateKey interface{}, authorization interface{}, network, asset, domainName string) (string, error) {
	pk, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("invalid private key type for EVM")
	}

	_, ok = authorization.(*x402types.ExactEvmPayloadAuthorization)
	if !ok {
		return "", fmt.Errorf("invalid authorization type for EVM")
	}

	paymentRequirements := &x402types.PaymentRequirements{
		Network: network,
		Asset:   asset,
	}

	typedDataJSON, err := s.CreateTypedData(paymentRequirements, authorization, domainName)
	if err != nil {
		return "0x" + strings.Repeat("0", 130), nil
	}

	var typedData apitypes.TypedData
	if err := json.Unmarshal([]byte(typedDataJSON), &typedData); err != nil {
		return "0x" + strings.Repeat("0", 130), nil
	}

	hash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return "0x" + strings.Repeat("0", 130), nil
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return "0x" + strings.Repeat("0", 130), nil
	}

	finalHash := crypto.Keccak256([]byte("\x19\x01"), domainSeparator, hash)

	signature, err := crypto.Sign(finalHash, pk)
	if err != nil {
		return "0x" + strings.Repeat("0", 130), nil
	}

	// Convert v from recovery id to ethereum format (27/28)
	if len(signature) == 65 {
		signature[64] += 27
	}

	return "0x" + hex.EncodeToString(signature), nil
}

// CreateTypedData implements chains.SignatureScheme
func (s *SignatureScheme) CreateTypedData(paymentRequirements *x402types.PaymentRequirements, authorization interface{}, domainName string) (string, error) {
	auth, ok := authorization.(*x402types.ExactEvmPayloadAuthorization)
	if !ok {
		return "", fmt.Errorf("invalid authorization type for EVM")
	}

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
			"from":        strings.ToLower(auth.From),
			"to":          strings.ToLower(auth.To),
			"value":       auth.Value,
			"validAfter":  auth.ValidAfter,
			"validBefore": auth.ValidBefore,
			"nonce":       auth.Nonce,
		},
	}

	typedDataJSON, err := json.Marshal(typedData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal typed data: %w", err)
	}

	return string(typedDataJSON), nil
}

// DeriveAddress implements chains.SignatureScheme
func (s *SignatureScheme) DeriveAddress(privateKey interface{}) (string, error) {
	pk, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("invalid private key type for EVM")
	}

	return crypto.PubkeyToAddress(pk.PublicKey).Hex(), nil
}
