package svm

import (
	"fmt"

	"github.com/sigweihq/x402pay/pkg/chains"
)

// SVMAdapter provides SVM chain functionality
type SVMAdapter struct {
	network   string
	rpc       *RPCClient
	validator *TransactionValidator
}

// NewSVMAdapter creates a new SVM chain adapter
func NewSVMAdapter(network string, endpoints []string) *SVMAdapter {
	return &SVMAdapter{
		network:   network,
		rpc:       NewRPCClient(network, endpoints),
		validator: NewTransactionValidator(),
	}
}

// Network implements chains.ChainAdapter
func (a *SVMAdapter) Network() string {
	return a.network
}

// RPCClient implements chains.ChainAdapter
func (a *SVMAdapter) RPCClient() chains.RPCClient {
	return a.rpc
}

// SignatureScheme implements chains.ChainAdapter
// For verification-only support, we return a minimal stub
func (a *SVMAdapter) SignatureScheme() chains.SignatureScheme {
	return &stubSignatureScheme{}
}

// TransactionValidator implements chains.ChainAdapter
func (a *SVMAdapter) TransactionValidator() chains.TransactionValidator {
	return a.validator
}

// stubSignatureScheme is a minimal signature scheme for verification-only support
type stubSignatureScheme struct{}

func (s *stubSignatureScheme) DeriveAddress(privateKey interface{}) (string, error) {
	return "", fmt.Errorf("SVM signing not supported - verification only")
}
