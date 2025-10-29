package evm

import (
	"fmt"

	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/sigweihq/x402pay/pkg/constants"
)

// BaseEVMAdapter provides common EVM functionality that all EVM chains share
// Specific EVM chains (Base, Ethereum, Polygon, etc.) can embed this and override as needed
type BaseEVMAdapter struct {
	network   string
	chainID   int64
	rpc       *RPCClient
	signer    *SignatureScheme
	validator *TransactionValidator
}

// NewBaseEVMAdapter creates a base EVM adapter with common functionality
func NewBaseEVMAdapter(network string, chainID int64, endpoints []string) *BaseEVMAdapter {
	return &BaseEVMAdapter{
		network:   network,
		chainID:   chainID,
		rpc:       NewRPCClient(network, chainID, endpoints),
		signer:    NewSignatureScheme(),
		validator: NewTransactionValidator(),
	}
}

// Network implements chains.ChainAdapter
func (a *BaseEVMAdapter) Network() string {
	return a.network
}

// RPCClient implements chains.ChainAdapter
func (a *BaseEVMAdapter) RPCClient() chains.RPCClient {
	return a.rpc
}

// SignatureScheme implements chains.ChainAdapter
func (a *BaseEVMAdapter) SignatureScheme() chains.SignatureScheme {
	return a.signer
}

// TransactionValidator implements chains.ChainAdapter
func (a *BaseEVMAdapter) TransactionValidator() chains.TransactionValidator {
	return a.validator
}

// NewEVMAdapter creates an EVM chain adapter for any EVM-compatible network
// Network must be registered in constants.NetworkToChainID
func NewEVMAdapter(network string, endpoints []string) (chains.ChainAdapter, error) {
	chainID, ok := constants.NetworkToChainID[network]
	if !ok {
		return nil, fmt.Errorf("unsupported network: %s (add to constants.NetworkToChainID)", network)
	}
	return NewBaseEVMAdapter(network, chainID, endpoints), nil
}
