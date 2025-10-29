package evm

import "fmt"

// UnsupportedNetworkError is returned when a network is not supported
type UnsupportedNetworkError struct {
	Network string
}

func (e *UnsupportedNetworkError) Error() string {
	return fmt.Sprintf("unsupported network: %s", e.Network)
}

// RPCError represents an RPC-related error
type RPCError struct {
	Endpoint string
	Err      error
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC error on %s: %v", e.Endpoint, e.Err)
}

func (e *RPCError) Unwrap() error {
	return e.Err
}
