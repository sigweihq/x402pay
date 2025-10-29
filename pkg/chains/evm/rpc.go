package evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sigweihq/x402pay/pkg/chains"
	"github.com/sigweihq/x402pay/pkg/constants"
)

// RPCClient implements chains.RPCClient and chains.EIP3009Checker for EVM chains
// It provides both basic RPC operations and optional EIP-3009 nonce checking
type RPCClient struct {
	network   string
	chainID   int64
	endpoints []string
}

// NewRPCClient creates a new EVM RPC client
func NewRPCClient(network string, chainID int64, endpoints []string) *RPCClient {
	return &RPCClient{
		network:   network,
		chainID:   chainID,
		endpoints: endpoints,
	}
}

// Verify RPCClient implements both interfaces
var _ chains.RPCClient = (*RPCClient)(nil)
var _ chains.EIP3009Checker = (*RPCClient)(nil)

// GetTransactionReceipt implements chains.RPCClient
// Uses random start position for load balancing across RPC endpoints
func (r *RPCClient) GetTransactionReceipt(txHash string) (chains.TransactionReceipt, error) {
	if len(r.endpoints) == 0 {
		return nil, nil // Skip verification if no endpoints
	}

	// Start at a random position for load balancing
	startIdx := rand.Intn(len(r.endpoints))
	initialDelay := constants.DelayBetweenRPCCalls

	for i := 0; i < len(r.endpoints); i++ {
		if i > 0 {
			delay := time.Duration(i*constants.DelayBetweenRPCCalls+initialDelay) * time.Millisecond
			time.Sleep(delay)
		}

		// Wrap around using modulo for round-robin
		endpointIdx := (startIdx + i) % len(r.endpoints)
		endpoint := r.endpoints[endpointIdx]

		client, err := ethclient.Dial(endpoint)
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), constants.TransactionReceiptTimeout)
		receipt, err := patchedTransactionReceipt(ctx, client, common.HexToHash(txHash))
		client.Close()
		cancel()

		if err != nil {
			continue
		}

		return &EVMReceipt{receipt: receipt}, nil
	}

	return nil, fmt.Errorf("all RPC endpoints failed for network %s", r.network)
}

// IsNonceAlreadyUsed implements chains.EIP3009Checker
func (r *RPCClient) IsNonceAlreadyUsed(nonce, authorizer, asset string) (bool, error) {
	if nonce == "" {
		return false, fmt.Errorf("nonce not found in payment payload")
	}

	authorizerAddr := common.HexToAddress(authorizer)
	nonceBytes32 := common.HexToHash(nonce)

	contractABI := `[{"inputs":[{"internalType":"address","name":"authorizer","type":"address"},{"internalType":"bytes32","name":"nonce","type":"bytes32"}],"name":"authorizationState","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]`

	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return false, fmt.Errorf("failed to parse contract ABI: %w", err)
	}

	data, err := parsedABI.Pack("authorizationState", authorizerAddr, nonceBytes32)
	if err != nil {
		return false, fmt.Errorf("failed to pack function call: %w", err)
	}

	result, err := r.callContract(asset, common.Bytes2Hex(data))
	if err != nil {
		return false, fmt.Errorf("contract call failed: %w", err)
	}

	var isUsed bool
	err = parsedABI.UnpackIntoInterface(&isUsed, "authorizationState", common.Hex2Bytes(result[2:]))
	if err != nil {
		return false, fmt.Errorf("failed to decode contract call result: %w", err)
	}

	return isUsed, nil
}

// IsHealthy implements chains.RPCClient
func (r *RPCClient) IsHealthy(endpoint string) bool {
	client, err := ethclient.Dial(endpoint)
	if err != nil {
		return false
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = client.BlockNumber(ctx)
	return err == nil
}

// callContract makes a contract call with RPC failover
// Uses random start position for load balancing across RPC endpoints
func (r *RPCClient) callContract(contractAddress, data string) (string, error) {
	if len(r.endpoints) == 0 {
		return "", fmt.Errorf("no RPC endpoints available for network %s", r.network)
	}

	// Start at a random position for load balancing
	startIdx := rand.Intn(len(r.endpoints))

	for i := 0; i < len(r.endpoints); i++ {
		if i > 0 {
			delay := time.Duration(i*constants.DelayBetweenRPCCalls) * time.Millisecond
			time.Sleep(delay)
		}

		// Wrap around using modulo for round-robin
		endpointIdx := (startIdx + i) % len(r.endpoints)
		endpoint := r.endpoints[endpointIdx]

		client, err := ethclient.Dial(endpoint)
		if err != nil {
			continue
		}

		callData := data
		if !strings.HasPrefix(data, "0x") {
			callData = "0x" + data
		}
		msg := map[string]interface{}{
			"to":   contractAddress,
			"data": callData,
		}

		ctx, cancel := context.WithTimeout(context.Background(), constants.CallContractTimeout)
		var result string
		err = client.Client().CallContext(ctx, &result, "eth_call", msg, "latest")
		client.Close()
		cancel()

		if err != nil {
			continue
		}

		return result, nil
	}

	return "", fmt.Errorf("all RPC endpoints failed for network %s", r.network)
}

// patchedTransactionReceipt gets a transaction receipt with Base-specific fixes
func patchedTransactionReceipt(ctx context.Context, client *ethclient.Client, txHash common.Hash) (*ethtypes.Receipt, error) {
	var raw json.RawMessage
	err := client.Client().CallContext(ctx, &raw, "eth_getTransactionReceipt", txHash)
	if err != nil {
		return nil, err
	}
	if string(raw) == "null" {
		return nil, errors.New("not found")
	}

	cleaned, err := stripBlockTimestampFromLogs(raw)
	if err != nil {
		return nil, err
	}

	var receipt ethtypes.Receipt
	err = json.Unmarshal(cleaned, &receipt)
	if err != nil {
		return nil, err
	}

	return &receipt, nil
}

// stripBlockTimestampFromLogs removes the blockTimestamp field from transaction logs
func stripBlockTimestampFromLogs(raw json.RawMessage) ([]byte, error) {
	var receiptMap map[string]interface{}
	if err := json.Unmarshal(raw, &receiptMap); err != nil {
		return nil, err
	}

	logs, ok := receiptMap["logs"].([]interface{})
	if ok {
		for _, log := range logs {
			logMap, ok := log.(map[string]interface{})
			if ok {
				delete(logMap, "blockTimestamp")
			}
		}
	}

	return json.Marshal(receiptMap)
}

// EVMReceipt implements chains.TransactionReceipt
type EVMReceipt struct {
	receipt *ethtypes.Receipt
}

// NewEVMReceipt creates a new EVM receipt wrapper
func NewEVMReceipt(receipt *ethtypes.Receipt) *EVMReceipt {
	return &EVMReceipt{receipt: receipt}
}

func (r *EVMReceipt) IsSuccessful() bool {
	return r.receipt.Status == ethtypes.ReceiptStatusSuccessful
}

// GetUnderlyingReceipt returns the underlying EVM receipt (for compatibility)
func (r *EVMReceipt) GetUnderlyingReceipt() *ethtypes.Receipt {
	return r.receipt
}

func (r *EVMReceipt) GetTransferEvent() (*chains.TransferEvent, error) {
	// Transfer(address indexed from, address indexed to, uint256 value)
	transferEventSignature := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

	for _, log := range r.receipt.Logs {
		if len(log.Topics) >= 3 && log.Topics[0] == transferEventSignature {
			from := common.HexToAddress(log.Topics[1].Hex())
			to := common.HexToAddress(log.Topics[2].Hex())
			value := common.BytesToHash(log.Data).Big()

			return &chains.TransferEvent{
				From:  from.Hex(),
				To:    to.Hex(),
				Value: value.String(),
				Asset: log.Address.Hex(), // ERC-20 contract address
			}, nil
		}
	}

	return nil, fmt.Errorf("no transfer event found")
}
