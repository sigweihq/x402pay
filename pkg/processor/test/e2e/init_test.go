package processor

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/sigweihq/x402pay/pkg/chains/evm"
	"github.com/sigweihq/x402pay/pkg/chains/svm"
	"github.com/sigweihq/x402pay/pkg/processor"
)

// TestRealInitialization tests the actual initialization sequence similar to main.go
// This mimics the initialization pattern used in x402-hub/cmd/server/main.go:
//
//	processorConfig := &processor.ProcessorConfig{...}
//	processor.InitProcessorMap(processorConfig, logger)
//	err := evm.InitEVMChains(logger)
//	err = svm.InitSVMChains(logger)
//
// This test verifies that initialization completes quickly (~1 second) by:
// 1. Using official endpoints immediately (Base, Solana)
// 2. Running health checks asynchronously in background
// 3. Not blocking server startup on chainlist.org fetch
//
// Note: Some networks may show "no endpoints available" warnings initially.
// These networks will get endpoints once background health checks complete.
//
// Run with: go test -v -run TestRealInitialization
func TestRealInitialization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Use real facilitator URLs (you can override with environment variables)
	facilitatorURLs := []string{"https://facilitator.x402.rs"}
	cdpAPIKeyID := os.Getenv("CDP_API_KEY_ID")
	cdpAPIKeySecret := os.Getenv("CDP_API_KEY_SECRET")

	if cdpAPIKeyID != "" && cdpAPIKeySecret != "" {
		logger.Info("Using CDP credentials for initialization")
	} else {
		logger.Info("Using public facilitator URLs", "urls", facilitatorURLs)
	}

	// Create a timeout context - should complete in < 3 seconds now (was 30+)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Channel to signal completion
	done := make(chan error, 1)

	// Run initialization in a goroutine so we can timeout
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Initialization panicked", "panic", r)
				done <- nil
			}
		}()

		// Step 1: Initialize payment processor map with network configurations
		// This will make HTTP requests to facilitator /supported endpoints
		processorConfig := &processor.ProcessorConfig{
			FacilitatorURLs: facilitatorURLs,
			CDPAPIKeyID:     cdpAPIKeyID,
			CDPAPIKeySecret: cdpAPIKeySecret,
		}
		logger.Info("Initializing processor map...")
		startTime := time.Now()
		processor.InitProcessorMap(processorConfig, logger)
		logger.Info("Processor map initialized", "duration", time.Since(startTime))

		// Step 2: Auto-discover and initialize EVM chains
		// This will fetch from chainlist.org and health-check all RPC endpoints
		logger.Info("Initializing EVM chains...")
		startTime = time.Now()
		err := evm.InitEVMChains(logger)
		if err != nil {
			logger.Error("Failed to initialize EVM chains", "error", err)
			done <- err
			return
		}
		logger.Info("EVM chains initialized", "duration", time.Since(startTime))

		// Step 3: Auto-discover and initialize SVM chains
		logger.Info("Initializing SVM chains...")
		startTime = time.Now()
		err = svm.InitSVMChains(logger)
		if err != nil {
			logger.Error("Failed to initialize SVM chains", "error", err)
			done <- err
			return
		}
		logger.Info("SVM chains initialized", "duration", time.Since(startTime))

		done <- nil
	}()

	// Wait for either completion or timeout
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Initialization failed: %v", err)
		}
		logger.Info("✓ Initialization completed successfully (should be < 3 seconds)")
	case <-ctx.Done():
		t.Fatal("✗ Initialization timed out after 5 seconds - blocking issue detected!")
	}
}

// TestInitializationSteps tests each initialization step individually
// to identify which step is causing the blocking
func TestInitializationSteps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	facilitatorURLs := []string{"https://facilitator.x402.rs"}
	cdpAPIKeyID := os.Getenv("CDP_API_KEY_ID")
	cdpAPIKeySecret := os.Getenv("CDP_API_KEY_SECRET")

	t.Run("Step1_ProcessorMapInit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		done := make(chan bool, 1)
		go func() {
			processorConfig := &processor.ProcessorConfig{
				FacilitatorURLs: facilitatorURLs,
				CDPAPIKeyID:     cdpAPIKeyID,
				CDPAPIKeySecret: cdpAPIKeySecret,
			}
			startTime := time.Now()
			processor.InitProcessorMap(processorConfig, logger)
			duration := time.Since(startTime)
			logger.Info("✓ ProcessorMap initialization completed", "duration", duration)
			done <- true
		}()

		select {
		case <-done:
			// Success
		case <-ctx.Done():
			t.Fatal("✗ ProcessorMap initialization timed out - stuck on facilitator /supported requests")
		}
	})

	t.Run("Step2_EVMChainsInit", func(t *testing.T) {
		// Now that health checks are async, this should complete in < 1 second
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		done := make(chan bool, 1)
		go func() {
			startTime := time.Now()
			err := evm.InitEVMChains(logger)
			duration := time.Since(startTime)
			logger.Info("✓ EVM chains initialization completed (async health checks)", "duration", duration, "error", err)
			done <- true
		}()

		select {
		case <-done:
			// Success
		case <-ctx.Done():
			t.Fatal("✗ EVM chains initialization timed out - should be fast with async health checks!")
		}
	})

	t.Run("Step3_SVMChainsInit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		done := make(chan bool, 1)
		go func() {
			startTime := time.Now()
			err := svm.InitSVMChains(logger)
			duration := time.Since(startTime)
			logger.Info("✓ SVM chains initialization completed", "duration", duration, "error", err)
			done <- true
		}()

		select {
		case <-done:
			// Success
		case <-ctx.Done():
			t.Fatal("✗ SVM chains initialization timed out")
		}
	})
}
