package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/withObsrvr/pluginapi"
)

// KaleMetricsProcessor processes Kale contract events to extract block metrics
type KaleMetricsProcessor struct {
	// blockMetrics maps block indices to their metrics
	blockMetrics map[uint32]*KaleBlockMetrics
	// consumers receive metrics updates
	consumers []pluginapi.Processor
	// contractID is the ID of the Kale contract to monitor
	contractID string
	// mu protects access to shared state
	mu sync.RWMutex
	// stats tracks operational metrics
	stats struct {
		ProcessedBlocks uint32
		LastBlockIndex  uint32
		LastUpdated     time.Time
	}
	// startTime records when the processor was created
	startTime time.Time
}

// Initialize initializes the processor with the given configuration
func (p *KaleMetricsProcessor) Initialize(config map[string]interface{}) error {
	log.Printf("Initializing KaleMetricsProcessor with config: %+v", config)

	contractID, ok := config["contract_id"].(string)
	if !ok {
		return NewProcessorError(
			fmt.Errorf("missing contract_id in configuration"),
			ErrorTypeConfig,
			ErrorSeverityFatal,
		)
	}
	p.contractID = contractID
	log.Printf("Initialized KaleMetricsProcessor for contract: %s", p.contractID)
	return nil
}

// NewKaleMetricsProcessor creates a new KaleMetricsProcessor
func NewKaleMetricsProcessor() *KaleMetricsProcessor {
	return &KaleMetricsProcessor{
		blockMetrics: make(map[uint32]*KaleBlockMetrics),
		consumers:    make([]pluginapi.Processor, 0),
		startTime:    time.Now(),
	}
}

// Subscribe registers a consumer to receive metrics
func (p *KaleMetricsProcessor) Subscribe(consumer pluginapi.Processor) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.consumers = append(p.consumers, consumer)
	log.Printf("Added new consumer, total consumers: %d", len(p.consumers))
}

// Unsubscribe removes a consumer
func (p *KaleMetricsProcessor) Unsubscribe(consumer pluginapi.Processor) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, c := range p.consumers {
		if c == consumer {
			p.consumers = append(p.consumers[:i], p.consumers[i+1:]...)
			log.Printf("Removed consumer, total consumers: %d", len(p.consumers))
			return
		}
	}
}

// ProcessEventMessage processes a contract event message
func (p *KaleMetricsProcessor) ProcessEventMessage(ctx context.Context, contractEvent map[string]interface{}) error {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return NewProcessorError(
			fmt.Errorf("context canceled during event processing: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		)
	}

	// Check if this is from our target contract
	contractID, ok := contractEvent["contract_id"].(string)
	if !ok || contractID != p.contractID {
		return NewProcessorError(
			fmt.Errorf("event is not from target contract: expected %s, got %s", p.contractID, contractID),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		).WithContract(contractID)
	}

	log.Printf("Processing event from Kale contract: %s", contractID)
	err := p.processEventMessage(ctx, contractEvent)

	if err != nil {
		// If it's already a ProcessorError, return it as is
		if procErr, ok := err.(*ProcessorError); ok {
			return procErr
		}

		// Extract context for the error
		txHash, _ := contractEvent["transaction_hash"].(string)
		var ledgerSeq uint32
		if seq, ok := contractEvent["ledger_sequence"].(float64); ok {
			ledgerSeq = uint32(seq)
		}

		return NewProcessorError(
			fmt.Errorf("error processing event message: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityError,
		).WithContract(contractID).WithTransaction(txHash).WithLedger(ledgerSeq)
	}

	return nil
}

// ProcessInvocationMessage processes a contract invocation message
func (p *KaleMetricsProcessor) ProcessInvocationMessage(ctx context.Context, invocation map[string]interface{}) error {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return NewProcessorError(
			fmt.Errorf("context canceled during invocation processing: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		)
	}

	// Check if this is from our target contract
	contractID, ok := invocation["contract_id"].(string)
	if !ok || contractID != p.contractID {
		return NewProcessorError(
			fmt.Errorf("invocation is not for target contract: expected %s, got %s", p.contractID, contractID),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		).WithContract(contractID)
	}

	log.Printf("Processing invocation for Kale contract: %s", contractID)
	err := p.processInvocationMessage(ctx, invocation)

	if err != nil {
		// If it's already a ProcessorError, return it as is
		if procErr, ok := err.(*ProcessorError); ok {
			return procErr
		}

		// Extract context for the error
		txHash, _ := invocation["transaction_hash"].(string)
		var ledgerSeq uint32
		if seq, ok := invocation["ledger_sequence"].(float64); ok {
			ledgerSeq = uint32(seq)
		}

		return NewProcessorError(
			fmt.Errorf("error processing invocation message: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityError,
		).WithContract(contractID).WithTransaction(txHash).WithLedger(ledgerSeq)
	}

	return nil
}

// getOrCreateBlockMetrics gets or creates metrics for a block
func (p *KaleMetricsProcessor) getOrCreateBlockMetrics(blockIndex uint32) *KaleBlockMetrics {
	p.mu.Lock()
	defer p.mu.Unlock()

	metrics, ok := p.blockMetrics[blockIndex]
	if !ok {
		log.Printf("Creating new metrics for block %d", blockIndex)
		metrics = NewKaleBlockMetrics(blockIndex)
		p.blockMetrics[blockIndex] = metrics

		// Update statistics
		p.stats.ProcessedBlocks++
		p.stats.LastBlockIndex = blockIndex
		p.stats.LastUpdated = time.Now()
	}
	return metrics
}

// GetBlockMetrics returns a copy of the metrics for a given block index
func (p *KaleMetricsProcessor) GetBlockMetrics(blockIndex uint32) (*KaleBlockMetrics, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	metrics, ok := p.blockMetrics[blockIndex]
	if !ok {
		return nil, NewProcessorError(
			fmt.Errorf("no metrics found for block index %d", blockIndex),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		).WithBlock(blockIndex)
	}

	// Return a copy to avoid race conditions
	metricsCopy := *metrics
	return &metricsCopy, nil
}

// GetAllBlockMetrics returns a map with copies of all block metrics
func (p *KaleMetricsProcessor) GetAllBlockMetrics() map[uint32]*KaleBlockMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[uint32]*KaleBlockMetrics, len(p.blockMetrics))
	for idx, metrics := range p.blockMetrics {
		metricsCopy := *metrics
		result[idx] = &metricsCopy
	}

	return result
}

// GetStatus returns operational metrics for the processor
func (p *KaleMetricsProcessor) GetStatus() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"stats": map[string]interface{}{
			"processed_blocks": p.stats.ProcessedBlocks,
			"last_block_index": p.stats.LastBlockIndex,
			"last_updated":     p.stats.LastUpdated,
		},
		"consumers":   len(p.consumers),
		"uptime":      time.Since(p.startTime).String(),
		"contract_id": p.contractID,
	}
}

// forwardToConsumers forwards metrics to all registered consumers
func (p *KaleMetricsProcessor) forwardToConsumers(ctx context.Context, metrics *KaleBlockMetrics) error {
	if err := ctx.Err(); err != nil {
		return NewProcessorError(
			fmt.Errorf("context canceled before forwarding to consumers: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		)
	}

	p.mu.RLock()
	consumers := make([]pluginapi.Processor, len(p.consumers))
	copy(consumers, p.consumers)
	p.mu.RUnlock()

	if len(consumers) == 0 {
		log.Printf("No consumers registered, skipping forwarding")
		return nil
	}

	log.Printf("Forwarding metrics for block %d to %d consumers", metrics.BlockIndex, len(consumers))

	// Convert metrics to JSON
	metricsJSON, err := json.Marshal(metrics)
	if err != nil {
		return NewProcessorError(
			fmt.Errorf("error marshaling metrics to JSON: %w", err),
			ErrorTypeParsing,
			ErrorSeverityError,
		).WithBlock(metrics.BlockIndex)
	}

	// Create a message to send to consumers
	msg := pluginapi.Message{
		Payload:   metricsJSON,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"block_index": metrics.BlockIndex,
			"type":        "kale_block_metrics",
		},
	}

	// Forward to each consumer
	var forwardErrors []error
	for _, consumer := range consumers {
		if err := consumer.Process(ctx, msg); err != nil {
			log.Printf("Error forwarding metrics to consumer: %v", err)
			forwardErrors = append(forwardErrors, err)
		}
	}

	if len(forwardErrors) > 0 {
		return NewProcessorError(
			fmt.Errorf("failed to forward metrics to %d out of %d consumers", len(forwardErrors), len(consumers)),
			ErrorTypeNetwork,
			ErrorSeverityWarning,
		).WithBlock(metrics.BlockIndex).WithContext("error_count", len(forwardErrors))
	}

	return nil
}
