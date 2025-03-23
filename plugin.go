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

// KaleMetricsPlugin implements the pluginapi.Plugin interface
type KaleMetricsPlugin struct {
	processor *KaleMetricsProcessor
	mu        sync.RWMutex
	stats     struct {
		ProcessedEvents      uint64
		ProcessedInvocations uint64
		FailedEvents         uint64
		FailedInvocations    uint64
		LastProcessedTime    time.Time
	}
	startTime  time.Time
	contractID string
	consumers  []pluginapi.Consumer
}

// NewPlugin creates a new KaleMetricsPlugin
func NewPlugin() *KaleMetricsPlugin {
	return &KaleMetricsPlugin{
		processor: NewKaleMetricsProcessor(),
		startTime: time.Now(),
	}
}

// Name returns the name of the plugin
func (p *KaleMetricsPlugin) Name() string {
	return "flow/processor/kale-metrics"
}

// Description returns a description of the plugin
func (p *KaleMetricsPlugin) Description() string {
	return "Extracts metrics from Kale contract events and invocations"
}

// Version returns the version of the plugin
func (p *KaleMetricsPlugin) Version() string {
	return "1.0.0"
}

// Type returns the type of the plugin
func (p *KaleMetricsPlugin) Type() pluginapi.PluginType {
	return pluginapi.ProcessorPlugin
}

// Process implements the Processor interface
func (p *KaleMetricsPlugin) Process(ctx context.Context, msg pluginapi.Message) error {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return NewProcessorError(
			fmt.Errorf("context canceled before processing: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		)
	}

	log.Printf("KaleMetricsPlugin.Process called with message metadata: %+v", msg.Metadata)

	// Get the message type from metadata
	msgType, ok := msg.Metadata["type"].(string)
	if !ok {
		log.Printf("Message type not found in metadata, trying to determine from payload")
		// Try to determine message type from payload structure
		payloadBytes, ok := msg.Payload.([]byte)
		if !ok {
			return NewProcessorError(
				fmt.Errorf("message payload is not a byte slice"),
				ErrorTypeParsing,
				ErrorSeverityError,
			)
		}

		var data map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &data); err != nil {
			return NewProcessorError(
				fmt.Errorf("failed to unmarshal message data: %w", err),
				ErrorTypeParsing,
				ErrorSeverityError,
			)
		}

		// Check for fields that indicate event vs invocation
		if _, hasTopics := data["topic"]; hasTopics {
			msgType = "contract_event"
		} else if _, hasFunction := data["function_name"]; hasFunction {
			msgType = "contract_invocation"
		} else {
			log.Printf("Could not determine message type from payload, skipping")
			return nil
		}
	}

	log.Printf("Processing message of type: %s", msgType)

	// Parse the message data
	var data map[string]interface{}
	payloadBytes, ok := msg.Payload.([]byte)
	if !ok {
		return NewProcessorError(
			fmt.Errorf("message payload is not a byte slice"),
			ErrorTypeParsing,
			ErrorSeverityError,
		)
	}

	if err := json.Unmarshal(payloadBytes, &data); err != nil {
		return NewProcessorError(
			fmt.Errorf("failed to unmarshal message data: %w", err),
			ErrorTypeParsing,
			ErrorSeverityError,
		)
	}

	// Check if this event is for our target contract
	if p.contractID != "" {
		if contractID, ok := data["contract_id"].(string); ok && contractID != p.contractID {
			log.Printf("Message is not for our target contract %s (got %s), skipping", p.contractID, contractID)
			return nil
		}
	}

	var err error

	// Process the message based on its type
	switch msgType {
	case "contract_event":
		err = p.processEvent(ctx, data)
	case "contract_invocation":
		err = p.processInvocation(ctx, data)
	case "kale_block_metrics":
		// Pass metrics directly to plugin consumers
		err = p.forwardToPluginConsumers(ctx, msg)
		if err != nil {
			log.Printf("Error forwarding metrics to plugin consumers: %v", err)
		}
	default:
		log.Printf("Unsupported message type: %s", msgType)
		return nil // Skip unsupported message types
	}

	// Record processing statistics
	p.recordProcessing(msgType, err == nil)

	return err
}

// processEvent handles contract event messages and updates statistics
func (p *KaleMetricsPlugin) processEvent(ctx context.Context, data map[string]interface{}) error {
	// First, let the processor handle the event
	err := p.processor.ProcessEventMessage(ctx, data)

	// After processing, check if we need to forward metrics to plugin consumers
	if err == nil && len(p.consumers) > 0 {
		// Get the block index from the event data
		var blockIndex uint32
		if blockIndexFloat, ok := data["block_index"].(float64); ok {
			blockIndex = uint32(blockIndexFloat)
		} else if blockIndexFloat, ok := data["ledger_sequence"].(float64); ok {
			// Fallback to ledger sequence if block index is not available
			blockIndex = uint32(blockIndexFloat)
		}

		if blockIndex > 0 {
			// Get the metrics for this block and forward to plugin consumers
			metrics, getErr := p.processor.GetBlockMetrics(blockIndex)
			if getErr == nil && metrics != nil {
				p.mu.RLock()
				consumers := make([]pluginapi.Consumer, len(p.consumers))
				copy(consumers, p.consumers)
				p.mu.RUnlock()

				// Forward the metrics to plugin consumers
				if forwardErr := p.processor.forwardToPluginConsumers(ctx, metrics, consumers); forwardErr != nil {
					log.Printf("Error forwarding metrics to plugin consumers: %v", forwardErr)
				}
			}
		}
	}

	return err
}

// processInvocation handles contract invocation messages and updates statistics
func (p *KaleMetricsPlugin) processInvocation(ctx context.Context, data map[string]interface{}) error {
	// First, let the processor handle the invocation
	err := p.processor.ProcessInvocationMessage(ctx, data)

	// After processing, check if we need to forward metrics to plugin consumers
	if err == nil && len(p.consumers) > 0 {
		// Get the block index from the invocation data
		var blockIndex uint32
		if blockIndexFloat, ok := data["block_index"].(float64); ok {
			blockIndex = uint32(blockIndexFloat)
		} else if blockIndexFloat, ok := data["ledger_sequence"].(float64); ok {
			// Fallback to ledger sequence if block index is not available
			blockIndex = uint32(blockIndexFloat)
		}

		if blockIndex > 0 {
			// Get the metrics for this block and forward to plugin consumers
			metrics, getErr := p.processor.GetBlockMetrics(blockIndex)
			if getErr == nil && metrics != nil {
				p.mu.RLock()
				consumers := make([]pluginapi.Consumer, len(p.consumers))
				copy(consumers, p.consumers)
				p.mu.RUnlock()

				// Forward the metrics to plugin consumers
				if forwardErr := p.processor.forwardToPluginConsumers(ctx, metrics, consumers); forwardErr != nil {
					log.Printf("Error forwarding metrics to plugin consumers: %v", forwardErr)
				}
			}
		}
	}

	return err
}

// forwardToPluginConsumers forwards messages to all registered plugin consumers
func (p *KaleMetricsPlugin) forwardToPluginConsumers(ctx context.Context, msg pluginapi.Message) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled before forwarding to plugin consumers: %w", err)
	}

	p.mu.RLock()
	consumers := make([]pluginapi.Consumer, len(p.consumers))
	copy(consumers, p.consumers)
	p.mu.RUnlock()

	if len(consumers) == 0 {
		log.Printf("No plugin consumers registered, skipping forwarding")
		return nil
	}

	log.Printf("Forwarding metrics to %d plugin consumers", len(consumers))

	// Forward to each plugin consumer
	var forwardErrors []error
	for _, consumer := range consumers {
		if err := consumer.Process(ctx, msg); err != nil {
			log.Printf("Error forwarding metrics to plugin consumer %s: %v", consumer.Name(), err)
			forwardErrors = append(forwardErrors, err)
		} else {
			log.Printf("Successfully forwarded metrics to plugin consumer %s", consumer.Name())
		}
	}

	if len(forwardErrors) > 0 {
		return fmt.Errorf("failed to forward metrics to %d out of %d plugin consumers", len(forwardErrors), len(consumers))
	}

	return nil
}

// recordProcessing updates statistics based on message type and success
func (p *KaleMetricsPlugin) recordProcessing(msgType string, success bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stats.LastProcessedTime = time.Now()

	if msgType == "contract_event" {
		if success {
			p.stats.ProcessedEvents++
		} else {
			p.stats.FailedEvents++
		}
	} else if msgType == "contract_invocation" {
		if success {
			p.stats.ProcessedInvocations++
		} else {
			p.stats.FailedInvocations++
		}
	}
}

// GetStatus returns the operational status of the plugin
func (p *KaleMetricsPlugin) GetStatus() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"stats": map[string]interface{}{
			"processed_events":      p.stats.ProcessedEvents,
			"processed_invocations": p.stats.ProcessedInvocations,
			"failed_events":         p.stats.FailedEvents,
			"failed_invocations":    p.stats.FailedInvocations,
			"last_processed_time":   p.stats.LastProcessedTime,
		},
		"uptime":        time.Since(p.startTime).String(),
		"contract_id":   p.contractID,
		"metrics_count": len(p.processor.blockMetrics),
	}
}

// ProcessMessage processes a message from the flow processor (alias for Process)
func (p *KaleMetricsPlugin) ProcessMessage(ctx context.Context, msg pluginapi.Message) error {
	return p.Process(ctx, msg)
}

// Subscribe registers a consumer to receive metrics
func (p *KaleMetricsPlugin) Subscribe(consumer pluginapi.Processor) {
	p.processor.Subscribe(consumer)
}

// Unsubscribe removes a consumer
func (p *KaleMetricsPlugin) Unsubscribe(consumer pluginapi.Processor) {
	p.processor.Unsubscribe(consumer)
}

// Initialize initializes the plugin with the given configuration
func (p *KaleMetricsPlugin) Initialize(config map[string]interface{}) error {
	log.Printf("Initializing kale-metrics plugin with config: %+v", config)

	// Extract contract_id from configuration if provided
	if contractID, ok := config["contract_id"].(string); ok {
		p.contractID = contractID
		log.Printf("Set target contract ID to: %s", p.contractID)
	}

	return p.processor.Initialize(config)
}

// Init initializes the plugin
func (p *KaleMetricsPlugin) Init(ctx context.Context, config json.RawMessage) error {
	log.Printf("Initializing kale-metrics plugin")
	var configMap map[string]interface{}
	if err := json.Unmarshal(config, &configMap); err != nil {
		return NewProcessorError(
			fmt.Errorf("failed to unmarshal config: %w", err),
			ErrorTypeConfig,
			ErrorSeverityFatal,
		)
	}
	return p.Initialize(configMap)
}

// Close cleans up resources
func (p *KaleMetricsPlugin) Close() error {
	log.Printf("Closing kale-metrics plugin after running for %s", time.Since(p.startTime))
	return nil
}

// SchemaProvider returns whether the plugin implements the SchemaProvider interface
func (p *KaleMetricsPlugin) SchemaProvider() bool {
	return true
}

// RegisterConsumer registers a consumer to receive metrics
func (p *KaleMetricsPlugin) RegisterConsumer(consumer pluginapi.Consumer) {
	log.Printf("Registering consumer: %s", consumer.Name())
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consumers = append(p.consumers, consumer)

	// Forward existing metrics to the new consumer, if any
	if len(p.processor.blockMetrics) > 0 {
		go func() {
			ctx := context.Background()
			log.Printf("Forwarding existing metrics to newly registered consumer %s", consumer.Name())

			p.processor.mu.RLock()
			metrics := p.processor.GetAllBlockMetrics()
			p.processor.mu.RUnlock()

			for _, metric := range metrics {
				metricsJSON, err := json.Marshal(metric)
				if err != nil {
					log.Printf("Error marshaling metrics for block %d: %v", metric.BlockIndex, err)
					continue
				}

				msg := pluginapi.Message{
					Payload:   metricsJSON,
					Timestamp: time.Now(),
					Metadata: map[string]interface{}{
						"block_index": metric.BlockIndex,
						"type":        "kale_block_metrics",
					},
				}

				if err := consumer.Process(ctx, msg); err != nil {
					log.Printf("Error forwarding existing metrics for block %d to new consumer %s: %v",
						metric.BlockIndex, consumer.Name(), err)
				} else {
					log.Printf("Successfully forwarded existing metrics for block %d to new consumer %s",
						metric.BlockIndex, consumer.Name())
				}
			}
		}()
	}
}
