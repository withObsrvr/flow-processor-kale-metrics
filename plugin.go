package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
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
		// Extract the contractID to ensure we're dealing with the target contract
		contractID, _ := data["contract_id"].(string)
		if p.contractID != "" && contractID != p.contractID {
			return nil // Skip if not our target contract
		}

		// Check if we have function_name and it's a harvest function
		if functionName, ok := data["function_name"].(string); ok && functionName == "harvest" {
			// For harvest functions, try to find the Kale block index in the arguments
			if args, ok := data["arguments"].([]interface{}); ok && len(args) >= 2 {
				if arg, ok := args[1].(map[string]interface{}); ok {
					if u32Val, ok := arg["U32"].(float64); ok {
						// This is likely the Kale block index
						blockIndex := uint32(u32Val)
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
						return nil
					}
				}
			}
		}

		// For other events, check if block metrics were created by the processor
		// Get the latest block metrics that were updated
		blockIndices := p.processor.GetUpdatedBlockIndices()
		if len(blockIndices) > 0 {
			// Use the most recently updated block metrics
			latestIndex := blockIndices[len(blockIndices)-1]
			metrics, getErr := p.processor.GetBlockMetrics(latestIndex)
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
		// Extract the contractID to ensure we're dealing with the target contract
		contractID, _ := data["contract_id"].(string)
		if p.contractID != "" && contractID != p.contractID {
			return nil // Skip if not our target contract
		}

		// Get function name
		functionName, ok := data["function_name"].(string)
		if !ok {
			log.Printf("Function name not found in invocation data")
			return err
		}

		log.Printf("Processing %s function invocation for forwarding metrics", functionName)

		// For harvest function, extract block index from arguments
		if functionName == "harvest" {
			if args, ok := data["arguments"].([]interface{}); ok && len(args) >= 2 {
				if arg, ok := args[1].(map[string]interface{}); ok {
					if u32Val, ok := arg["U32"].(float64); ok {
						// This is likely the Kale block index
						blockIndex := uint32(u32Val)
						log.Printf("Using Kale block index %d from harvest arguments for forwarding metrics", blockIndex)

						// Get the metrics for this block and forward to plugin consumers
						metrics, getErr := p.processor.GetBlockMetrics(blockIndex)
						if getErr == nil && metrics != nil {
							p.mu.RLock()
							consumers := make([]pluginapi.Consumer, len(p.consumers))
							copy(consumers, p.consumers)
							p.mu.RUnlock()

							// Forward the metrics to plugin consumers with the correct Kale block index
							if forwardErr := p.processor.forwardToPluginConsumers(ctx, metrics, consumers); forwardErr != nil {
								log.Printf("Error forwarding metrics to plugin consumers: %v", forwardErr)
							}
						} else {
							log.Printf("No metrics found for Kale block index %d", blockIndex)
						}
						return nil
					}
				}
			}
		} else if functionName == "plant" {
			// For plant functions, we need to look in the transaction data for the Pail entries

			// Get or create metrics for the correct block index
			blockIndex, found := findPailBlockIndex(data)

			if found {
				log.Printf("Using Kale block index %d from 'plant' temporary data for forwarding metrics", blockIndex)

				// Get the metrics for this block and forward to plugin consumers
				metrics, getErr := p.processor.GetBlockMetrics(blockIndex)
				if getErr == nil && metrics != nil {
					p.mu.RLock()
					consumers := make([]pluginapi.Consumer, len(p.consumers))
					copy(consumers, p.consumers)
					p.mu.RUnlock()

					// Forward the metrics to plugin consumers with the correct Kale block index
					if forwardErr := p.processor.forwardToPluginConsumers(ctx, metrics, consumers); forwardErr != nil {
						log.Printf("Error forwarding metrics to plugin consumers: %v", forwardErr)
					}
				} else {
					log.Printf("No metrics found for Kale block index %d", blockIndex)
				}
				return nil
			} else {
				log.Printf("Could not find Pail block index in plant invocation data, dumping available fields")
				// Log the top-level fields to help debug
				for k := range data {
					log.Printf("  Field: %s", k)
				}
			}
		}

		// For other invocations or if we couldn't extract the block index from arguments,
		// check if block metrics were created by the processor
		blockIndices := p.processor.GetUpdatedBlockIndices()
		if len(blockIndices) > 0 {
			// Use the most recently updated block metrics
			latestIndex := blockIndices[len(blockIndices)-1]
			log.Printf("Using most recently updated block index %d for forwarding metrics", latestIndex)

			metrics, getErr := p.processor.GetBlockMetrics(latestIndex)
			if getErr == nil && metrics != nil {
				p.mu.RLock()
				consumers := make([]pluginapi.Consumer, len(p.consumers))
				copy(consumers, p.consumers)
				p.mu.RUnlock()

				// Forward the metrics to plugin consumers
				if forwardErr := p.processor.forwardToPluginConsumers(ctx, metrics, consumers); forwardErr != nil {
					log.Printf("Error forwarding metrics to plugin consumers: %v", forwardErr)
				}
			} else {
				log.Printf("No metrics found for block index %d", latestIndex)
			}
		} else {
			log.Printf("No updated block indices found, cannot forward metrics")
		}
	}

	return err
}

// extractBlockIndexFromChanges searches for block index in transaction changes
func extractBlockIndexFromChanges(changes []interface{}) (uint32, bool) {
	log.Printf("Searching for block index in %d changes", len(changes))

	for _, change := range changes {
		changeMap, ok := change.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for temporary entry with key containing "Pail"
		if entryType, ok := changeMap["type"].(string); ok && entryType == "temporary" {
			log.Printf("Found temporary entry: %+v", changeMap)

			// Look for key field
			if key, ok := changeMap["key"].(string); ok && strings.Contains(key, "Pail") {
				log.Printf("Found Pail key: %s", key)

				// Check for value field
				if valueData, ok := changeMap["value"].(map[string]interface{}); ok {
					// Try to extract from various formats
					if strVal, ok := valueData["String"].(string); ok {
						// Try to find a 5-digit number in the string
						re := regexp.MustCompile(`\b(\d{5})\b`)
						matches := re.FindStringSubmatch(strVal)
						if len(matches) > 1 {
							if num, err := strconv.ParseUint(matches[1], 10, 32); err == nil {
								log.Printf("Extracted block index %d from String value", num)
								return uint32(num), true
							}
						}
					} else if u32Val, ok := valueData["U32"].(float64); ok {
						log.Printf("Extracted block index %d from U32 value", uint32(u32Val))
						return uint32(u32Val), true
					} else if data, ok := valueData["Vec"].([]interface{}); ok && len(data) > 0 {
						log.Printf("Examining Vec data: %+v", data)

						// Look for a U32 value in the Vec elements
						for _, elem := range data {
							if elemMap, ok := elem.(map[string]interface{}); ok {
								if u32Val, ok := elemMap["U32"].(float64); ok {
									log.Printf("Extracted block index %d from Vec element", uint32(u32Val))
									return uint32(u32Val), true
								}
							}
						}
					}
				}
			}
		}

		// Look in ledger entry data
		if dataField, ok := changeMap["data"].(map[string]interface{}); ok {
			// Check if this is a LedgerEntry with Pail data
			if xdr, ok := dataField["xdr"].(string); ok && strings.Contains(xdr, "Pail") {
				log.Printf("Found Pail reference in ledger entry XDR: %s", xdr)

				// Try to extract a number that might be the block index
				re := regexp.MustCompile(`\b(\d{5})\b`) // Look for 5-digit numbers
				matches := re.FindStringSubmatch(xdr)
				if len(matches) > 1 {
					if num, err := strconv.ParseUint(matches[1], 10, 32); err == nil {
						log.Printf("Extracted block index %d from ledger entry", num)
						return uint32(num), true
					}
				}
			}
		}
	}

	return 0, false
}

// findPailBlockIndex attempts to find the Kale block index in Pail entries
func findPailBlockIndex(data map[string]interface{}) (uint32, bool) {
	log.Printf("Looking for Pail block index in data with %d top-level fields", len(data))

	// Display top-level fields for debugging
	for key, value := range data {
		log.Printf("Top-level field: %s (type: %T)", key, value)
	}

	// Check temporary_data field
	if tempData, ok := data["temporary_data"].([]interface{}); ok {
		log.Printf("Examining field temporary_data for Pail data")
		log.Printf("Found temporary data array with %d entries", len(tempData))

		for i, entry := range tempData {
			entryMap, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}

			log.Printf("Temporary data entry %d: %v", i, entryMap)

			if key, ok := entryMap["key"].(string); ok {
				log.Printf("Entry key: %s", key)

				if strings.Contains(key, "Pail") {
					log.Printf("Found Pail in temporary data key: %s", key)

					// Check for the Vec field which contains the block index as the third element
					var vecData map[string]interface{}
					if err := json.Unmarshal([]byte(key), &vecData); err == nil {
						if vec, ok := vecData["Vec"].([]interface{}); ok && len(vec) >= 3 {
							// The third element should have the block index
							if thirdElem, ok := vec[2].(map[string]interface{}); ok {
								if u32Val, ok := thirdElem["U32"].(float64); ok {
									log.Printf("Extracted block index from Vec[2].U32: %d", uint32(u32Val))
									return uint32(u32Val), true
								}
							}
						}
					}

					// If we reach here, we found Pail but couldn't extract index via direct JSON parsing
					// Try to find the U32 value using regex
					re := regexp.MustCompile(`"U32":(\d+)`)
					matches := re.FindStringSubmatch(key)
					if len(matches) > 1 {
						if val, err := strconv.ParseUint(matches[1], 10, 32); err == nil {
							log.Printf("Extracted block index from regex: %d", uint32(val))
							return uint32(val), true
						}
					}

					log.Printf("Examining value: %v", entryMap["value"])
				}
			}
		}
	}

	// Check tx_meta.changes field for temporary entries
	log.Printf("Examining temporary_data field for Pail data")
	if txMeta, ok := data["tx_meta"].(map[string]interface{}); ok {
		if changes, ok := txMeta["changes"].([]interface{}); ok {
			for _, change := range changes {
				if changeMap, ok := change.(map[string]interface{}); ok {
					if entryType, ok := changeMap["type"].(string); ok && entryType == "temporary" {
						if key, ok := changeMap["key"].(string); ok && strings.Contains(key, "Pail") {
							re := regexp.MustCompile(`"U32":(\d+)`)
							matches := re.FindStringSubmatch(key)
							if len(matches) > 1 {
								if val, err := strconv.ParseUint(matches[1], 10, 32); err == nil {
									log.Printf("Extracted block index from temporary entry: %d", uint32(val))
									return uint32(val), true
								}
							}
						}
					}
				}
			}
		}
	}

	// Check Operations.Changes for contract data with Pail
	if operations, ok := data["Operations"].([]interface{}); ok {
		for _, op := range operations {
			if opMap, ok := op.(map[string]interface{}); ok {
				if changes, ok := opMap["Changes"].([]interface{}); ok {
					for _, change := range changes {
						if changeMap, ok := change.(map[string]interface{}); ok {
							if state, ok := changeMap["State"].(map[string]interface{}); ok {
								if stateData, ok := state["Data"].(map[string]interface{}); ok {
									if contractData, ok := stateData["ContractData"].(map[string]interface{}); ok {
										if key, ok := contractData["Key"].(map[string]interface{}); ok {
											keyStr, _ := json.Marshal(key)
											if strings.Contains(string(keyStr), "Pail") {
												// Try to extract block index using regex
												re := regexp.MustCompile(`"U32":(\d+)`)
												matches := re.FindStringSubmatch(string(keyStr))
												if len(matches) > 1 {
													if val, err := strconv.ParseUint(matches[1], 10, 32); err == nil {
														log.Printf("Extracted block index from contract data: %d", uint32(val))
														return uint32(val), true
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Search for 'Pail' in the entire payload as a last resort
	if payload, err := json.Marshal(data); err == nil {
		log.Printf("Searching for 'Pail' in full payload of length %d", len(string(payload)))
		pailIndex := strings.Index(string(payload), "Pail")
		if pailIndex >= 0 {
			log.Printf("Found 'Pail' in payload at position %d", pailIndex)
			// Look for U32 values near the Pail string
			startPos := max(0, pailIndex-100)
			endPos := min(len(string(payload)), pailIndex+200)
			region := string(payload)[startPos:endPos]

			re := regexp.MustCompile(`"U32":(\d+)`)
			matches := re.FindAllStringSubmatch(region, -1)
			for _, match := range matches {
				if len(match) > 1 {
					if val, err := strconv.ParseUint(match[1], 10, 32); err == nil {
						// Only consider values that look like block indices (e.g., 5-digit numbers)
						if val > 10000 && val < 1000000 {
							log.Printf("Found potential block index from payload: %d", uint32(val))
							return uint32(val), true
						}
					}
				}
			}
		}
	}

	log.Printf("Failed to find Pail block index in any field")

	// Last resort - check function arguments directly
	if args, ok := data["arguments"].([]interface{}); ok && len(args) >= 2 {
		// Second argument is usually the block index in harvest calls
		argStr, _ := json.Marshal(args[1])
		re := regexp.MustCompile(`"U32":(\d+)`)
		matches := re.FindStringSubmatch(string(argStr))
		if len(matches) > 1 {
			if val, err := strconv.ParseUint(matches[1], 10, 32); err == nil {
				log.Printf("Extracted block index from function argument: %d", uint32(val))
				return uint32(val), true
			}
		}
	}

	// Dump available fields for debugging
	log.Printf("Could not find Pail block index in plant invocation data, dumping available fields")
	for key := range data {
		log.Printf("  Field: %s", key)
	}

	return 0, false
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
