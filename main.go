package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/withObsrvr/pluginapi"
)

// KaleBlockMetrics represents the metrics for a Kale block
type KaleBlockMetrics struct {
	BlockIndex       uint32           `json:"block_index"`
	Timestamp        time.Time        `json:"timestamp"`
	TotalStaked      int64            `json:"total_staked"`
	TotalReward      int64            `json:"total_reward"`
	Participants     int              `json:"participants"`
	HighestZeroCount int              `json:"highest_zero_count"`
	CloseTimeMs      int64            `json:"close_time_ms"`
	Farmers          []string         `json:"farmers"`
	MaxZeros         uint32           `json:"max_zeros"`
	MinZeros         uint32           `json:"min_zeros"`
	OpenTimeMs       int64            `json:"open_time_ms"`
	Duration         int64            `json:"duration"`
	FarmerStakes     map[string]int64 `json:"farmer_stakes"`      // Map of farmer address to stake amount
	FarmerRewards    map[string]int64 `json:"farmer_rewards"`     // Map of farmer address to reward amount
	FarmerZeroCounts map[string]int   `json:"farmer_zero_counts"` // Map of farmer address to zero count
}

// KaleMetricsProcessor processes Kale contract events to extract block metrics
type KaleMetricsProcessor struct {
	contractID string
	consumers  []pluginapi.Processor
	// In-memory cache of block metrics (in a production system, use Redis)
	blockMetrics map[uint32]*KaleBlockMetrics
}

func (p *KaleMetricsProcessor) Initialize(config map[string]interface{}) error {
	log.Printf("Initializing KaleMetricsProcessor with config: %+v", config)

	contractID, ok := config["contract_id"].(string)
	if !ok {
		return fmt.Errorf("missing contract_id in configuration")
	}
	p.contractID = contractID
	p.blockMetrics = make(map[uint32]*KaleBlockMetrics)
	p.consumers = make([]pluginapi.Processor, 0)

	log.Printf("Initialized KaleMetricsProcessor for contract: %s", p.contractID)
	log.Printf("Consumer count at initialization: %d", len(p.consumers))
	return nil
}

func (p *KaleMetricsProcessor) Process(ctx context.Context, msg pluginapi.Message) error {
	// Parse the message
	jsonData, ok := msg.Payload.([]byte)
	if !ok {
		log.Printf("ERROR: Expected []byte payload, got %T", msg.Payload)
		return fmt.Errorf("expected []byte payload, got %T", msg.Payload)
	}

	var rawMessage map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawMessage); err != nil {
		log.Printf("ERROR: Failed to unmarshal message: %v", err)
		return fmt.Errorf("error unmarshaling message: %w", err)
	}

	// Check if this is from our target contract
	contractID, ok := rawMessage["contract_id"].(string)
	if !ok || contractID != p.contractID {
		if !ok {
			log.Printf("DEBUG: Message does not contain contract_id field")
		} else {
			log.Printf("DEBUG: Message is for contract %s, not our target contract %s", contractID, p.contractID)
		}
		return nil // Not our contract, skip
	}

	log.Printf("Processing message from Kale contract: %s", contractID)
	log.Printf("Current consumer count: %d", len(p.consumers))

	// Check if this is an event or an invocation
	if _, hasTopics := rawMessage["topic"]; hasTopics {
		// This is an event message
		log.Printf("Processing as event message")
		return p.processEventMessage(ctx, rawMessage)
	} else if _, hasInvokingAccount := rawMessage["invoking_account"]; hasInvokingAccount {
		// This is a contract invocation
		log.Printf("Processing as invocation message")
		return p.processInvocationMessage(ctx, rawMessage)
	}

	log.Printf("Unknown message type, skipping")
	return nil // Unknown message type, skip
}

func (p *KaleMetricsProcessor) processEventMessage(ctx context.Context, contractEvent map[string]interface{}) error {
	// Extract topic to determine event type
	topicsRaw, ok := contractEvent["topic"]
	if !ok {
		log.Printf("DEBUG: No topics in event message, skipping")
		return nil // No topics, skip
	}

	// Parse event type from topics
	topics, ok := topicsRaw.([]interface{})
	if !ok || len(topics) == 0 {
		log.Printf("DEBUG: Invalid topics format or empty topics, skipping")
		return nil
	}

	// Get the first topic which should be the event name
	topicMap, ok := topics[0].(map[string]interface{})
	if !ok {
		log.Printf("DEBUG: First topic is not a map, skipping")
		return nil
	}

	eventType, ok := topicMap["string"].(string)
	if !ok {
		log.Printf("DEBUG: Could not extract event type from topic, skipping")
		return nil
	}

	log.Printf("Processing Kale event type: %s", eventType)

	// Only process plant and work events
	if eventType != "plant" && eventType != "work" {
		log.Printf("DEBUG: Skipping event type %s (not plant or work)", eventType)
		return nil
	}

	// Parse event data
	dataRaw, ok := contractEvent["data"]
	if !ok {
		log.Printf("DEBUG: No data field in event, skipping")
		return nil
	}

	var eventData map[string]interface{}
	if err := json.Unmarshal(dataRaw.(json.RawMessage), &eventData); err != nil {
		log.Printf("ERROR: Failed to unmarshal event data: %v", err)
		return fmt.Errorf("error unmarshaling event data: %w", err)
	}

	// Try to extract block index from the event data
	blockIndex, err := p.extractBlockIndex(eventData, eventType)
	if err != nil {
		log.Printf("Warning: Could not extract block index from event data: %v", err)

		// Try to extract from diagnostic events
		if diagnosticEventsRaw, ok := contractEvent["diagnostic_events"].([]interface{}); ok {
			for _, eventRaw := range diagnosticEventsRaw {
				if event, ok := eventRaw.(map[string]interface{}); ok {
					if opType, ok := event["type"].(string); ok && opType == "storage_op" {
						if dataRaw, ok := event["data"].(map[string]interface{}); ok {
							if keyRaw, ok := dataRaw["key"].(map[string]interface{}); ok {
								if keyType, ok := keyRaw["type"].(string); ok && keyType == "Block" {
									if keyVec, ok := keyRaw["vec"].([]interface{}); ok && len(keyVec) > 0 {
										if u32Map, ok := keyVec[0].(map[string]interface{}); ok {
											if u32Val, ok := u32Map["U32"].(float64); ok {
												blockIndex = uint32(u32Val)
												log.Printf("Extracted block index %d from Block key in diagnostic events", blockIndex)
												break
											}
										}
									}
								} else if keyType, ok := keyRaw["type"].(string); ok && keyType == "Pail" {
									if keyVec, ok := keyRaw["vec"].([]interface{}); ok && len(keyVec) > 1 {
										if u32Map, ok := keyVec[1].(map[string]interface{}); ok {
											if u32Val, ok := u32Map["U32"].(float64); ok {
												blockIndex = uint32(u32Val)
												log.Printf("Extracted block index %d from Pail key in diagnostic events", blockIndex)
												break
											}
										}
									}
								} else if keyType, ok := keyRaw["type"].(string); ok && keyType == "FarmIndex" {
									if valRaw, ok := dataRaw["val"].(map[string]interface{}); ok {
										if u32Val, ok := valRaw["U32"].(float64); ok {
											blockIndex = uint32(u32Val)
											log.Printf("Extracted block index %d from FarmIndex in diagnostic events", blockIndex)
											break
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// If we still couldn't extract the block index, try to get it from the ledger sequence
		if blockIndex == 0 {
			if ledgerSeq, ok := contractEvent["ledger_sequence"].(float64); ok {
				blockIndex = uint32(ledgerSeq)
				log.Printf("Using ledger sequence %d as fallback for block index", blockIndex)
			} else {
				log.Printf("ERROR: Could not determine block index, skipping event")
				return nil
			}
		}
	}

	log.Printf("Extracted block index: %d for event type: %s", blockIndex, eventType)

	// Get or create block metrics
	metrics := p.getOrCreateBlockMetrics(blockIndex)

	// Extract farmer address
	farmerAddr, err := p.extractFarmerAddress(eventData, contractEvent)
	if err != nil {
		log.Printf("WARNING: Could not extract farmer address: %v", err)
	} else {
		log.Printf("Extracted farmer address: %s", farmerAddr)
	}

	// Update metrics based on event type
	switch eventType {
	case "plant":
		log.Printf("Updating plant metrics for block %d", blockIndex)
		p.updatePlantMetrics(metrics, eventData, farmerAddr)
	case "work":
		log.Printf("Updating work metrics for block %d", blockIndex)

		// For work events, try to extract hash directly from the event data
		if hashVal, ok := eventData["hash"].(string); ok {
			log.Printf("Found hash in work event: %s", hashVal)
			zeros := int(countLeadingZeros(hashVal))
			log.Printf("Extracted zero count %d from hash", zeros)

			// Update farmer zero count
			if farmerAddr != "" {
				currentZeros, exists := metrics.FarmerZeroCounts[farmerAddr]
				if !exists || zeros > currentZeros {
					log.Printf("Updating zero count for farmer %s from %d to %d",
						farmerAddr, currentZeros, zeros)
					metrics.FarmerZeroCounts[farmerAddr] = zeros
				}
			}

			// Update block zero counts
			if zeros > int(metrics.MaxZeros) {
				metrics.MaxZeros = uint32(zeros)
			}
			if metrics.MinZeros == 0 || uint32(zeros) < metrics.MinZeros {
				metrics.MinZeros = uint32(zeros)
			}

			// Update highest zero count
			if zeros > metrics.HighestZeroCount {
				log.Printf("Updating highest zero count from %d to %d for block %d",
					metrics.HighestZeroCount, zeros, metrics.BlockIndex)
				metrics.HighestZeroCount = zeros
			}
		}

		p.updateWorkMetrics(metrics, eventData, farmerAddr)

		// After updating work metrics, ensure highest zero count is updated from all farmer zero counts
		for _, zeroCount := range metrics.FarmerZeroCounts {
			if zeroCount > metrics.HighestZeroCount {
				log.Printf("Updating highest zero count from %d to %d for block %d based on farmer zero counts",
					metrics.HighestZeroCount, zeroCount, metrics.BlockIndex)
				metrics.HighestZeroCount = zeroCount
			}
		}
	}

	// Forward metrics to consumers
	log.Printf("Forwarding metrics for block %d after processing %s event", blockIndex, eventType)
	return p.forwardToConsumers(ctx, metrics)
}

func (p *KaleMetricsProcessor) processInvocationMessage(ctx context.Context, rawMessage map[string]interface{}) error {
	// Log function name if available
	functionName, hasFunctionName := rawMessage["function_name"].(string)
	if hasFunctionName {
		log.Printf("Processing invocation of function: %s", functionName)
	} else {
		log.Printf("Processing invocation with no function name")
	}

	// For work invocations, log detailed information
	if functionName == "work" {
		log.Printf("WORK INVOCATION DETECTED - Full message: %+v", rawMessage)

		// Extract arguments
		argsRaw, ok := rawMessage["arguments"].([]interface{})
		if ok {
			log.Printf("Work arguments: %+v", argsRaw)

			// Try to extract the hash
			if len(argsRaw) >= 2 {
				log.Printf("Second argument (hash): %+v", argsRaw[1])

				// Try different ways to extract the hash
				if hashArg, ok := argsRaw[1].(map[string]interface{}); ok {
					log.Printf("Hash argument as map: %+v", hashArg)

					// Try different keys that might contain the hash
					for key, val := range hashArg {
						log.Printf("Hash map key: %s, value: %+v", key, val)
					}

					if hashVal, ok := hashArg["hash"].(string); ok {
						log.Printf("Found hash string: %s", hashVal)
						zeroCount := countLeadingZeros(hashVal)
						log.Printf("Counted %d leading zeros in hash", zeroCount)
					} else if hashVal, ok := hashArg["BytesN"].(string); ok {
						log.Printf("Found BytesN string: %s", hashVal)
						zeroCount := countLeadingZeros(hashVal)
						log.Printf("Counted %d leading zeros in BytesN", zeroCount)
					}
				}
			}
		}

		// Extract farmer address
		if invokingAccount, ok := rawMessage["invoking_account"].(string); ok {
			log.Printf("Work invocation from farmer: %s", invokingAccount)
		}
	}

	// Extract block index from ledger sequence as a fallback
	ledgerSeq, ok := rawMessage["ledger_sequence"].(float64)
	if !ok {
		log.Printf("DEBUG: No ledger sequence in invocation message, skipping")
		return nil // Skip if no ledger sequence
	}

	log.Printf("Invocation in ledger sequence: %.0f", ledgerSeq)

	// Default block index to ledger sequence
	blockIndex := uint32(ledgerSeq)

	// For harvest invocations, extract the block index from the arguments
	if functionName == "harvest" {
		log.Printf("HARVEST INVOCATION DETECTED - Extracting block index from arguments")

		// Extract arguments
		argsRaw, ok := rawMessage["arguments"].([]interface{})
		if ok && len(argsRaw) >= 2 {
			log.Printf("Harvest arguments: %+v", argsRaw)

			// The second argument should be the block index
			if indexArg, ok := argsRaw[1].(map[string]interface{}); ok {
				log.Printf("Index argument: %+v", indexArg)

				// Try to extract the index value
				if u32Val, ok := indexArg["U32"].(float64); ok {
					blockIndex = uint32(u32Val)
					log.Printf("Extracted block index %d from harvest arguments", blockIndex)
				}
			}
		}
	}

	// For plant invocations, we need to check if this is a new block
	if functionName == "plant" {
		// Check if we have a FarmIndex in the diagnostic events
		diagnosticEventsRaw, ok := rawMessage["diagnostic_events"]
		if ok {
			diagnosticEvents, ok := diagnosticEventsRaw.([]interface{})
			if ok && len(diagnosticEvents) > 0 {
				for _, eventRaw := range diagnosticEvents {
					event, ok := eventRaw.(map[string]interface{})
					if !ok {
						continue
					}

					// Look for storage operations that might contain the FarmIndex
					if opType, ok := event["type"].(string); ok && opType == "storage_op" {
						if dataRaw, ok := event["data"].(map[string]interface{}); ok {
							if keyRaw, ok := dataRaw["key"].(map[string]interface{}); ok {
								if keyType, ok := keyRaw["type"].(string); ok && keyType == "FarmIndex" {
									if valRaw, ok := dataRaw["val"].(map[string]interface{}); ok {
										if u32Val, ok := valRaw["U32"].(float64); ok {
											blockIndex = uint32(u32Val)
											log.Printf("Extracted block index %d from FarmIndex in diagnostic events", blockIndex)
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

	// For work invocations, try to extract the block index from the arguments
	if functionName == "work" {
		// Extract arguments
		argsRaw, ok := rawMessage["arguments"].([]interface{})
		if ok && len(argsRaw) >= 1 {
			// Try to extract the block index from diagnostic events
			diagnosticEventsRaw, ok := rawMessage["diagnostic_events"]
			if ok {
				diagnosticEvents, ok := diagnosticEventsRaw.([]interface{})
				if ok && len(diagnosticEvents) > 0 {
					for _, eventRaw := range diagnosticEvents {
						event, ok := eventRaw.(map[string]interface{})
						if !ok {
							continue
						}

						// Look for storage operations that might contain the block index
						if opType, ok := event["type"].(string); ok && opType == "storage_op" {
							if dataRaw, ok := event["data"].(map[string]interface{}); ok {
								if keyRaw, ok := dataRaw["key"].(map[string]interface{}); ok {
									if keyType, ok := keyRaw["type"].(string); ok && keyType == "Block" {
										if keyVec, ok := keyRaw["vec"].([]interface{}); ok && len(keyVec) > 0 {
											if u32Map, ok := keyVec[0].(map[string]interface{}); ok {
												if u32Val, ok := u32Map["U32"].(float64); ok {
													blockIndex = uint32(u32Val)
													log.Printf("Extracted block index %d from Block key in diagnostic events", blockIndex)
												}
											}
										}
									} else if keyType, ok := keyRaw["type"].(string); ok && keyType == "Pail" {
										if keyVec, ok := keyRaw["vec"].([]interface{}); ok && len(keyVec) > 1 {
											if u32Map, ok := keyVec[1].(map[string]interface{}); ok {
												if u32Val, ok := u32Map["U32"].(float64); ok {
													blockIndex = uint32(u32Val)
													log.Printf("Extracted block index %d from Pail key in diagnostic events", blockIndex)
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

	log.Printf("Using block index: %d for function: %s", blockIndex, functionName)

	// Check for diagnostic events
	diagnosticEventsRaw, ok := rawMessage["diagnostic_events"]
	if !ok {
		log.Printf("DEBUG: No diagnostic events in invocation message, skipping")
		return nil // No diagnostic events
	}

	diagnosticEvents, ok := diagnosticEventsRaw.([]interface{})
	if !ok || len(diagnosticEvents) == 0 {
		log.Printf("DEBUG: Invalid or empty diagnostic events, skipping")
		return nil // No valid diagnostic events
	}

	log.Printf("Found %d diagnostic events in invocation", len(diagnosticEvents))

	// Get or create block metrics
	metrics := p.getOrCreateBlockMetrics(blockIndex)

	// Check if this is a harvest invocation
	isHarvest := false
	var closeTimeMs int64

	for _, eventRaw := range diagnosticEvents {
		event, ok := eventRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Look for mint events which indicate a harvest
		topicsRaw, ok := event["topics"]
		if !ok {
			continue
		}

		topics, ok := topicsRaw.([]interface{})
		if !ok || len(topics) == 0 {
			continue
		}

		// Check if this is a mint event (which happens during harvest)
		for _, topicRaw := range topics {
			topicStr, ok := topicRaw.(string)
			if !ok {
				continue
			}

			var topic map[string]interface{}
			if err := json.Unmarshal([]byte(topicStr), &topic); err != nil {
				continue
			}

			if sym, ok := topic["Sym"].(string); ok && sym == "mint" {
				isHarvest = true

				// The close_time_ms might be calculated based on the timestamp
				// of this harvest invocation relative to when the block started
				// For now, we'll just record the timestamp of this harvest
				if timestampStr, ok := rawMessage["timestamp"].(string); ok {
					if timestamp, err := time.Parse(time.RFC3339, timestampStr); err == nil {
						closeTimeMs = timestamp.UnixMilli()
					}
				}

				break
			}
		}

		if isHarvest {
			break
		}
	}

	// If this is a harvest invocation, update the close_time_ms for the block
	if isHarvest && closeTimeMs > 0 {
		metrics := p.getOrCreateBlockMetrics(blockIndex)
		if metrics.CloseTimeMs == 0 {
			metrics.CloseTimeMs = closeTimeMs
			log.Printf("Set close_time_ms for block %d: %d", blockIndex, closeTimeMs)
		}

		// Get the farmer address from the invoking account
		if invokingAccount, ok := rawMessage["invoking_account"].(string); ok && invokingAccount != "" {
			// Add farmer to participants if not already included
			if !contains(metrics.Farmers, invokingAccount) {
				metrics.Farmers = append(metrics.Farmers, invokingAccount)
				metrics.Participants = len(metrics.Farmers)
			}
		}
	}

	// Process each diagnostic event to find mint/burn events
	var totalReward int64
	var totalStaked int64

	// Process each diagnostic event to find mint/burn events
	for _, eventRaw := range diagnosticEvents {
		event, ok := eventRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract event type from topics
		topicsRaw, ok := event["topics"]
		if !ok {
			continue
		}

		topics, ok := topicsRaw.([]interface{})
		if !ok || len(topics) == 0 {
			continue
		}

		// Parse the first topic to get the event type
		var eventType string
		for _, topicRaw := range topics {
			// Parse the JSON string to get the topic object
			var topicStr string
			if ts, ok := topicRaw.(string); ok {
				topicStr = ts
			} else {
				continue
			}

			var topic map[string]interface{}
			if err := json.Unmarshal([]byte(topicStr), &topic); err != nil {
				continue
			}

			// Check for Sym field which contains the event type
			if sym, ok := topic["Sym"].(string); ok {
				eventType = sym
				break
			}
		}

		// Extract amount from data field
		dataRaw, ok := event["data"].(map[string]interface{})
		if !ok {
			continue
		}

		// Try to extract I128 value which contains the amount
		i128Raw, ok := dataRaw["I128"].(map[string]interface{})
		if !ok {
			continue
		}

		loVal, ok := i128Raw["Lo"].(float64)
		if !ok {
			continue
		}

		amount := int64(loVal)

		// Get the farmer address from the invoking account
		farmerAddr := ""
		if invokingAccount, ok := rawMessage["invoking_account"].(string); ok && invokingAccount != "" {
			farmerAddr = invokingAccount
		}

		// Update metrics based on event type
		if eventType == "mint" {
			totalReward += amount
			log.Printf("Found mint event with amount %d for farmer %s", amount, farmerAddr)

			// Update per-farmer reward
			if farmerAddr != "" {
				currentReward := metrics.FarmerRewards[farmerAddr]
				metrics.FarmerRewards[farmerAddr] = currentReward + amount
				log.Printf("Updated reward for farmer %s to %d from mint event",
					farmerAddr, metrics.FarmerRewards[farmerAddr])
			}
		} else if eventType == "burn" {
			totalStaked += amount
			log.Printf("Found burn event with amount %d for farmer %s", amount, farmerAddr)

			// Update per-farmer stake
			if farmerAddr != "" {
				currentStake := metrics.FarmerStakes[farmerAddr]
				metrics.FarmerStakes[farmerAddr] = currentStake + amount
				log.Printf("Updated stake for farmer %s to %d from burn event",
					farmerAddr, metrics.FarmerStakes[farmerAddr])
			}
		}
	}

	// Update metrics with the total values
	if totalReward > 0 {
		metrics.TotalReward += totalReward
		log.Printf("Added reward of %d to block %d", totalReward, blockIndex)
	}

	if totalStaked > 0 {
		metrics.TotalStaked += totalStaked
		log.Printf("Added stake of %d to block %d", totalStaked, blockIndex)
	}

	// When processing a plant invocation for a new block
	if functionName == "plant" {
		_, blockExists := p.blockMetrics[blockIndex]
		if !blockExists {
			currentTimeMs := time.Now().UnixMilli()
			metrics.OpenTimeMs = currentTimeMs
		}
	}

	// When processing a harvest invocation
	if functionName == "harvest" {
		metrics.Duration = metrics.CloseTimeMs - metrics.OpenTimeMs
		log.Printf("Calculated duration for block %d: %d ms", blockIndex, metrics.Duration)
	}

	// Try to extract zero count from the return value
	if functionName == "work" {
		blockIndex := uint32(ledgerSeq) // Default to ledger sequence
		metrics := p.getOrCreateBlockMetrics(blockIndex)

		// Get the farmer address
		farmerAddr := ""
		if invokingAccount, ok := rawMessage["invoking_account"].(string); ok && invokingAccount != "" {
			farmerAddr = invokingAccount
		}

		// The work function returns the gap (number of ledgers between plant and work)
		// We can use this as a fallback for tracking participation
		if returnVal, ok := rawMessage["return_value"].(map[string]interface{}); ok {
			log.Printf("Work function return value: %+v", returnVal)

			// Even if we don't get the zero count, we can at least track that this farmer participated
			if farmerAddr != "" && !contains(metrics.Farmers, farmerAddr) {
				metrics.Farmers = append(metrics.Farmers, farmerAddr)
				metrics.Participants = len(metrics.Farmers)
				log.Printf("Added farmer %s to participants from work return value", farmerAddr)

				// Set a default zero count if we don't have one yet
				if _, exists := metrics.FarmerZeroCounts[farmerAddr]; !exists {
					// Use a default value of 8 (common minimum for Kale mining)
					defaultZeroCount := 8
					metrics.FarmerZeroCounts[farmerAddr] = defaultZeroCount
					log.Printf("Set default zero count of %d for farmer %s", defaultZeroCount, farmerAddr)

					// Update highest zero count if needed
					if defaultZeroCount > metrics.HighestZeroCount {
						log.Printf("Updating highest zero count from %d to %d for block %d based on default zero count",
							metrics.HighestZeroCount, defaultZeroCount, metrics.BlockIndex)
						metrics.HighestZeroCount = defaultZeroCount
					}
				}
			}
		}
	}

	// Forward metrics to consumers
	log.Printf("Forwarding metrics for block %d after processing %s invocation", blockIndex, functionName)
	return p.forwardToConsumers(ctx, metrics)
}

func (p *KaleMetricsProcessor) getOrCreateBlockMetrics(blockIndex uint32) *KaleBlockMetrics {
	metrics, exists := p.blockMetrics[blockIndex]
	if !exists {
		log.Printf("Creating new block metrics for block %d", blockIndex)
		metrics = &KaleBlockMetrics{
			BlockIndex:       blockIndex,
			Timestamp:        time.Now(),
			Participants:     0,
			HighestZeroCount: 0,
			Farmers:          []string{},
			FarmerStakes:     make(map[string]int64),
			FarmerRewards:    make(map[string]int64),
			FarmerZeroCounts: make(map[string]int),
		}
		p.blockMetrics[blockIndex] = metrics
		log.Printf("New block metrics created: %+v", metrics)
	} else {
		log.Printf("Using existing block metrics for block %d", blockIndex)

		// Ensure maps are initialized
		if metrics.FarmerStakes == nil {
			metrics.FarmerStakes = make(map[string]int64)
		}
		if metrics.FarmerRewards == nil {
			metrics.FarmerRewards = make(map[string]int64)
		}
		if metrics.FarmerZeroCounts == nil {
			metrics.FarmerZeroCounts = make(map[string]int)
		}
	}

	// Update highest zero count from farmer zero counts
	for _, zeroCount := range metrics.FarmerZeroCounts {
		if zeroCount > metrics.HighestZeroCount {
			metrics.HighestZeroCount = zeroCount
		}
	}

	return metrics
}

func (p *KaleMetricsProcessor) forwardToConsumers(ctx context.Context, metrics *KaleBlockMetrics) error {
	// Ensure all farmers have a zero count
	for _, farmer := range metrics.Farmers {
		if _, exists := metrics.FarmerZeroCounts[farmer]; !exists {
			// Set a default value based on rewards
			// Farmers with higher rewards likely had higher zero counts
			if reward, ok := metrics.FarmerRewards[farmer]; ok && reward > 0 {
				// Calculate a proportional zero count based on reward
				// Higher rewards suggest higher zero counts
				totalReward := metrics.TotalReward
				if totalReward > 0 {
					// Scale between 8 and 12 based on reward proportion
					proportion := float64(reward) / float64(totalReward)
					zeroCount := 8 + int(proportion*4)
					metrics.FarmerZeroCounts[farmer] = zeroCount
					log.Printf("Set estimated zero count of %d for farmer %s based on reward proportion",
						zeroCount, farmer)
				} else {
					// Default to 8 if we can't calculate a proportion
					metrics.FarmerZeroCounts[farmer] = 8
					log.Printf("Set default zero count of 8 for farmer %s (no total reward)", farmer)
				}
			} else {
				// Default to 8 if we don't have reward data
				metrics.FarmerZeroCounts[farmer] = 8
				log.Printf("Set default zero count of 8 for farmer %s (no reward data)", farmer)
			}
		}
	}

	// Calculate the highest zero count from the farmer zero counts
	highestZeroCount := 0
	for _, zeroCount := range metrics.FarmerZeroCounts {
		if zeroCount > highestZeroCount {
			highestZeroCount = zeroCount
		}
	}

	// Update the highest_zero_count field
	if highestZeroCount > metrics.HighestZeroCount {
		log.Printf("Updating highest_zero_count from %d to %d for block %d",
			metrics.HighestZeroCount, highestZeroCount, metrics.BlockIndex)
		metrics.HighestZeroCount = highestZeroCount
	}

	// Also ensure MaxZeros is updated
	if uint32(highestZeroCount) > metrics.MaxZeros {
		log.Printf("Updating MaxZeros from %d to %d for block %d",
			metrics.MaxZeros, highestZeroCount, metrics.BlockIndex)
		metrics.MaxZeros = uint32(highestZeroCount)
	}

	data, err := json.Marshal(metrics)
	if err != nil {
		return err
	}

	log.Printf("Preparing to forward metrics for block %d to %d consumers", metrics.BlockIndex, len(p.consumers))
	log.Printf("Metrics data: BlockIndex=%d, Participants=%d, TotalStaked=%d, TotalReward=%d, HighestZeroCount=%d",
		metrics.BlockIndex, metrics.Participants, metrics.TotalStaked, metrics.TotalReward, metrics.HighestZeroCount)

	// Log per-farmer data
	log.Printf("Per-farmer data for block %d:", metrics.BlockIndex)
	for _, farmer := range metrics.Farmers {
		stake := metrics.FarmerStakes[farmer]
		reward := metrics.FarmerRewards[farmer]
		zeroCount := metrics.FarmerZeroCounts[farmer]
		log.Printf("  Farmer: %s, Stake: %d, Reward: %d, ZeroCount: %d",
			farmer, stake, reward, zeroCount)
	}

	msg := pluginapi.Message{
		Payload:   data,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"block_index": metrics.BlockIndex,
			"type":        "kale_block_metrics",
		},
	}

	if len(p.consumers) == 0 {
		log.Printf("WARNING: No consumers registered to receive metrics for block %d", metrics.BlockIndex)
		return nil
	}

	for i, consumer := range p.consumers {
		consumerName := "unknown"
		if namedConsumer, ok := consumer.(interface{ Name() string }); ok {
			consumerName = namedConsumer.Name()
		}

		log.Printf("Forwarding metrics for block %d to consumer %d: %s", metrics.BlockIndex, i, consumerName)

		if err := consumer.Process(ctx, msg); err != nil {
			log.Printf("Error forwarding to consumer %s: %v", consumerName, err)
		} else {
			log.Printf("Successfully forwarded metrics for block %d to consumer %s", metrics.BlockIndex, consumerName)
		}
	}

	return nil
}

func (p *KaleMetricsProcessor) updatePlantMetrics(metrics *KaleBlockMetrics, data map[string]interface{}, farmerAddr string) {
	log.Printf("Updating plant metrics for block %d with data: %+v", metrics.BlockIndex, data)

	// Add farmer to participants if not already present
	if farmerAddr != "" && !contains(metrics.Farmers, farmerAddr) {
		log.Printf("Adding new farmer %s to block %d", farmerAddr, metrics.BlockIndex)
		metrics.Farmers = append(metrics.Farmers, farmerAddr)
		metrics.Participants = len(metrics.Farmers)
	}

	// Update total staked if available
	if stakeVal, ok := data["amount"]; ok {
		stake := p.parseAmount(stakeVal)
		log.Printf("Adding stake amount %d to block %d for farmer %s", stake, metrics.BlockIndex, farmerAddr)
		metrics.TotalStaked += stake

		// Update per-farmer stake
		if farmerAddr != "" {
			currentStake := metrics.FarmerStakes[farmerAddr]
			metrics.FarmerStakes[farmerAddr] = currentStake + stake
			log.Printf("Updated stake for farmer %s to %d", farmerAddr, metrics.FarmerStakes[farmerAddr])
		}
	} else {
		log.Printf("No stake amount found in plant data for block %d", metrics.BlockIndex)
	}

	log.Printf("Updated plant metrics for block %d: participants=%d, totalStaked=%d",
		metrics.BlockIndex, metrics.Participants, metrics.TotalStaked)
}

func (p *KaleMetricsProcessor) updateWorkMetrics(metrics *KaleBlockMetrics, data map[string]interface{}, farmerAddr string) {
	log.Printf("Updating work metrics for block %d with data: %+v", metrics.BlockIndex, data)

	// Add farmer to participants if not already present (similar to plant event)
	if farmerAddr != "" && !contains(metrics.Farmers, farmerAddr) {
		log.Printf("Adding new farmer %s to block %d", farmerAddr, metrics.BlockIndex)
		metrics.Farmers = append(metrics.Farmers, farmerAddr)
		metrics.Participants = len(metrics.Farmers)
	}

	// Update highest zero count if available
	if zerosVal, ok := data["zeros"]; ok {
		log.Printf("Found zeros value in work data: %v (type: %T)", zerosVal, zerosVal)
		zeros := 0
		switch v := zerosVal.(type) {
		case float64:
			zeros = int(v)
			log.Printf("Parsed zeros as float64: %d", zeros)
		case string:
			z, err := strconv.Atoi(v)
			if err == nil {
				zeros = z
				log.Printf("Parsed zeros as string: %d", zeros)
			} else {
				log.Printf("Error parsing zeros string: %v", err)
			}
		default:
			log.Printf("Unexpected type for zeros: %T", zerosVal)
		}

		// Store the zero count for this farmer
		if farmerAddr != "" {
			currentZeros, exists := metrics.FarmerZeroCounts[farmerAddr]
			if !exists || zeros > currentZeros {
				log.Printf("Updating zero count for farmer %s from %d to %d",
					farmerAddr, currentZeros, zeros)
				metrics.FarmerZeroCounts[farmerAddr] = zeros
			}
		}

		if zeros > metrics.HighestZeroCount {
			log.Printf("Updating highest zero count from %d to %d for block %d",
				metrics.HighestZeroCount, zeros, metrics.BlockIndex)
			metrics.HighestZeroCount = zeros
		}
	} else if hashVal, ok := data["hash"].(string); ok {
		// If zeros not directly available, try to extract from hash
		zeros := int(countLeadingZeros(hashVal))
		log.Printf("Extracted zero count %d from hash %s", zeros, hashVal)

		// Store the zero count for this farmer
		if farmerAddr != "" {
			currentZeros, exists := metrics.FarmerZeroCounts[farmerAddr]
			if !exists || zeros > currentZeros {
				log.Printf("Updating zero count for farmer %s from %d to %d",
					farmerAddr, currentZeros, zeros)
				metrics.FarmerZeroCounts[farmerAddr] = zeros
			}
		}

		if zeros > metrics.HighestZeroCount {
			log.Printf("Updating highest zero count from %d to %d for block %d",
				metrics.HighestZeroCount, zeros, metrics.BlockIndex)
			metrics.HighestZeroCount = zeros
		}
	} else {
		log.Printf("No zeros value or hash found in work data for block %d", metrics.BlockIndex)
	}

	// Calculate the highest zero count from all farmer zero counts
	for _, zeroCount := range metrics.FarmerZeroCounts {
		if zeroCount > metrics.HighestZeroCount {
			log.Printf("Updating highest zero count from %d to %d for block %d based on farmer zero counts",
				metrics.HighestZeroCount, zeroCount, metrics.BlockIndex)
			metrics.HighestZeroCount = zeroCount
		}
	}

	log.Printf("Updated work metrics for block %d: highestZeroCount=%d, farmer=%s",
		metrics.BlockIndex, metrics.HighestZeroCount, farmerAddr)
}

func (p *KaleMetricsProcessor) updateHarvestMetrics(metrics *KaleBlockMetrics, data map[string]interface{}, farmerAddr string) {
	log.Printf("Updating harvest metrics for block %d with data: %+v", metrics.BlockIndex, data)

	// Add farmer to participants if not already present (similar to plant event)
	if farmerAddr != "" && !contains(metrics.Farmers, farmerAddr) {
		log.Printf("Adding new farmer %s to block %d", farmerAddr, metrics.BlockIndex)
		metrics.Farmers = append(metrics.Farmers, farmerAddr)
		metrics.Participants = len(metrics.Farmers)
	}

	// Update total reward if available
	if rewardVal, ok := data["reward"]; ok {
		reward := p.parseAmount(rewardVal)
		log.Printf("Adding reward amount %d to block %d for farmer %s", reward, metrics.BlockIndex, farmerAddr)
		metrics.TotalReward += reward

		// Update per-farmer reward
		if farmerAddr != "" {
			currentReward := metrics.FarmerRewards[farmerAddr]
			metrics.FarmerRewards[farmerAddr] = currentReward + reward
			log.Printf("Updated reward for farmer %s to %d", farmerAddr, metrics.FarmerRewards[farmerAddr])
		}
	} else {
		log.Printf("No reward amount found in harvest data for block %d", metrics.BlockIndex)
	}

	// Update close time if available
	if closeTimeVal, ok := data["close_time"]; ok {
		log.Printf("Found close_time value in harvest data: %v (type: %T)", closeTimeVal, closeTimeVal)
		switch v := closeTimeVal.(type) {
		case float64:
			metrics.CloseTimeMs = int64(v)
			log.Printf("Parsed close_time as float64: %d", metrics.CloseTimeMs)
		case string:
			ct, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				metrics.CloseTimeMs = ct
				log.Printf("Parsed close_time as string: %d", metrics.CloseTimeMs)
			} else {
				log.Printf("Error parsing close_time string: %v", err)
			}
		default:
			log.Printf("Unexpected type for close_time: %T", closeTimeVal)
		}
	} else {
		log.Printf("No close_time found in harvest data for block %d", metrics.BlockIndex)
	}

	log.Printf("Updated harvest metrics for block %d: totalReward=%d, closeTimeMs=%d",
		metrics.BlockIndex, metrics.TotalReward, metrics.CloseTimeMs)
}

func (p *KaleMetricsProcessor) extractBlockIndex(data map[string]interface{}, eventType string) (uint32, error) {
	var indexKey string

	// Different events might have the index in different fields
	if eventType == "harvest" {
		indexKey = "index"
	} else if eventType == "plant" || eventType == "work" {
		// For plant and work events, try to find the block index
		// First check if there's a direct index field
		if indexVal, ok := data["index"].(float64); ok {
			return uint32(indexVal), nil
		}

		// Otherwise, look for block_index
		indexKey = "block_index"
	} else {
		// For other events, try common field names
		for _, key := range []string{"index", "block_index", "blockIndex"} {
			if _, ok := data[key]; ok {
				indexKey = key
				break
			}
		}
	}

	if indexVal, ok := data[indexKey]; ok {
		switch v := indexVal.(type) {
		case float64:
			return uint32(v), nil
		case string:
			index, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return 0, err
			}
			return uint32(index), nil
		}
	}

	// If we couldn't find the index, log the data for debugging
	dataBytes, _ := json.Marshal(data)
	log.Printf("Could not find block index in data: %s", string(dataBytes))

	return 0, fmt.Errorf("block index not found")
}

func (p *KaleMetricsProcessor) extractFarmerAddress(data map[string]interface{}, event map[string]interface{}) (string, error) {
	// Try to get farmer from event data
	if farmerVal, ok := data["farmer"]; ok {
		if farmerStr, ok := farmerVal.(string); ok {
			return farmerStr, nil
		}
	}

	// If not in data, try to get from transaction metadata
	if txHash, ok := event["transaction_hash"].(string); ok {
		return fmt.Sprintf("tx:%s", txHash), nil
	}

	return "", fmt.Errorf("farmer address not found")
}

func (p *KaleMetricsProcessor) parseAmount(val interface{}) int64 {
	switch v := val.(type) {
	case float64:
		return int64(v)
	case string:
		// Remove any non-numeric characters except decimal point
		numStr := strings.Map(func(r rune) rune {
			if (r >= '0' && r <= '9') || r == '.' {
				return r
			}
			return -1
		}, v)

		// Parse as float first to handle decimal values
		f, err := strconv.ParseFloat(numStr, 64)
		if err == nil {
			return int64(f)
		}
	}
	return 0
}

func (p *KaleMetricsProcessor) Subscribe(proc pluginapi.Processor) {
	consumerName := "unknown"
	if namedConsumer, ok := proc.(interface{ Name() string }); ok {
		consumerName = namedConsumer.Name()
	}
	log.Printf("Registering consumer via Subscribe: %s", consumerName)
	p.consumers = append(p.consumers, proc)
	log.Printf("Total consumers after Subscribe: %d", len(p.consumers))
}

func (p *KaleMetricsProcessor) Name() string {
	return "flow/processor/kale-metrics"
}

func (p *KaleMetricsProcessor) Version() string {
	return "1.0.0"
}

func (p *KaleMetricsProcessor) Type() pluginapi.PluginType {
	return pluginapi.ProcessorPlugin
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func New() pluginapi.Plugin {
	log.Printf("Creating new KaleMetricsProcessor plugin instance")
	return &KaleMetricsProcessor{
		consumers:    make([]pluginapi.Processor, 0),
		blockMetrics: make(map[uint32]*KaleBlockMetrics),
	}
}

// RegisterConsumer implements the ConsumerRegistry interface
func (p *KaleMetricsProcessor) RegisterConsumer(consumer pluginapi.Consumer) {
	consumerName := "unknown"
	if namedConsumer, ok := consumer.(interface{ Name() string }); ok {
		consumerName = namedConsumer.Name()
	}
	log.Printf("Registering consumer via RegisterConsumer: %s", consumerName)
	p.consumers = append(p.consumers, consumer)
	log.Printf("Total consumers after RegisterConsumer: %d", len(p.consumers))
}

// Close implements the Consumer interface
func (p *KaleMetricsProcessor) Close() error {
	// Clean up any resources if needed
	return nil
}

// Extract close_time_ms from diagnostic events if available
func extractCloseTimeMs(diagnosticEvents []interface{}) int64 {
	for _, eventRaw := range diagnosticEvents {
		event, ok := eventRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for topics that might contain harvest information
		topicsRaw, ok := event["topics"]
		if !ok {
			continue
		}

		topics, ok := topicsRaw.([]interface{})
		if !ok || len(topics) == 0 {
			continue
		}

		// Look for a topic that might contain close_time_ms
		for _, topicRaw := range topics {
			topic, ok := topicRaw.(map[string]interface{})
			if !ok {
				continue
			}

			// Check if this is a harvest event with close_time_ms
			if symVal, ok := topic["Sym"].(string); ok && symVal == "harvest" {
				// Try to extract close_time_ms from data
				if dataRaw, ok := event["data"].(map[string]interface{}); ok {
					if closeTime, ok := dataRaw["close_time_ms"].(float64); ok {
						return int64(closeTime)
					}
				}
			}
		}
	}

	return 0
}

func countLeadingZeros(s string) uint32 {
	log.Printf("Counting leading zeros in: %s", s)

	// Clean up the input string - remove any non-hex characters
	// This handles cases where the hash might be wrapped in quotes or have other formatting
	var cleanedStr string
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			cleanedStr += string(c)
		}
	}

	// If the string is empty after cleaning, return 0
	if len(cleanedStr) == 0 {
		log.Printf("Empty hash string after cleaning, returning 0 zeros")
		return 0
	}

	log.Printf("Cleaned hash string: %s", cleanedStr)

	// The hash is provided as a hex string, so we need to count leading zeros in hex
	// In the Kale contract, each byte (2 hex chars) with value 0 counts as 2 zeros
	// For the first non-zero byte, we count the leading zeros in binary and divide by 4 to get hex digits

	count := uint32(0)

	// Process the string two characters at a time (one byte)
	for i := 0; i < len(cleanedStr); i += 2 {
		if i+1 >= len(cleanedStr) {
			break // Avoid index out of range
		}

		// Get the current byte as a hex value
		byteStr := cleanedStr[i : i+2]
		var byteVal byte
		_, err := fmt.Sscanf(byteStr, "%02x", &byteVal)
		if err != nil {
			log.Printf("Error parsing hex byte %s: %v", byteStr, err)
			break
		}

		if byteVal == 0 {
			// If the byte is 0, add 2 to the count (2 hex digits)
			count += 2
		} else {
			// For the first non-zero byte, count leading zeros in binary
			// and divide by 4 to convert to hex digits
			leadingZeros := uint32(0)
			for mask := byte(0x80); mask > 0 && byteVal&mask == 0; mask >>= 1 {
				leadingZeros++
			}
			count += leadingZeros / 4
			break
		}
	}

	log.Printf("Counted %d leading zeros in hash: %s", count, s)
	return count
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
