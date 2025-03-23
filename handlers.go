package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// processEventMessage processes a contract event message
func (p *KaleMetricsProcessor) processEventMessage(ctx context.Context, msg []byte) error {
	// Parse the message into a map
	log.Printf("Processing contract event message")
	var data map[string]interface{}
	err := json.Unmarshal(msg, &data)
	if err != nil {
		return fmt.Errorf("error unmarshaling event message: %w", err)
	}

	contractEvent, ok := data["contract_event"].(map[string]interface{})
	if !ok {
		log.Printf("contract_event field not found or not a map")
		return nil
	}

	// Extract topics to identify the event type
	topics, ok := contractEvent["topics"].([]interface{})
	if !ok || len(topics) == 0 {
		log.Printf("No topics found in contract event, skipping")
		return nil
	}

	// First topic should be the event type
	eventType, ok := topics[0].(string)
	if !ok {
		log.Printf("First topic is not a string, skipping")
		return nil
	}

	log.Printf("Processing %s event", eventType)

	// Convert data structure to expected format based on event type
	var eventData map[string]interface{}
	if eventDataRaw, ok := contractEvent["data"].(map[string]interface{}); ok {
		eventData = eventDataRaw
	} else {
		eventData = contractEvent
	}

	// Extract block index using our legacy method
	blockIndex, err := p.extractBlockIndex(eventData, eventType)
	if err != nil {
		log.Printf("Error extracting block index from %s event: %v", eventType, err)
		return nil
	}

	// Forward metrics with the extracted block index
	p.ForwardMetrics(blockIndex, eventType, eventData)

	return nil
}

// processInvocationMessage processes an invocation message
func (p *KaleMetricsProcessor) processInvocationMessage(ctx context.Context, msg []byte) error {
	// Parse the message into a map
	log.Printf("Processing invocation message")
	var data map[string]interface{}
	err := json.Unmarshal(msg, &data)
	if err != nil {
		return fmt.Errorf("error unmarshaling invocation message: %w", err)
	}

	// Extract the invocation details
	invocation, ok := data["invocation"].(map[string]interface{})
	if !ok {
		log.Printf("invocation field not found or not a map")
		return nil
	}

	// Extract function name
	functionName, ok := invocation["function_name"].(string)
	if !ok {
		log.Printf("function_name not found or not a string")
		return nil
	}

	log.Printf("Processing %s invocation", functionName)

	// Prepare data structure for block index extraction
	invocationData := make(map[string]interface{})
	invocationData["function_name"] = functionName

	// Include arguments and other fields that might help with extraction
	if args, ok := invocation["arguments"].([]interface{}); ok {
		invocationData["arguments"] = args
		log.Printf("Found %d arguments in invocation", len(args))
	}
	if tempData, ok := invocation["temporary_data"].(map[string]interface{}); ok {
		invocationData["temporary_data"] = tempData
		log.Printf("Found temporary_data in invocation")
	}
	if metadata, ok := invocation["metadata"].(map[string]interface{}); ok {
		invocationData["metadata"] = metadata
		log.Printf("Found metadata in invocation")
	}

	// Extract block index
	blockIndex, err := p.extractBlockIndex(invocationData, functionName)
	if err != nil {
		log.Printf("Error extracting block index from %s invocation: %v", functionName, err)
		return nil
	}

	log.Printf("Extracted block index %d from %s invocation", blockIndex, functionName)
	p.ForwardMetrics(blockIndex, functionName, invocationData)

	return nil
}

// extractBlockIndex extracts the block index from event data
func (p *KaleMetricsProcessor) extractBlockIndex(data map[string]interface{}, eventType string) (uint32, error) {
	log.Printf("Extracting block index for %s using enhanced extractor", eventType)

	// First check if block_index exists in the top-level data
	if blockIdx, ok := data["block_index"]; ok {
		log.Printf("Found block_index field directly in event data: %v (type: %T)", blockIdx, blockIdx)
		switch v := blockIdx.(type) {
		case float64:
			return uint32(v), nil
		case int:
			return uint32(v), nil
		case string:
			if index, err := strconv.ParseUint(v, 10, 32); err == nil {
				return uint32(index), nil
			}
		case map[string]interface{}:
			// Try to extract from nested map (common in Stellar contract data)
			log.Printf("Found nested block_index structure: %+v", v)
			for subKey, subVal := range v {
				if subKey == "U32" || subKey == "U64" {
					if floatVal, ok := subVal.(float64); ok {
						log.Printf("Extracted block index %d from block_index.%s", uint32(floatVal), subKey)
						return uint32(floatVal), nil
					}
				} else if subKey == "I128" && subVal != nil {
					if i128Map, ok := subVal.(map[string]interface{}); ok {
						if loVal, ok := i128Map["Lo"].(float64); ok {
							log.Printf("Extracted block index %d from block_index.I128.Lo", uint32(loVal))
							return uint32(loVal), nil
						}
					}
				} else if subKey == "String" {
					if strVal, ok := subVal.(string); ok {
						if index, err := strconv.ParseUint(strVal, 10, 32); err == nil {
							log.Printf("Extracted block index %d from block_index.String", uint32(index))
							return uint32(index), nil
						}
					}
				}
			}
		}
	}

	// Try other common field names for block index
	for _, key := range []string{"index", "blockIndex", "block", "idx", "block_number", "farm_index"} {
		if val, ok := data[key]; ok {
			log.Printf("Found potential block index in field %s: %v (type: %T)", key, val, val)

			switch v := val.(type) {
			case float64:
				log.Printf("Extracted block index %d from %s field", uint32(v), key)
				return uint32(v), nil
			case int:
				log.Printf("Extracted block index %d from %s field", uint32(v), key)
				return uint32(v), nil
			case string:
				if index, err := strconv.ParseUint(v, 10, 32); err == nil {
					log.Printf("Extracted block index %d from %s field", uint32(index), key)
					return uint32(index), nil
				}
			case map[string]interface{}:
				// Try to extract from nested map
				log.Printf("Found nested structure in %s field: %+v", key, v)
				for subKey, subVal := range v {
					if subKey == "U32" || subKey == "U64" {
						if floatVal, ok := subVal.(float64); ok {
							log.Printf("Extracted block index %d from %s.%s", uint32(floatVal), key, subKey)
							return uint32(floatVal), nil
						}
					} else if subKey == "I128" && subVal != nil {
						if i128Map, ok := subVal.(map[string]interface{}); ok {
							if loVal, ok := i128Map["Lo"].(float64); ok {
								log.Printf("Extracted block index %d from %s.%s.Lo", uint32(loVal), key, subKey)
								return uint32(loVal), nil
							}
						}
					} else if subKey == "String" {
						if strVal, ok := subVal.(string); ok {
							if index, err := strconv.ParseUint(strVal, 10, 32); err == nil {
								log.Printf("Extracted block index %d from %s.%s", uint32(index), key, subKey)
								return uint32(index), nil
							}
						}
					}
				}
			}
		}
	}

	// For special cases
	if eventType == "harvest" {
		// For harvest invocations, check arguments
		if args, ok := data["arguments"].([]interface{}); ok && len(args) >= 2 {
			log.Printf("Examining harvest arguments for block index. Found %d arguments", len(args))
			// The second argument is typically the block index in harvest calls
			if arg, ok := args[1].(map[string]interface{}); ok {
				log.Printf("Second argument is a map: %+v", arg)
				if u32Val, ok := arg["U32"].(float64); ok {
					log.Printf("Found block index %d in second argument U32 field", uint32(u32Val))
					return uint32(u32Val), nil
				}
			}
		}
	}

	// Check for temporary data that might contain Pail info with block index
	for _, field := range []string{"temporary_data", "metadata", "soroban_meta"} {
		if meta, ok := data[field]; ok {
			log.Printf("Checking %s field for potential block index", field)
			if metaMap, ok := meta.(map[string]interface{}); ok {
				// Look for any keys that might contain Pail or block_index
				for key, val := range metaMap {
					if strings.Contains(strings.ToLower(key), "pail") ||
						strings.Contains(strings.ToLower(key), "block") ||
						strings.Contains(strings.ToLower(key), "index") {
						log.Printf("Found potential block index data in %s.%s", field, key)

						// Try direct extraction
						if blockIndex, ok := extractUint32FromValue(val); ok {
							log.Printf("Extracted block index %d from %s.%s", blockIndex, field, key)
							return blockIndex, nil
						}

						// Try nested map
						if valMap, ok := val.(map[string]interface{}); ok {
							for subKey, subVal := range valMap {
								if blockIndex, ok := extractUint32FromValue(subVal); ok {
									log.Printf("Extracted block index %d from %s.%s.%s", blockIndex, field, key, subKey)
									return blockIndex, nil
								}
							}
						}
					}
				}
			}
		}
	}

	// If all else fails, dump the data and return an error
	dataBytes, _ := json.Marshal(data)
	log.Printf("Failed to extract block index from %s data: %s", eventType, string(dataBytes))
	return 0, fmt.Errorf("could not extract block index from %s data", eventType)
}

// extractUint32FromValue attempts to extract a uint32 from a value
func extractUint32FromValue(val interface{}) (uint32, bool) {
	switch v := val.(type) {
	case float64:
		return uint32(v), true
	case int:
		return uint32(v), true
	case uint32:
		return v, true
	case uint64:
		return uint32(v), true
	case int64:
		return uint32(v), true
	case string:
		if index, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint32(index), true
		}
	case map[string]interface{}:
		// Try common Stellar contract data formats
		for key, subVal := range v {
			if key == "U32" || key == "U64" {
				if floatVal, ok := subVal.(float64); ok {
					return uint32(floatVal), true
				}
			} else if key == "I128" && subVal != nil {
				if i128Map, ok := subVal.(map[string]interface{}); ok {
					if loVal, ok := i128Map["Lo"].(float64); ok {
						return uint32(loVal), true
					}
				}
			} else if key == "String" {
				if strVal, ok := subVal.(string); ok {
					if index, err := strconv.ParseUint(strVal, 10, 32); err == nil {
						return uint32(index), true
					}
				}
			}
		}
	}
	return 0, false
}

// extractFarmerAddress extracts the farmer address from event data
func (p *KaleMetricsProcessor) extractFarmerAddress(data map[string]interface{}, event map[string]interface{}) (string, error) {
	log.Printf("Extracting farmer address from data: %+v", data)

	// Try common field names for farmer address
	for _, key := range []string{"farmer", "address", "account", "invoking_account"} {
		if val, ok := data[key]; ok {
			log.Printf("Found potential farmer address in field %s: %v", key, val)

			switch v := val.(type) {
			case string:
				return v, nil
			case map[string]interface{}:
				// Try to extract from nested map
				for _, subVal := range v {
					if strVal, ok := subVal.(string); ok {
						return strVal, nil
					}
				}
			}
		}
	}

	// Try to get from the event if not in data
	if invokingAccount, ok := event["invoking_account"].(string); ok {
		return invokingAccount, nil
	}

	// If we couldn't find the address, try to use transaction hash as a fallback
	if txHash, ok := event["transaction_hash"].(string); ok {
		return fmt.Sprintf("tx:%s", txHash), nil
	}

	return "", fmt.Errorf("farmer address not found")
}

// updatePlantMetrics updates metrics based on a plant event
func (p *KaleMetricsProcessor) updatePlantMetrics(metrics *KaleBlockMetrics, data map[string]interface{}, farmerAddr string) {
	log.Printf("Updating plant metrics for block %d with data: %+v", metrics.BlockIndex, data)

	// Add farmer to participants if not already present
	if farmerAddr != "" && !contains(metrics.Farmers, farmerAddr) {
		log.Printf("Adding new farmer %s to block %d", farmerAddr, metrics.BlockIndex)
		metrics.Farmers = append(metrics.Farmers, farmerAddr)
		metrics.Participants = len(metrics.Farmers)
	}

	// Update total staked if available
	// Try different field names for stake amount
	stakeFound := false
	for _, key := range []string{"amount", "stake", "staked"} {
		if stakeVal, ok := data[key]; ok {
			stake := parseAmount(stakeVal)
			if stake > 0 {
				log.Printf("Adding stake amount %d to block %d for farmer %s", stake, metrics.BlockIndex, farmerAddr)
				metrics.TotalStaked += stake

				// Update per-farmer stake
				if farmerAddr != "" {
					currentStake := metrics.FarmerStakes[farmerAddr]
					metrics.FarmerStakes[farmerAddr] = currentStake + stake
					log.Printf("Updated stake for farmer %s to %d", farmerAddr, metrics.FarmerStakes[farmerAddr])
				}
				stakeFound = true
				break
			}
		}
	}

	// If we didn't find a stake amount directly, try to look in nested structures
	if !stakeFound {
		// Try to find in nested maps
		for key, val := range data {
			if nestedMap, ok := val.(map[string]interface{}); ok {
				for nestedKey, nestedVal := range nestedMap {
					if strings.Contains(strings.ToLower(nestedKey), "stake") ||
						strings.Contains(strings.ToLower(nestedKey), "amount") {
						stake := parseAmount(nestedVal)
						if stake > 0 {
							log.Printf("Adding stake amount %d from nested field %s.%s to block %d for farmer %s",
								stake, key, nestedKey, metrics.BlockIndex, farmerAddr)
							metrics.TotalStaked += stake

							// Update per-farmer stake
							if farmerAddr != "" {
								currentStake := metrics.FarmerStakes[farmerAddr]
								metrics.FarmerStakes[farmerAddr] = currentStake + stake
								log.Printf("Updated stake for farmer %s to %d", farmerAddr, metrics.FarmerStakes[farmerAddr])
							}
							stakeFound = true
							break
						}
					}
				}
				if stakeFound {
					break
				}
			}
		}
	}

	// Set open time if not already set
	if metrics.OpenTimeMs == 0 {
		metrics.OpenTimeMs = time.Now().UnixMilli()
		log.Printf("Set open time for block %d: %d", metrics.BlockIndex, metrics.OpenTimeMs)
	}

	log.Printf("Updated plant metrics for block %d: participants=%d, totalStaked=%d",
		metrics.BlockIndex, metrics.Participants, metrics.TotalStaked)
}

// updateWorkMetrics updates metrics based on a work event
func (p *KaleMetricsProcessor) updateWorkMetrics(metrics *KaleBlockMetrics, data map[string]interface{}, farmerAddr string) {
	log.Printf("Updating work metrics for block %d with data: %+v", metrics.BlockIndex, data)

	// Add farmer to participants if not already present
	if farmerAddr != "" && !contains(metrics.Farmers, farmerAddr) {
		log.Printf("Adding new farmer %s to block %d", farmerAddr, metrics.BlockIndex)
		metrics.Farmers = append(metrics.Farmers, farmerAddr)
		metrics.Participants = len(metrics.Farmers)
	}

	// Try to extract zero count from different fields
	zeros := 0

	// First try direct zeros field
	if zerosVal, ok := data["zeros"]; ok {
		log.Printf("Found zeros value in work data: %v (type: %T)", zerosVal, zerosVal)

		switch v := zerosVal.(type) {
		case float64:
			zeros = int(v)
		case int:
			zeros = v
		case string:
			if z, err := strconv.Atoi(v); err == nil {
				zeros = z
			}
		case map[string]interface{}:
			// Try to extract from nested map
			for _, subVal := range v {
				if floatVal, ok := subVal.(float64); ok {
					zeros = int(floatVal)
					log.Printf("Extracted zero count %d from nested zeros field", zeros)
					break
				} else if strVal, ok := subVal.(string); ok {
					if z, err := strconv.Atoi(strVal); err == nil {
						zeros = z
						log.Printf("Extracted zero count %d from nested zeros string field", zeros)
						break
					}
				}
			}
		}
	} else if hashVal, ok := data["hash"].(string); ok {
		// If zeros not directly available, try to extract from hash
		zeros = int(countLeadingZeros(hashVal))
		log.Printf("Extracted zero count %d from hash %s", zeros, hashVal)
	} else {
		// Try to find hash in nested fields
		for _, key := range []string{"result", "output", "hash_result", "work_result"} {
			if resultVal, ok := data[key]; ok {
				if resultMap, ok := resultVal.(map[string]interface{}); ok {
					// Try to find hash in the result map
					if hashVal, ok := resultMap["hash"].(string); ok {
						zeros = int(countLeadingZeros(hashVal))
						log.Printf("Extracted zero count %d from hash in %s field", zeros, key)
						break
					}

					// Try to find zeros directly in the result map
					if zerosVal, ok := resultMap["zeros"]; ok {
						switch v := zerosVal.(type) {
						case float64:
							zeros = int(v)
						case int:
							zeros = v
						case string:
							if z, err := strconv.Atoi(v); err == nil {
								zeros = z
							}
						}
						if zeros > 0 {
							log.Printf("Extracted zero count %d from zeros in %s field", zeros, key)
							break
						}
					}
				} else if hashStr, ok := resultVal.(string); ok {
					// The result might be a hash string directly
					zeros = int(countLeadingZeros(hashStr))
					log.Printf("Extracted zero count %d from hash in %s field", zeros, key)
					break
				}
			}
		}

		// If we still don't have zeros, try to search all string fields for potential hashes
		if zeros == 0 {
			for key, val := range data {
				if strVal, ok := val.(string); ok && len(strVal) >= 32 {
					// This might be a hash - check if it has hex characters
					isHex := true
					for _, c := range strVal {
						if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
							isHex = false
							break
						}
					}

					if isHex {
						zeros = int(countLeadingZeros(strVal))
						if zeros > 0 {
							log.Printf("Extracted zero count %d from potential hash in %s field", zeros, key)
							break
						}
					}
				}
			}
		}
	}

	// Update farmer zero count if we found a value
	if zeros > 0 && farmerAddr != "" {
		currentZeros, exists := metrics.FarmerZeroCounts[farmerAddr]
		if !exists || zeros > currentZeros {
			log.Printf("Updating zero count for farmer %s from %d to %d",
				farmerAddr, currentZeros, zeros)
			metrics.FarmerZeroCounts[farmerAddr] = zeros
		}
	}

	// Update block zero counts
	if zeros > 0 {
		if uint32(zeros) > metrics.MaxZeros {
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

	log.Printf("Updated work metrics for block %d: highestZeroCount=%d, farmer=%s",
		metrics.BlockIndex, metrics.HighestZeroCount, farmerAddr)
}

// updateHarvestMetrics updates metrics based on a harvest event
func (p *KaleMetricsProcessor) updateHarvestMetrics(metrics *KaleBlockMetrics, data map[string]interface{}, farmerAddr string) {
	log.Printf("Updating harvest metrics for block %d with data: %+v", metrics.BlockIndex, data)

	// Add farmer to participants if not already present
	if farmerAddr != "" && !contains(metrics.Farmers, farmerAddr) {
		log.Printf("Adding new farmer %s to block %d", farmerAddr, metrics.BlockIndex)
		metrics.Farmers = append(metrics.Farmers, farmerAddr)
		metrics.Participants = len(metrics.Farmers)
	}

	// Update total reward if available
	rewardFound := false

	// Try different field names for reward amount
	for _, key := range []string{"reward", "amount", "payout"} {
		if rewardVal, ok := data[key]; ok {
			reward := parseAmount(rewardVal)
			if reward > 0 {
				log.Printf("Adding reward amount %d to block %d for farmer %s", reward, metrics.BlockIndex, farmerAddr)
				metrics.TotalReward += reward

				// Update per-farmer reward
				if farmerAddr != "" {
					currentReward := metrics.FarmerRewards[farmerAddr]
					metrics.FarmerRewards[farmerAddr] = currentReward + reward
					log.Printf("Updated reward for farmer %s to %d", farmerAddr, metrics.FarmerRewards[farmerAddr])
				}
				rewardFound = true
				break
			}
		}
	}

	// If we didn't find a reward amount directly, try to look in nested structures
	if !rewardFound {
		// Try to find in nested maps
		for key, val := range data {
			if nestedMap, ok := val.(map[string]interface{}); ok {
				for nestedKey, nestedVal := range nestedMap {
					if strings.Contains(strings.ToLower(nestedKey), "reward") ||
						strings.Contains(strings.ToLower(nestedKey), "amount") ||
						strings.Contains(strings.ToLower(nestedKey), "payout") {
						reward := parseAmount(nestedVal)
						if reward > 0 {
							log.Printf("Adding reward amount %d from nested field %s.%s to block %d for farmer %s",
								reward, key, nestedKey, metrics.BlockIndex, farmerAddr)
							metrics.TotalReward += reward

							// Update per-farmer reward
							if farmerAddr != "" {
								currentReward := metrics.FarmerRewards[farmerAddr]
								metrics.FarmerRewards[farmerAddr] = currentReward + reward
								log.Printf("Updated reward for farmer %s to %d", farmerAddr, metrics.FarmerRewards[farmerAddr])
							}
							rewardFound = true
							break
						}
					}
				}
				if rewardFound {
					break
				}
			}
		}
	}

	// Update close time if available
	if closeTimeVal, ok := data["close_time"]; ok {
		log.Printf("Found close_time value in harvest data: %v (type: %T)", closeTimeVal, closeTimeVal)
		switch v := closeTimeVal.(type) {
		case float64:
			metrics.CloseTimeMs = int64(v)
		case int64:
			metrics.CloseTimeMs = v
		case string:
			ct, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				metrics.CloseTimeMs = ct
			}
		}
	}

	// If close time is set but open time is not, set a default open time
	if metrics.CloseTimeMs > 0 && metrics.OpenTimeMs == 0 {
		// Set open time to 5 minutes before close time (typical Kale block duration)
		metrics.OpenTimeMs = metrics.CloseTimeMs - (5 * 60 * 1000)
		log.Printf("Set default open time for block %d: %d (5 minutes before close time)",
			metrics.BlockIndex, metrics.OpenTimeMs)
	}

	// Calculate duration if both open and close times are set
	if metrics.OpenTimeMs > 0 && metrics.CloseTimeMs > 0 {
		metrics.Duration = metrics.CloseTimeMs - metrics.OpenTimeMs
		log.Printf("Calculated duration for block %d: %d ms", metrics.BlockIndex, metrics.Duration)
	}

	log.Printf("Updated harvest metrics for block %d: totalReward=%d, closeTimeMs=%d",
		metrics.BlockIndex, metrics.TotalReward, metrics.CloseTimeMs)
}

// ForwardMetrics forwards metrics to consumers with the specified block index
func (p *KaleMetricsProcessor) ForwardMetrics(blockIndex uint32, eventType string, data map[string]interface{}) {
	log.Printf("Forwarding %s metrics for block index %d", eventType, blockIndex)

	// Get or create metrics for this block
	metrics := p.getOrCreateBlockMetrics(blockIndex)

	// Update metrics based on event type
	switch strings.ToLower(eventType) {
	case "plant":
		// Try to extract farmer address for plant metrics
		farmerAddr := extractFarmerAddress(data)
		p.updatePlantMetrics(metrics, data, farmerAddr)

	case "work":
		// Try to extract farmer address for work metrics
		farmerAddr := extractFarmerAddress(data)
		p.updateWorkMetrics(metrics, data, farmerAddr)

	case "harvest":
		// Try to extract farmer address for harvest metrics
		farmerAddr := extractFarmerAddress(data)
		p.updateHarvestMetrics(metrics, data, farmerAddr)

	default:
		log.Printf("No specific metric update for event type: %s", eventType)
	}

	// Forward to consumers
	if err := p.forwardToConsumers(context.Background(), metrics); err != nil {
		log.Printf("Error forwarding %s metrics to consumers: %v", eventType, err)
	}
}

// extractFarmerAddress attempts to extract a farmer address from event data
func extractFarmerAddress(data map[string]interface{}) string {
	// Try common field names
	for _, key := range []string{"farmerAddr", "farmer", "address", "public_key"} {
		if val, ok := data[key]; ok {
			if strVal, ok := val.(string); ok {
				log.Printf("Extracted farmer address '%s' from field %s", strVal, key)
				return strVal
			}
		}
	}

	// Try from arguments
	if args, ok := data["arguments"].([]interface{}); ok && len(args) > 0 {
		if farmerArg, ok := args[0].(string); ok {
			log.Printf("Extracted farmer address '%s' from first argument", farmerArg)
			return farmerArg
		}
	}

	log.Printf("Could not extract farmer address, using 'unknown'")
	return "unknown"
}
