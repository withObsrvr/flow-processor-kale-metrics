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
	var eventType string

	// Try different formats for the topic
	topicMap, ok := topics[0].(map[string]interface{})
	if ok {
		// Try Symbol field first (common in Stellar events)
		if symVal, ok := topicMap["Symbol"].(string); ok {
			eventType = symVal
		} else if symVal, ok := topicMap["string"].(string); ok {
			// Try string field as fallback
			eventType = symVal
		} else {
			// Try to extract from any field
			for _, val := range topicMap {
				if strVal, ok := val.(string); ok {
					eventType = strVal
					break
				}
			}
		}
	} else if strVal, ok := topics[0].(string); ok {
		// Direct string value
		eventType = strVal
	}

	if eventType == "" {
		log.Printf("DEBUG: Could not extract event type from topic, skipping")
		return nil
	}

	log.Printf("Processing event of type: %s", eventType)

	// Extract event data
	dataRaw, ok := contractEvent["data"]
	if !ok {
		log.Printf("DEBUG: No data in event message, skipping")
		return nil // No data, skip
	}

	// Parse event data - handle different formats
	var eventData map[string]interface{}

	switch d := dataRaw.(type) {
	case map[string]interface{}:
		// Already a map
		eventData = d
	case string:
		// JSON string
		if err := json.Unmarshal([]byte(d), &eventData); err != nil {
			log.Printf("ERROR: Failed to unmarshal event data string: %v", err)
			return nil
		}
	case []byte:
		// JSON bytes
		if err := json.Unmarshal(d, &eventData); err != nil {
			log.Printf("ERROR: Failed to unmarshal event data bytes: %v", err)
			return nil
		}
	case json.RawMessage:
		// JSON raw message
		if err := json.Unmarshal(d, &eventData); err != nil {
			log.Printf("ERROR: Failed to unmarshal event data raw message: %v", err)
			return nil
		}
	default:
		log.Printf("DEBUG: Event data is not in a recognized format: %T, skipping", dataRaw)
		return nil
	}

	// Extract block index
	blockIndex, err := p.extractBlockIndex(eventData, eventType)
	if err != nil {
		log.Printf("WARNING: Could not extract block index: %v", err)
		// Try to use ledger sequence as fallback
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

	// Extract transaction hash and store it in metrics
	if txHash, ok := contractEvent["transaction_hash"].(string); ok {
		metrics.TransactionHash = txHash
		log.Printf("Extracted transaction hash for block %d: %s", blockIndex, txHash)
	}

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
		p.updateWorkMetrics(metrics, eventData, farmerAddr)
	case "harvest":
		log.Printf("Updating harvest metrics for block %d", blockIndex)
		p.updateHarvestMetrics(metrics, eventData, farmerAddr)
	default:
		log.Printf("Unsupported event type: %s", eventType)
	}

	// Forward metrics to consumers
	log.Printf("Forwarding metrics for block %d after processing %s event", blockIndex, eventType)
	return p.forwardToConsumers(ctx, metrics)
}

// processInvocationMessage processes a contract invocation message
func (p *KaleMetricsProcessor) processInvocationMessage(ctx context.Context, invocation map[string]interface{}) error {
	// Extract function name
	functionName, ok := invocation["function_name"].(string)
	if !ok {
		log.Printf("DEBUG: No function name in invocation message, skipping")
		return nil
	}

	log.Printf("Processing invocation of function: %s", functionName)

	// Extract block index - first try from arguments
	var blockIndex uint32

	if argsRaw, ok := invocation["arguments"].([]interface{}); ok {
		log.Printf("Found %d arguments in invocation for %s function", len(argsRaw), functionName)

		// For harvest, the block index is usually the second argument
		if functionName == "harvest" && len(argsRaw) >= 2 {
			log.Printf("DEBUG: Examining second argument for harvest function: %+v", argsRaw[1])

			// Handle different formats for the block index
			if indexArg, ok := argsRaw[1].(map[string]interface{}); ok {
				// Try to extract from U32 format
				if u32Val, ok := indexArg["U32"].(float64); ok {
					blockIndex = uint32(u32Val)
					log.Printf("Extracted block index %d from harvest arguments (U32 format)", blockIndex)
				} else if u64Val, ok := indexArg["U64"].(float64); ok {
					// Try U64 format
					blockIndex = uint32(u64Val)
					log.Printf("Extracted block index %d from harvest arguments (U64 format)", blockIndex)
				} else if i128Val, ok := indexArg["I128"].(map[string]interface{}); ok {
					// Try I128 format (common in Stellar)
					if loVal, ok := i128Val["Lo"].(float64); ok {
						blockIndex = uint32(loVal)
						log.Printf("Extracted block index %d from harvest arguments (I128 format)", blockIndex)
					}
				} else if strVal, ok := indexArg["String"].(string); ok {
					// Try String format
					if idx, err := strconv.ParseUint(strVal, 10, 32); err == nil {
						blockIndex = uint32(idx)
						log.Printf("Extracted block index %d from harvest arguments (String format)", blockIndex)
					}
				} else {
					// Log the whole argument structure for debugging
					indexBytes, _ := json.Marshal(indexArg)
					log.Printf("DEBUG: Could not extract block index from harvest argument structure: %s", string(indexBytes))
				}
			} else if floatVal, ok := argsRaw[1].(float64); ok {
				// Direct numeric value
				blockIndex = uint32(floatVal)
				log.Printf("Extracted block index %d from harvest arguments (direct numeric)", blockIndex)
			} else if strVal, ok := argsRaw[1].(string); ok {
				// Direct string value, try to parse
				if idx, err := strconv.ParseUint(strVal, 10, 32); err == nil {
					blockIndex = uint32(idx)
					log.Printf("Extracted block index %d from harvest arguments (direct string)", blockIndex)
				}
			} else {
				// Log the argument type for debugging
				log.Printf("DEBUG: Second harvest argument has unsupported type: %T", argsRaw[1])
			}
		}

		// If we still don't have the block index, check all arguments
		if blockIndex == 0 && functionName == "harvest" {
			log.Printf("DEBUG: Block index not found in second argument, checking all arguments")
			for i, arg := range argsRaw {
				log.Printf("DEBUG: Examining argument %d: %+v", i, arg)

				if indexArg, ok := arg.(map[string]interface{}); ok {
					// Try common fields that might contain block index
					for fieldName, fieldValue := range indexArg {
						if strings.Contains(strings.ToLower(fieldName), "block") ||
							strings.Contains(strings.ToLower(fieldName), "index") ||
							fieldName == "farm_index" {
							log.Printf("DEBUG: Found potential block index field '%s' in argument %d with value %v", fieldName, i, fieldValue)
							if numVal, ok := fieldValue.(float64); ok {
								blockIndex = uint32(numVal)
								log.Printf("Extracted block index %d from argument %d field '%s'", blockIndex, i, fieldName)
								break
							} else if strVal, ok := fieldValue.(string); ok {
								if idx, err := strconv.ParseUint(strVal, 10, 32); err == nil {
									blockIndex = uint32(idx)
									log.Printf("Extracted block index %d from argument %d field '%s'", blockIndex, i, fieldName)
									break
								}
							} else if valueMap, ok := fieldValue.(map[string]interface{}); ok {
								// Handle nested values
								log.Printf("DEBUG: Field '%s' contains nested structure: %+v", fieldName, valueMap)
								for subKey, subVal := range valueMap {
									if subKey == "U32" || subKey == "U64" {
										if numVal, ok := subVal.(float64); ok {
											blockIndex = uint32(numVal)
											log.Printf("Extracted block index %d from argument %d field '%s.%s'", blockIndex, i, fieldName, subKey)
											break
										}
									} else if subKey == "I128" {
										if i128Map, ok := subVal.(map[string]interface{}); ok {
											if loVal, ok := i128Map["Lo"].(float64); ok {
												blockIndex = uint32(loVal)
												log.Printf("Extracted block index %d from argument %d field '%s.%s.Lo'", blockIndex, i, fieldName, subKey)
												break
											}
										}
									}
								}
							}
						}
					}
					if blockIndex > 0 {
						break
					}
				} else if numVal, ok := arg.(float64); ok {
					// Direct numeric value
					if i == 1 && functionName == "harvest" {
						// Second argument in harvest is typically the index
						blockIndex = uint32(numVal)
						log.Printf("Extracted block index %d from direct numeric value in argument %d", blockIndex, i)
						break
					}
				}
			}
		}
	}

	// If we couldn't extract from arguments, try finding it in the invocation data
	if blockIndex == 0 {
		for key, val := range invocation {
			if (strings.Contains(strings.ToLower(key), "block") && strings.Contains(strings.ToLower(key), "index")) ||
				key == "block_index" || key == "farm_index" {
				if numVal, ok := val.(float64); ok {
					blockIndex = uint32(numVal)
					log.Printf("Extracted block index %d from invocation field '%s'", blockIndex, key)
					break
				} else if strVal, ok := val.(string); ok {
					if idx, err := strconv.ParseUint(strVal, 10, 32); err == nil {
						blockIndex = uint32(idx)
						log.Printf("Extracted block index %d from invocation field '%s'", blockIndex, key)
						break
					}
				}
			}
		}
	}

	// If we still couldn't find the block index, use ledger sequence as fallback
	if blockIndex == 0 {
		if ledgerSeq, ok := invocation["ledger_sequence"].(float64); ok {
			blockIndex = uint32(ledgerSeq)
			log.Printf("Using ledger sequence %d as fallback for block index", blockIndex)
		} else {
			// As a last resort, dump the full invocation for debugging
			invocationBytes, _ := json.Marshal(invocation)
			log.Printf("DEBUG: Could not determine block index, full invocation data: %s", string(invocationBytes))
			return fmt.Errorf("could not determine block index from invocation data")
		}
	}

	// Get or create block metrics
	metrics := p.getOrCreateBlockMetrics(blockIndex)

	// Extract transaction hash
	if txHash, ok := invocation["transaction_hash"].(string); ok {
		metrics.TransactionHash = txHash
		log.Printf("Extracted transaction hash for block %d: %s", blockIndex, txHash)
	}

	// Extract farmer address
	farmerAddr := ""
	if invokingAccount, ok := invocation["invoking_account"].(string); ok {
		farmerAddr = invokingAccount
		log.Printf("Extracted farmer address from invoking account: %s", farmerAddr)

		// Add farmer to participants if not already included
		if !contains(metrics.Farmers, farmerAddr) {
			metrics.Farmers = append(metrics.Farmers, farmerAddr)
			metrics.Participants = len(metrics.Farmers)
		}
	}

	// Process based on function name
	switch functionName {
	case "plant":
		log.Printf("Processing plant invocation for block %d", blockIndex)

		// Set open time if not already set
		if metrics.OpenTimeMs == 0 {
			metrics.OpenTimeMs = time.Now().UnixMilli()
			log.Printf("Set open time for block %d: %d", blockIndex, metrics.OpenTimeMs)
		}

		// Extract stake amount from arguments
		if argsRaw, ok := invocation["arguments"].([]interface{}); ok && len(argsRaw) >= 2 {
			if amountArg, ok := argsRaw[1].(map[string]interface{}); ok {
				// Try to extract from I128 format
				if i128Val, ok := amountArg["I128"].(map[string]interface{}); ok {
					if loVal, ok := i128Val["Lo"].(float64); ok {
						stake := int64(loVal)
						log.Printf("Extracted stake amount %d from plant arguments", stake)

						// Update total staked
						metrics.TotalStaked += stake

						// Update per-farmer stake
						if farmerAddr != "" {
							currentStake := metrics.FarmerStakes[farmerAddr]
							metrics.FarmerStakes[farmerAddr] = currentStake + stake
							log.Printf("Updated stake for farmer %s to %d", farmerAddr, metrics.FarmerStakes[farmerAddr])
						}
					}
				}
			}
		}

	case "work":
		log.Printf("Processing work invocation for block %d", blockIndex)

		// Try to extract hash from arguments
		if argsRaw, ok := invocation["arguments"].([]interface{}); ok && len(argsRaw) >= 2 {
			if hashArg, ok := argsRaw[1].(map[string]interface{}); ok {
				// Try different formats for hash
				var hashVal string
				if bytesVal, ok := hashArg["BytesN"].(string); ok {
					hashVal = bytesVal
				} else if strVal, ok := hashArg["String"].(string); ok {
					hashVal = strVal
				} else if hashStr, ok := hashArg["hash"].(string); ok {
					hashVal = hashStr
				}

				if hashVal != "" {
					zeros := int(countLeadingZeros(hashVal))
					log.Printf("Extracted zero count %d from hash in work arguments", zeros)

					// Update farmer zero count
					if farmerAddr != "" {
						currentZeros, exists := metrics.FarmerZeroCounts[farmerAddr]
						if !exists || zeros > currentZeros {
							metrics.FarmerZeroCounts[farmerAddr] = zeros
							log.Printf("Updated zero count for farmer %s to %d", farmerAddr, zeros)
						}
					}

					// Update block zero counts
					if uint32(zeros) > metrics.MaxZeros {
						metrics.MaxZeros = uint32(zeros)
					}
					if metrics.MinZeros == 0 || uint32(zeros) < metrics.MinZeros {
						metrics.MinZeros = uint32(zeros)
					}

					// Update highest zero count
					if zeros > metrics.HighestZeroCount {
						metrics.HighestZeroCount = zeros
						log.Printf("Updated highest zero count to %d for block %d", zeros, blockIndex)
					}
				}
			}
		}

	case "harvest":
		log.Printf("Processing harvest invocation for block %d", blockIndex)

		// Set close time if not already set
		if metrics.CloseTimeMs == 0 {
			metrics.CloseTimeMs = time.Now().UnixMilli()
			log.Printf("Set close time for block %d: %d", blockIndex, metrics.CloseTimeMs)

			// Calculate duration if open time is set
			if metrics.OpenTimeMs > 0 {
				metrics.Duration = metrics.CloseTimeMs - metrics.OpenTimeMs
				log.Printf("Calculated duration for block %d: %d ms", blockIndex, metrics.Duration)
			}
		}

		// Look for mint events in diagnostic events
		if diagnosticEventsRaw, ok := invocation["diagnostic_events"].([]interface{}); ok {
			for _, eventRaw := range diagnosticEventsRaw {
				if event, ok := eventRaw.(map[string]interface{}); ok {
					// Check for mint events
					if topicsRaw, ok := event["topics"].([]interface{}); ok {
						for _, topicRaw := range topicsRaw {
							var topic map[string]interface{}

							// Topic might be a string that needs to be parsed
							if topicStr, ok := topicRaw.(string); ok {
								if err := json.Unmarshal([]byte(topicStr), &topic); err != nil {
									continue
								}
							} else if topicMap, ok := topicRaw.(map[string]interface{}); ok {
								topic = topicMap
							} else {
								continue
							}

							// Check if this is a mint event
							if symVal, ok := topic["Sym"].(string); ok && symVal == "mint" {
								// Extract amount from data
								if dataRaw, ok := event["data"].(map[string]interface{}); ok {
									if i128Raw, ok := dataRaw["I128"].(map[string]interface{}); ok {
										if loVal, ok := i128Raw["Lo"].(float64); ok {
											amount := int64(loVal)
											log.Printf("Found mint event with amount %d", amount)

											// Update total reward
											metrics.TotalReward += amount

											// Update per-farmer reward
											if farmerAddr != "" {
												currentReward := metrics.FarmerRewards[farmerAddr]
												metrics.FarmerRewards[farmerAddr] = currentReward + amount
												log.Printf("Updated reward for farmer %s to %d", farmerAddr, metrics.FarmerRewards[farmerAddr])
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

	// Forward metrics to consumers
	log.Printf("Forwarding metrics for block %d after processing %s invocation", blockIndex, functionName)
	return p.forwardToConsumers(ctx, metrics)
}

// extractBlockIndex extracts the block index from event data
func (p *KaleMetricsProcessor) extractBlockIndex(data map[string]interface{}, eventType string) (uint32, error) {
	log.Printf("Extracting block index from %s event type with data", eventType)

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

	// For Kale contract events, look for nested data structures that might contain the block index
	if eventType == "harvest" || strings.Contains(strings.ToLower(eventType), "kale") {
		// Check for nested blocks of data
		for key, val := range data {
			if nestedMap, ok := val.(map[string]interface{}); ok {
				log.Printf("Examining nested data structure in field '%s' for potential block index", key)

				// First look for fields directly related to block index
				for nestedKey, nestedVal := range nestedMap {
					if strings.Contains(strings.ToLower(nestedKey), "block") ||
						strings.Contains(strings.ToLower(nestedKey), "index") ||
						nestedKey == "farm_index" {
						switch v := nestedVal.(type) {
						case float64:
							log.Printf("Extracted block index %d from nested field %s.%s", uint32(v), key, nestedKey)
							return uint32(v), nil
						case int:
							log.Printf("Extracted block index %d from nested field %s.%s", uint32(v), key, nestedKey)
							return uint32(v), nil
						case string:
							if index, err := strconv.ParseUint(v, 10, 32); err == nil {
								log.Printf("Extracted block index %d from nested field %s.%s", uint32(index), key, nestedKey)
								return uint32(index), nil
							}
						}
					}
				}
			}
		}
	}

	// If we still can't find the block index, log the entire event data for debugging
	dataBytes, _ := json.Marshal(data)
	log.Printf("DEBUG: Could not find block index in %s event data: %s", eventType, string(dataBytes))

	return 0, fmt.Errorf("block index not found in %s event", eventType)
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
