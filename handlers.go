package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
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
func extractFarmerAddress(data map[string]interface{}) string {
	log.Printf("Attempting to extract farmer address from data")

	// Check if there's an arguments field which is common in invocations
	if args, ok := data["arguments"].([]interface{}); ok && len(args) > 0 {
		// First argument is usually the farmer address
		firstArg := args[0]

		log.Printf("First argument type: %T", firstArg)
		argStr, _ := json.Marshal(firstArg)
		log.Printf("First argument value: %s", string(argStr))

		// Look for Address field with AccountId
		accountIdRegex := regexp.MustCompile(`"Address":[^}]*"AccountId":[^}]*"Ed25519":\s*\[([0-9,\s]+)\]`)
		matches := accountIdRegex.FindStringSubmatch(string(argStr))
		if len(matches) > 1 {
			// Convert the byte array to a Stellar address
			parts := strings.Split(matches[1], ",")
			bytes := make([]byte, len(parts))
			for i, s := range parts {
				s = strings.TrimSpace(s)
				if val, err := strconv.Atoi(s); err == nil {
					bytes[i] = byte(val)
				}
			}

			// Create an address from the bytes
			addr := fmt.Sprintf("G%x", bytes)
			log.Printf("Extracted farmer address from AccountId.Ed25519 bytes: %s", addr)
			return addr
		}

		// Direct Ed25519 pattern (no Address wrapper)
		ed25519Regex := regexp.MustCompile(`"Ed25519":\s*\[([0-9,\s]+)\]`)
		matches = ed25519Regex.FindStringSubmatch(string(argStr))
		if len(matches) > 1 {
			// Convert the byte array to a Stellar address
			parts := strings.Split(matches[1], ",")
			bytes := make([]byte, len(parts))
			for i, s := range parts {
				s = strings.TrimSpace(s)
				if val, err := strconv.Atoi(s); err == nil {
					bytes[i] = byte(val)
				}
			}

			// Create an address from the bytes
			addr := fmt.Sprintf("G%x", bytes)
			log.Printf("Extracted farmer address from Ed25519 bytes: %s", addr)
			return addr
		}

		// Look for String format which may contain the address directly
		stringRegex := regexp.MustCompile(`"String":\s*"([G|C][A-Z0-9]+)"`)
		matches = stringRegex.FindStringSubmatch(string(argStr))
		if len(matches) > 1 {
			log.Printf("Extracted farmer address from String: %s", matches[1])
			return matches[1]
		}
	}

	// Look for invoking_account which is common in contract invocations
	if account, ok := data["invoking_account"].(string); ok && (strings.HasPrefix(account, "G") || strings.HasPrefix(account, "C")) {
		log.Printf("Extracted farmer address from invoking_account: %s", account)
		return account
	}

	// Look through transaction metadata for Ed25519 addresses
	if txMeta, ok := data["tx_meta"].(map[string]interface{}); ok {
		log.Printf("Found tx_meta field, checking for account information")
		txMetaStr, _ := json.Marshal(txMeta)

		// Look for Ed25519 addresses in tx_meta
		ed25519Regex := regexp.MustCompile(`"Ed25519":\s*\[([0-9,\s]+)\]`)
		matches := ed25519Regex.FindAllStringSubmatch(string(txMetaStr), -1)
		if len(matches) > 0 {
			// Use the first match (usually the source account)
			parts := strings.Split(matches[0][1], ",")
			bytes := make([]byte, len(parts))
			for i, s := range parts {
				s = strings.TrimSpace(s)
				if val, err := strconv.Atoi(s); err == nil {
					bytes[i] = byte(val)
				}
			}

			addr := fmt.Sprintf("G%x", bytes)
			log.Printf("Extracted farmer address from tx_meta Ed25519: %s", addr)
			return addr
		}
	}

	// Check SorobanMeta for events with addresses
	if sorobanMeta, ok := data["soroban_meta"].(map[string]interface{}); ok {
		log.Printf("Soroban meta structure: %s", prettyPrint(sorobanMeta))

		// Check events for addresses
		if events, ok := sorobanMeta["Events"].([]interface{}); ok {
			for _, event := range events {
				eventMap, ok := event.(map[string]interface{})
				if !ok {
					continue
				}

				if body, ok := eventMap["Body"].(map[string]interface{}); ok {
					if v0, ok := body["V0"].(map[string]interface{}); ok {
						if topics, ok := v0["Topics"].([]interface{}); ok {
							// Check each topic for an address
							for _, topic := range topics {
								topicMap, ok := topic.(map[string]interface{})
								if !ok {
									continue
								}

								if addr, ok := topicMap["Address"].(map[string]interface{}); ok {
									// Try to get the AccountId
									if accountId, ok := addr["AccountId"].(map[string]interface{}); ok {
										if ed25519, ok := accountId["Ed25519"].([]interface{}); ok {
											// Convert bytes to address
											bytes := make([]byte, len(ed25519))
											for i, b := range ed25519 {
												if val, ok := b.(float64); ok {
													bytes[i] = byte(val)
												}
											}

											addr := fmt.Sprintf("G%x", bytes)
											log.Printf("Extracted farmer address from event topics: %s", addr)
											return addr
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

	// If we couldn't find the address, try to use transaction hash as a fallback
	if txHash, ok := data["transaction_hash"].(string); ok {
		addr := fmt.Sprintf("tx:%s", txHash)
		log.Printf("Using transaction hash as farmer ID: %s", addr)
		return addr
	}

	// Nothing found
	log.Printf("Could not extract farmer address")
	return ""
}

// prettyPrint formats a complex structure for logging
func prettyPrint(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
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

// ForwardMetrics forwards metrics for a block
func (p *KaleMetricsProcessor) ForwardMetrics(blockIndex uint32, eventType string, data map[string]interface{}) {
	log.Printf("Forwarding metrics for block %d, event type: %s", blockIndex, eventType)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get or create metrics for this block
	metrics := p.getOrCreateBlockMetrics(blockIndex)

	// Extract farmer address
	farmerAddr := "unknown"
	addrStr := extractFarmerAddress(data)
	if addrStr != "" {
		farmerAddr = addrStr
		log.Printf("Using farmer address: %s for block %d", farmerAddr, blockIndex)
	} else {
		log.Printf("Could not extract farmer address for block %d, defaulting to unknown", blockIndex)
	}

	// Update metrics based on event type
	switch eventType {
	case "plant":
		// Extract stake amount
		stakeAmount := int64(0)

		// First try arguments
		if args, ok := data["arguments"].([]interface{}); ok && len(args) >= 2 {
			// Second argument is typically the stake amount in plant calls
			argStr, _ := json.Marshal(args[1])

			// Look for I128 value
			i128Regex := regexp.MustCompile(`"I128"\s*:\s*\{\s*"Hi"\s*:\s*\d+\s*,\s*"Lo"\s*:\s*(\d+)`)
			matches := i128Regex.FindStringSubmatch(string(argStr))
			if len(matches) > 1 {
				if val, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
					stakeAmount = val
					log.Printf("Extracted stake amount %d from argument I128", stakeAmount)
				}
			}
		}

		// If not found in arguments, try temporary_data
		if stakeAmount == 0 {
			if tempData, ok := data["temporary_data"].([]interface{}); ok {
				for _, entry := range tempData {
					if entryMap, ok := entry.(map[string]interface{}); ok {
						if valueMap, ok := entryMap["value"].(map[string]interface{}); ok {
							if mapVal, ok := valueMap["Map"].([]interface{}); ok {
								for _, kv := range mapVal {
									if kvMap, ok := kv.(map[string]interface{}); ok {
										if keyMap, ok := kvMap["Key"].(map[string]interface{}); ok {
											if sym, ok := keyMap["Sym"].(string); ok && sym == "stake" {
												if valMap, ok := kvMap["Val"].(map[string]interface{}); ok {
													if i128, ok := valMap["I128"].(map[string]interface{}); ok {
														if lo, ok := i128["Lo"].(float64); ok {
															stakeAmount = int64(lo)
															log.Printf("Extracted stake amount %d from temporary data", stakeAmount)
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

		// If still not found, try SorobanMeta
		if stakeAmount == 0 {
			if sorobanMeta, ok := data["soroban_meta"].(map[string]interface{}); ok {
				if returnVal, ok := sorobanMeta["ReturnValue"].(map[string]interface{}); ok {
					if i128, ok := returnVal["I128"].(map[string]interface{}); ok {
						if lo, ok := i128["Lo"].(float64); ok {
							stakeAmount = int64(lo)
							log.Printf("Extracted stake amount %d from SorobanMeta ReturnValue", stakeAmount)
						}
					}
				}
			}
		}

		// Update metrics with farmer and stake
		p.mu.Lock()
		if !contains(metrics.Farmers, farmerAddr) {
			metrics.Farmers = append(metrics.Farmers, farmerAddr)
			metrics.Participants = len(metrics.Farmers)
		}

		// Update stake
		metrics.FarmerStakes[farmerAddr] = stakeAmount
		metrics.TotalStaked += stakeAmount
		metrics.TransactionHash = getTransactionHash(data)

		// Set open time if not already set
		if metrics.OpenTimeMs == 0 {
			metrics.OpenTimeMs = time.Now().UnixMilli()
		}
		p.mu.Unlock()

		log.Printf("Updated plant metrics for block %d: farmer=%s, stake=%d, participants=%d, totalStaked=%d",
			blockIndex, farmerAddr, stakeAmount, metrics.Participants, metrics.TotalStaked)

	case "work":
		// Extract zero count
		zeroCount := 0

		// Try to extract from arguments
		if args, ok := data["arguments"].([]interface{}); ok && len(args) >= 2 {
			// Extract hash from arguments and count zeros
			argStr, _ := json.Marshal(args[1])

			// Look for Bytes representation
			bytesRegex := regexp.MustCompile(`"Bytes"\s*:\s*\[([0-9,\s]+)\]`)
			matches := bytesRegex.FindStringSubmatch(string(argStr))
			if len(matches) > 1 {
				parts := strings.Split(matches[1], ",")
				bytes := make([]byte, len(parts))
				for i, s := range parts {
					s = strings.TrimSpace(s)
					if val, err := strconv.Atoi(s); err == nil {
						bytes[i] = byte(val)
					}
				}
				hexStr := fmt.Sprintf("%x", bytes)
				zeroCount = int(countLeadingZeros(hexStr))
				log.Printf("Extracted hash %s with %d leading zeros from argument bytes", hexStr, zeroCount)
			}
		}

		// If not found in arguments, check temporary_data
		if zeroCount == 0 {
			if tempData, ok := data["temporary_data"].([]interface{}); ok {
				for _, entry := range tempData {
					if entryMap, ok := entry.(map[string]interface{}); ok {
						if valueMap, ok := entryMap["value"].(map[string]interface{}); ok {
							if mapVal, ok := valueMap["Map"].([]interface{}); ok {
								for _, kv := range mapVal {
									if kvMap, ok := kv.(map[string]interface{}); ok {
										if keyMap, ok := kvMap["Key"].(map[string]interface{}); ok {
											if sym, ok := keyMap["Sym"].(string); ok && sym == "zeros" {
												if valMap, ok := kvMap["Val"].(map[string]interface{}); ok {
													if u32, ok := valMap["U32"].(float64); ok {
														zeroCount = int(u32)
														log.Printf("Extracted zero count %d from temporary data", zeroCount)
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

		// Update metrics with work data
		p.mu.Lock()
		if !contains(metrics.Farmers, farmerAddr) {
			metrics.Farmers = append(metrics.Farmers, farmerAddr)
			metrics.Participants = len(metrics.Farmers)
		}

		// Only update if count is greater than existing
		if zeroCount > metrics.FarmerZeroCounts[farmerAddr] {
			metrics.FarmerZeroCounts[farmerAddr] = zeroCount
			log.Printf("Updated zero count for farmer %s to %d", farmerAddr, zeroCount)
		}

		// Update highest zero count
		if zeroCount > metrics.HighestZeroCount {
			metrics.HighestZeroCount = zeroCount
			log.Printf("Updated highest zero count to %d", zeroCount)
		}

		// Update max/min zeros
		if uint32(zeroCount) > metrics.MaxZeros {
			metrics.MaxZeros = uint32(zeroCount)
		}
		if metrics.MinZeros == 0 || uint32(zeroCount) < metrics.MinZeros {
			metrics.MinZeros = uint32(zeroCount)
		}
		p.mu.Unlock()

		log.Printf("Updated work metrics for block %d: farmer=%s, zeros=%d, highestZeroCount=%d",
			blockIndex, farmerAddr, zeroCount, metrics.HighestZeroCount)

	case "harvest":
		// Extract reward amount
		rewardAmount := int64(0)

		// First try SorobanMeta events
		if sorobanMeta, ok := data["soroban_meta"].(map[string]interface{}); ok {
			log.Printf("Soroban meta structure: %s", prettyPrint(sorobanMeta))

			// Look for mint event in Events
			if events, ok := sorobanMeta["Events"].([]interface{}); ok {
				for _, event := range events {
					eventMap, ok := event.(map[string]interface{})
					if !ok {
						continue
					}

					if body, ok := eventMap["Body"].(map[string]interface{}); ok {
						if v0, ok := body["V0"].(map[string]interface{}); ok {
							if topics, ok := v0["Topics"].([]interface{}); ok && len(topics) > 0 {
								// Look for mint event
								topicMap, ok := topics[0].(map[string]interface{})
								if !ok {
									continue
								}

								if sym, ok := topicMap["Sym"].(string); ok && sym == "mint" {
									// Extract amount from data
									if eventData, ok := v0["Data"].(map[string]interface{}); ok {
										if i128, ok := eventData["I128"].(map[string]interface{}); ok {
											if lo, ok := i128["Lo"].(float64); ok {
												rewardAmount = int64(lo)
												log.Printf("Extracted reward amount %d from mint event", rewardAmount)
											}
										}
									}
								}
							}
						}
					}
				}
			}

			// If no event found, try ReturnValue
			if rewardAmount == 0 {
				if returnVal, ok := sorobanMeta["ReturnValue"].(map[string]interface{}); ok {
					if i128, ok := returnVal["I128"].(map[string]interface{}); ok {
						if lo, ok := i128["Lo"].(float64); ok {
							rewardAmount = int64(lo)
							log.Printf("Extracted reward amount %d from SorobanMeta ReturnValue", rewardAmount)
						}
					}
				}
			}
		}

		// Update metrics with harvest data
		p.mu.Lock()
		if !contains(metrics.Farmers, farmerAddr) {
			metrics.Farmers = append(metrics.Farmers, farmerAddr)
			metrics.Participants = len(metrics.Farmers)
		}

		// Update rewards
		metrics.FarmerRewards[farmerAddr] = rewardAmount
		metrics.TotalReward += rewardAmount

		// Set close time if not already set
		if metrics.CloseTimeMs == 0 {
			metrics.CloseTimeMs = time.Now().UnixMilli()

			// Calculate duration if open time is set
			if metrics.OpenTimeMs > 0 {
				metrics.Duration = metrics.CloseTimeMs - metrics.OpenTimeMs
				log.Printf("Calculated duration %d ms for block %d", metrics.Duration, blockIndex)
			}
		}
		p.mu.Unlock()

		log.Printf("Updated harvest metrics for block %d: farmer=%s, reward=%d, totalReward=%d",
			blockIndex, farmerAddr, rewardAmount, metrics.TotalReward)
	}

	// Forward to consumers
	log.Printf("Forwarding metrics for block %d to consumers", blockIndex)
	if err := p.forwardToConsumers(ctx, metrics); err != nil {
		log.Printf("Error forwarding metrics to consumers: %v", err)
	} else {
		log.Printf("Successfully forwarded metrics for block %d to consumers", blockIndex)
	}

	// Store updated block indices for retrieval
	p.mu.Lock()
	p.stats.LastBlockIndex = blockIndex
	p.stats.LastUpdated = time.Now()
	p.mu.Unlock()
}

// Helper function to get transaction hash from data
func getTransactionHash(data map[string]interface{}) string {
	if hash, ok := data["transaction_hash"].(string); ok {
		return hash
	}
	return ""
}
