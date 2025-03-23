package main

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// KaleDataType represents the type of Kale contract data being extracted
type KaleDataType string

const (
	// KaleDataTypePlant represents data from plant operations
	KaleDataTypePlant KaleDataType = "plant"
	// KaleDataTypeWork represents data from work operations
	KaleDataTypeWork KaleDataType = "work"
	// KaleDataTypeHarvest represents data from harvest operations
	KaleDataTypeHarvest KaleDataType = "harvest"
	// KaleDataTypePail represents data from Pail temporary storage
	KaleDataTypePail KaleDataType = "pail"
)

// KalePlantData represents data from a plant operation
type KalePlantData struct {
	BlockIndex  uint32
	Farmer      string
	StakeAmount int64
	Timestamp   time.Time
	IsValid     bool
}

// KaleWorkData represents data from a work operation
type KaleWorkData struct {
	BlockIndex    uint32
	Farmer        string
	HashValue     string
	ZeroCount     uint32
	Timestamp     time.Time
	IsValid       bool
	TransactionID string
}

// KaleHarvestData represents data from a harvest operation
type KaleHarvestData struct {
	BlockIndex   uint32
	Farmer       string
	RewardAmount int64
	Timestamp    time.Time
	IsValid      bool
}

// KalePailData represents data from Pail temporary storage
type KalePailData struct {
	BlockIndex  uint32
	Entropy     string
	Farmers     []string
	OpenTimeMs  int64
	CloseTimeMs int64
	IsValid     bool
}

// ExtractBlockIndex extracts the block index from various data formats
// Returns the extracted index and a boolean indicating success
func ExtractBlockIndex(data interface{}, dataType KaleDataType) (uint32, bool) {
	log.Printf("Extracting block index from %s data", dataType)

	switch v := data.(type) {
	case map[string]interface{}:
		// First check direct block_index field (most common)
		if index, ok := v["block_index"]; ok {
			log.Printf("Found block_index field in %s data", dataType)
			switch idx := index.(type) {
			case float64:
				return uint32(idx), true
			case int:
				return uint32(idx), true
			case string:
				if val, err := strconv.ParseUint(idx, 10, 32); err == nil {
					return uint32(val), true
				}
			case map[string]interface{}:
				// Check for Soroban style U32/U64/etc. format
				if u32Val, ok := idx["U32"].(float64); ok {
					return uint32(u32Val), true
				}
				if u64Val, ok := idx["U64"].(float64); ok {
					return uint32(u64Val), true
				}
				if strVal, ok := idx["String"].(string); ok {
					if val, err := strconv.ParseUint(strVal, 10, 32); err == nil {
						return uint32(val), true
					}
				}
			}
		}

		// For specific data types, check for other ways to extract the block index
		switch dataType {
		case KaleDataTypeHarvest:
			// For harvest invocations, check arguments array
			if args, ok := v["arguments"].([]interface{}); ok && len(args) >= 2 {
				// The second argument is typically the block index
				if arg, ok := args[1].(map[string]interface{}); ok {
					if u32Val, ok := arg["U32"].(float64); ok {
						log.Printf("Extracted block index %d from harvest arguments[1]", uint32(u32Val))
						return uint32(u32Val), true
					}
				}
			}

		case KaleDataTypePail:
			// For Pail data, search temporary_data
			if tempData, ok := v["temporary_data"].([]interface{}); ok {
				for _, entry := range tempData {
					if entryMap, ok := entry.(map[string]interface{}); ok {
						if key, ok := entryMap["key"].(string); ok && strings.Contains(key, "Pail") {
							// Try to extract from key
							re := regexp.MustCompile(`\b(\d{5})\b`)
							matches := re.FindStringSubmatch(key)
							if len(matches) > 1 {
								if val, err := strconv.ParseUint(matches[1], 10, 32); err == nil {
									log.Printf("Extracted block index %d from Pail key", uint32(val))
									return uint32(val), true
								}
							}

							// Try to extract from value
							if value, ok := entryMap["value"].(map[string]interface{}); ok {
								if u32Val, ok := value["U32"].(float64); ok {
									log.Printf("Extracted block index %d from Pail value", uint32(u32Val))
									return uint32(u32Val), true
								}
							}
						}
					}
				}
			}
		}

		// As a fallback, look for any key containing "index" or "block"
		for key, value := range v {
			if strings.Contains(strings.ToLower(key), "index") || strings.Contains(strings.ToLower(key), "block") {
				switch val := value.(type) {
				case float64:
					log.Printf("Extracted block index %d from field %s", uint32(val), key)
					return uint32(val), true
				case int:
					log.Printf("Extracted block index %d from field %s", uint32(val), key)
					return uint32(val), true
				case string:
					if intVal, err := strconv.ParseUint(val, 10, 32); err == nil {
						log.Printf("Extracted block index %d from field %s", uint32(intVal), key)
						return uint32(intVal), true
					}
				case map[string]interface{}:
					if u32Val, ok := val["U32"].(float64); ok {
						log.Printf("Extracted block index %d from field %s", uint32(u32Val), key)
						return uint32(u32Val), true
					}
				}
			}
		}
	}

	log.Printf("Failed to extract block index from %s data", dataType)
	return 0, false
}

// ExtractFarmerAddress extracts a farmer address from various data formats
// Returns the extracted address and a boolean indicating success
func ExtractFarmerAddress(data interface{}) (string, bool) {
	log.Printf("Extracting farmer address")

	switch v := data.(type) {
	case map[string]interface{}:
		// Check direct farmer field
		if farmer, ok := v["farmer"]; ok {
			switch f := farmer.(type) {
			case string:
				if f != "" {
					log.Printf("Extracted farmer address: %s", f)
					return f, true
				}
			case map[string]interface{}:
				// Check for Address field (common in contract invocations)
				if addr, ok := f["Address"].(map[string]interface{}); ok {
					if account, ok := addr["Account"].(map[string]interface{}); ok {
						if pub, ok := account["PublicKeyEd25519"].(string); ok && pub != "" {
							log.Printf("Extracted farmer address from nested structure: %s", pub)
							return pub, true
						}
					}
				}
			}
		}

		// Check arguments array (common in contract invocations)
		if args, ok := v["arguments"].([]interface{}); ok && len(args) > 0 {
			// The first argument is typically the farmer address
			if arg, ok := args[0].(map[string]interface{}); ok {
				if addr, ok := arg["Address"].(map[string]interface{}); ok {
					if account, ok := addr["Account"].(map[string]interface{}); ok {
						if pub, ok := account["PublicKeyEd25519"].(string); ok && pub != "" {
							log.Printf("Extracted farmer address from arguments: %s", pub)
							return pub, true
						}
					}
				}
				// It could also be a string
				if str, ok := arg["String"].(string); ok && str != "" {
					log.Printf("Extracted farmer address from arguments: %s", str)
					return str, true
				}
			}
			// It could be a direct string
			if str, ok := args[0].(string); ok && str != "" {
				log.Printf("Extracted farmer address from arguments: %s", str)
				return str, true
			}
		}

		// As a fallback, check for any key that might contain a farmer address
		for key, value := range v {
			if strings.Contains(strings.ToLower(key), "account") ||
				strings.Contains(strings.ToLower(key), "address") ||
				strings.Contains(strings.ToLower(key), "farmer") {
				if str, ok := value.(string); ok && str != "" &&
					(strings.HasPrefix(str, "G") || strings.HasPrefix(str, "C")) {
					log.Printf("Extracted potential farmer address from field %s: %s", key, str)
					return str, true
				}
			}
		}
	}

	log.Printf("Failed to extract farmer address")
	return "", false
}

// ExtractAmount extracts an amount (stake or reward) from various data formats
// Returns the extracted amount and a boolean indicating success
func ExtractAmount(data interface{}, amountType string) (int64, bool) {
	log.Printf("Extracting %s amount", amountType)

	// First, look for the exact field
	switch v := data.(type) {
	case map[string]interface{}:
		// Check direct fields
		fieldNames := []string{amountType, amountType + "_amount", amountType + "Amount"}
		for _, fieldName := range fieldNames {
			if amount, ok := v[fieldName]; ok {
				switch amt := amount.(type) {
				case float64:
					log.Printf("Extracted %s amount: %d", amountType, int64(amt))
					return int64(amt), true
				case int64:
					log.Printf("Extracted %s amount: %d", amountType, amt)
					return amt, true
				case int:
					log.Printf("Extracted %s amount: %d", amountType, int64(amt))
					return int64(amt), true
				case string:
					if val, err := strconv.ParseInt(amt, 10, 64); err == nil {
						log.Printf("Extracted %s amount: %d", amountType, val)
						return val, true
					}
				case map[string]interface{}:
					// Check for I128 format (common in Stellar/Soroban)
					if i128, ok := amt["I128"].(map[string]interface{}); ok {
						if lo, ok := i128["Lo"].(float64); ok {
							log.Printf("Extracted %s amount from I128: %d", amountType, int64(lo))
							return int64(lo), true
						}
					}
					// Check for U64 format
					if u64Val, ok := amt["U64"].(float64); ok {
						log.Printf("Extracted %s amount from U64: %d", amountType, int64(u64Val))
						return int64(u64Val), true
					}
					// Check for U32 format
					if u32Val, ok := amt["U32"].(float64); ok {
						log.Printf("Extracted %s amount from U32: %d", amountType, int64(u32Val))
						return int64(u32Val), true
					}
				}
			}
		}

		// For specific amount types, check other paths
		switch amountType {
		case "stake":
			// Plant events often have the stake in the data field
			if data, ok := v["data"].(map[string]interface{}); ok {
				if stake, ok := data["stake"]; ok {
					switch s := stake.(type) {
					case float64:
						return int64(s), true
					case int64:
						return s, true
					case int:
						return int64(s), true
					}
				}
			}

		case "reward":
			// Harvest events may have rewards in diagnostic events
			if events, ok := v["diagnostic_events"].([]interface{}); ok {
				for _, event := range events {
					if eventMap, ok := event.(map[string]interface{}); ok {
						if eventType, ok := eventMap["type"].(string); ok &&
							(eventType == "mint" || strings.Contains(strings.ToLower(eventType), "reward")) {
							if eventData, ok := eventMap["data"].(map[string]interface{}); ok {
								if amount, ok := eventData["amount"]; ok {
									switch amt := amount.(type) {
									case float64:
										return int64(amt), true
									case int64:
										return amt, true
									case int:
										return int64(amt), true
									}
								}
							}
						}
					}
				}
			}
		}
	}

	log.Printf("Failed to extract %s amount", amountType)
	return 0, false
}

// ExtractPlantData extracts all relevant data from a plant operation
func ExtractPlantData(data map[string]interface{}) KalePlantData {
	result := KalePlantData{
		Timestamp: time.Now(),
		IsValid:   false,
	}

	// Extract the block index
	blockIndex, blockFound := ExtractBlockIndex(data, KaleDataTypePlant)
	if !blockFound {
		log.Printf("Failed to extract block index from plant data")
		return result
	}
	result.BlockIndex = blockIndex

	// Extract the farmer address
	farmer, farmerFound := ExtractFarmerAddress(data)
	if !farmerFound {
		log.Printf("Failed to extract farmer address from plant data")
		return result
	}
	result.Farmer = farmer

	// Extract the stake amount
	stake, stakeFound := ExtractAmount(data, "stake")
	if !stakeFound {
		log.Printf("Failed to extract stake amount from plant data")
		return result
	}
	result.StakeAmount = stake

	// All required fields were found
	result.IsValid = true
	log.Printf("Successfully extracted plant data: Block=%d, Farmer=%s, Stake=%d",
		result.BlockIndex, result.Farmer, result.StakeAmount)

	return result
}

// ExtractWorkData extracts all relevant data from a work operation
func ExtractWorkData(data map[string]interface{}) KaleWorkData {
	result := KaleWorkData{
		Timestamp: time.Now(),
		IsValid:   false,
	}

	// Extract the block index
	blockIndex, blockFound := ExtractBlockIndex(data, KaleDataTypeWork)
	if !blockFound {
		log.Printf("Failed to extract block index from work data")
		return result
	}
	result.BlockIndex = blockIndex

	// Extract the farmer address
	farmer, farmerFound := ExtractFarmerAddress(data)
	if !farmerFound {
		log.Printf("Failed to extract farmer address from work data")
		return result
	}
	result.Farmer = farmer

	// Extract the transaction ID if available
	if txHash, ok := data["transaction_hash"].(string); ok {
		result.TransactionID = txHash
	}

	// Extract the hash value and count zeros
	hashFound := false
	if eventData, ok := data["data"].(map[string]interface{}); ok {
		if hash, ok := eventData["hash"].(string); ok && hash != "" {
			result.HashValue = hash
			result.ZeroCount = countLeadingZeros(hash)
			hashFound = true
		}
	}

	// If we couldn't find the hash directly, check other fields
	if !hashFound {
		for key, value := range data {
			if strings.Contains(strings.ToLower(key), "hash") && key != "transaction_hash" {
				if hash, ok := value.(string); ok && hash != "" {
					result.HashValue = hash
					result.ZeroCount = countLeadingZeros(hash)
					hashFound = true
					break
				}
			}
		}
	}

	if !hashFound {
		log.Printf("Failed to extract hash value from work data")
		return result
	}

	// All required fields were found
	result.IsValid = true
	log.Printf("Successfully extracted work data: Block=%d, Farmer=%s, ZeroCount=%d",
		result.BlockIndex, result.Farmer, result.ZeroCount)

	return result
}

// ExtractHarvestData extracts all relevant data from a harvest operation
func ExtractHarvestData(data map[string]interface{}) KaleHarvestData {
	result := KaleHarvestData{
		Timestamp: time.Now(),
		IsValid:   false,
	}

	// Extract the block index
	blockIndex, blockFound := ExtractBlockIndex(data, KaleDataTypeHarvest)
	if !blockFound {
		log.Printf("Failed to extract block index from harvest data")
		return result
	}
	result.BlockIndex = blockIndex

	// Extract the farmer address
	farmer, farmerFound := ExtractFarmerAddress(data)
	if !farmerFound {
		log.Printf("Failed to extract farmer address from harvest data")
		return result
	}
	result.Farmer = farmer

	// Extract the reward amount
	reward, rewardFound := ExtractAmount(data, "reward")
	if !rewardFound {
		log.Printf("Failed to extract reward amount from harvest data")
		return result
	}
	result.RewardAmount = reward

	// All required fields were found
	result.IsValid = true
	log.Printf("Successfully extracted harvest data: Block=%d, Farmer=%s, Reward=%d",
		result.BlockIndex, result.Farmer, result.RewardAmount)

	return result
}

// ExtractPailData extracts all relevant data from Pail temporary storage
func ExtractPailData(data map[string]interface{}) KalePailData {
	result := KalePailData{
		IsValid: false,
		Farmers: []string{},
	}

	// Extract the block index
	blockIndex, blockFound := ExtractBlockIndex(data, KaleDataTypePail)
	if !blockFound {
		log.Printf("Failed to extract block index from Pail data")
		return result
	}
	result.BlockIndex = blockIndex

	// Look for close_time in diagnostic events
	if diagEvents, ok := data["diagnostic_events"].([]interface{}); ok {
		result.CloseTimeMs = extractCloseTimeMs(diagEvents)
	}

	// All required fields were found (block index is the minimum)
	result.IsValid = true
	log.Printf("Successfully extracted Pail data: Block=%d", result.BlockIndex)

	return result
}

// ValidateDataFormat checks if data has the minimum required fields and format
// Returns a boolean indicating if the data is valid, and a string with the reason if invalid
func ValidateDataFormat(data map[string]interface{}, dataType KaleDataType) (bool, string) {
	// Common validations for all data types
	if data == nil {
		return false, "data is nil"
	}

	if len(data) == 0 {
		return false, "data is empty"
	}

	// Specific validations based on data type
	switch dataType {
	case KaleDataTypeHarvest:
		// For harvest, we need function_name and arguments
		if functionName, ok := data["function_name"].(string); !ok || functionName != "harvest" {
			return false, fmt.Sprintf("expected function_name 'harvest', got '%v'", data["function_name"])
		}

		if args, ok := data["arguments"].([]interface{}); !ok || len(args) < 2 {
			return false, "harvest requires at least 2 arguments"
		}

	case KaleDataTypePlant:
		// For plant, we need either topic or function_name
		if topic, ok := data["topic"].([]interface{}); ok {
			// Check if any topic is "plant"
			found := false
			for _, t := range topic {
				if tMap, ok := t.(map[string]interface{}); ok {
					if sym, ok := tMap["Symbol"].(string); ok && sym == "plant" {
						found = true
						break
					}
				}
			}
			if !found {
				return false, "topic does not contain 'plant'"
			}
		} else if functionName, ok := data["function_name"].(string); !ok || functionName != "plant" {
			return false, fmt.Sprintf("expected function_name 'plant', got '%v'", data["function_name"])
		}

	case KaleDataTypeWork:
		// For work, we need either topic or function_name
		if topic, ok := data["topic"].([]interface{}); ok {
			// Check if any topic is "work"
			found := false
			for _, t := range topic {
				if tMap, ok := t.(map[string]interface{}); ok {
					if sym, ok := tMap["Symbol"].(string); ok && sym == "work" {
						found = true
						break
					}
				}
			}
			if !found {
				return false, "topic does not contain 'work'"
			}
		} else if functionName, ok := data["function_name"].(string); !ok || functionName != "work" {
			return false, fmt.Sprintf("expected function_name 'work', got '%v'", data["function_name"])
		}

	case KaleDataTypePail:
		// For Pail, we need to check for temporary_data or similar fields
		hasPailData := false

		// Check for temporary_data
		if tempData, ok := data["temporary_data"].([]interface{}); ok {
			for _, entry := range tempData {
				if entryMap, ok := entry.(map[string]interface{}); ok {
					if key, ok := entryMap["key"].(string); ok && strings.Contains(key, "Pail") {
						hasPailData = true
						break
					}
				}
			}
		}

		// Check for soroban_meta.temporary_entries
		if !hasPailData {
			if meta, ok := data["soroban_meta"].(map[string]interface{}); ok {
				if entries, ok := meta["temporary_entries"].([]interface{}); ok {
					for _, entry := range entries {
						if entryMap, ok := entry.(map[string]interface{}); ok {
							if key, ok := entryMap["key"].(string); ok && strings.Contains(key, "Pail") {
								hasPailData = true
								break
							}
						}
					}
				}
			}
		}

		// Search contract data
		if !hasPailData {
			if txMeta, ok := data["tx_meta"].(map[string]interface{}); ok {
				if changes, ok := txMeta["changes"].([]interface{}); ok {
					for _, change := range changes {
						if changeMap, ok := change.(map[string]interface{}); ok {
							if entryType, ok := changeMap["type"].(string); ok && entryType == "temporary" {
								if key, ok := changeMap["key"].(string); ok && strings.Contains(key, "Pail") {
									hasPailData = true
									break
								}
							}
						}
					}
				}
			}
		}

		if !hasPailData {
			return false, "no Pail data found in temporary entries"
		}
	}

	// If we made it here, the data is valid
	return true, ""
}
