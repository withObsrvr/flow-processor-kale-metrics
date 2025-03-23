package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

// contains checks if a slice contains an item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// extractCloseTimeMs extracts the close time from diagnostic events
func extractCloseTimeMs(diagnosticEvents []interface{}) int64 {
	for _, eventRaw := range diagnosticEvents {
		event, ok := eventRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Look for close_time in event data
		if opType, ok := event["type"].(string); ok && opType == "log" {
			if dataRaw, ok := event["data"].(map[string]interface{}); ok {
				if msg, ok := dataRaw["msg"].(string); ok {
					if strings.Contains(msg, "close_time") {
						// Try to extract close time from log message
						parts := strings.Split(msg, ":")
						if len(parts) >= 2 {
							timeStr := strings.TrimSpace(parts[1])
							if closeTime, err := strconv.ParseInt(timeStr, 10, 64); err == nil {
								return closeTime
							}
						}
					}
				}
			}
		}
	}
	return 0
}

// countLeadingZeros counts the number of leading zeros in a hex string
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
			// Handle odd-length strings by padding with 0
			byteStr := cleanedStr[i:] + "0"
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
		} else {
			// Normal case - process a full byte
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
	}

	log.Printf("Counted %d leading zeros in hash: %s", count, s)
	return count
}

// max returns the larger of two uint32 values
func maxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

// min returns the smaller of two uint32 values
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// parseAmount parses an amount from various formats
func parseAmount(val interface{}) int64 {
	log.Printf("Parsing amount from: %v (type: %T)", val, val)

	switch v := val.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
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
	case map[string]interface{}:
		// Try to extract from I128 format (common in Stellar)
		if i128, ok := v["I128"].(map[string]interface{}); ok {
			if lo, ok := i128["Lo"].(float64); ok {
				return int64(lo)
			}
		}

		// Try to extract from U64 format
		if u64Val, ok := v["U64"].(float64); ok {
			return int64(u64Val)
		}

		// Try to extract from U32 format
		if u32Val, ok := v["U32"].(float64); ok {
			return int64(u32Val)
		}

		// Try to extract from String format
		if strVal, ok := v["String"].(string); ok {
			// Parse as float first to handle decimal values
			f, err := strconv.ParseFloat(strVal, 64)
			if err == nil {
				return int64(f)
			}
		}

		// Try any numeric field
		for _, fieldVal := range v {
			if floatVal, ok := fieldVal.(float64); ok {
				return int64(floatVal)
			} else if intVal, ok := fieldVal.(int64); ok {
				return intVal
			} else if strVal, ok := fieldVal.(string); ok {
				// Try to parse as number
				f, err := strconv.ParseFloat(strVal, 64)
				if err == nil {
					return int64(f)
				}
			}
		}
	}

	return 0
}
