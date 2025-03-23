package main

import (
	"time"
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
	TransactionHash  string           `json:"transaction_hash"`
	FarmerStakes     map[string]int64 `json:"farmer_stakes"`      // Map of farmer address to stake amount
	FarmerRewards    map[string]int64 `json:"farmer_rewards"`     // Map of farmer address to reward amount
	FarmerZeroCounts map[string]int   `json:"farmer_zero_counts"` // Map of farmer address to zero count
}

// NewKaleBlockMetrics creates a new KaleBlockMetrics instance
func NewKaleBlockMetrics(blockIndex uint32) *KaleBlockMetrics {
	return &KaleBlockMetrics{
		BlockIndex:       blockIndex,
		Timestamp:        time.Now(),
		Participants:     0,
		HighestZeroCount: 0,
		Farmers:          []string{},
		FarmerStakes:     make(map[string]int64),
		FarmerRewards:    make(map[string]int64),
		FarmerZeroCounts: make(map[string]int),
		TransactionHash:  "",
	}
}
