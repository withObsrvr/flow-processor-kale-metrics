package main

// GetSchemaDefinition returns the GraphQL schema definition for the plugin.
func (p *KaleMetricsPlugin) GetSchemaDefinition() string {
	return `
type KaleBlockMetrics {
	blockIndex: Int!
	timestamp: String!
	totalStaked: String!
	totalReward: String!
	participants: Int!
	highestZeroCount: Int!
	closeTimeMs: String
	farmers: [String!]!
	maxZeros: Int!
	minZeros: Int
	openTimeMs: String
	duration: String
	transactionHash: String
	farmerStakes: JSON
	farmerRewards: JSON
	farmerZeroCounts: JSON
}

type KaleMetricsProcessorStatus {
	processedBlocks: Int!
	lastBlockIndex: Int
	lastUpdated: String
	consumers: Int!
	uptime: String!
	contractId: String
}

scalar JSON
`
}

// GetQueryDefinitions returns the GraphQL query definitions for the plugin.
func (p *KaleMetricsPlugin) GetQueryDefinitions() string {
	return `
	getKaleBlockMetrics(blockIndex: Int!): KaleBlockMetrics
	getAllKaleBlockMetrics: [KaleBlockMetrics!]!
	getKaleBlockMetricsByFarmer(farmer: String!): [KaleBlockMetrics!]!
	getKaleMetricsProcessorStatus: KaleMetricsProcessorStatus!
`
}

// ResolveQuery resolves GraphQL queries for the plugin.
func (p *KaleMetricsPlugin) ResolveQuery(query string, args map[string]interface{}) (interface{}, error) {
	switch query {
	case "getKaleBlockMetrics":
		blockIndex, ok := args["blockIndex"].(int)
		if !ok {
			return nil, NewProcessorError(
				nil,
				ErrorTypeParsing,
				ErrorSeverityError,
			).WithContext("message", "Invalid block index provided")
		}
		return p.processor.GetBlockMetrics(uint32(blockIndex))

	case "getAllKaleBlockMetrics":
		metrics := p.processor.GetAllBlockMetrics()
		result := make([]KaleBlockMetrics, 0, len(metrics))
		for _, m := range metrics {
			result = append(result, *m)
		}
		return result, nil

	case "getKaleBlockMetricsByFarmer":
		farmer, ok := args["farmer"].(string)
		if !ok {
			return nil, NewProcessorError(
				nil,
				ErrorTypeParsing,
				ErrorSeverityError,
			).WithContext("message", "Invalid farmer address provided")
		}

		metrics := p.processor.GetAllBlockMetrics()
		result := make([]KaleBlockMetrics, 0)

		for _, m := range metrics {
			// Check if the farmer is in the list of farmers for this block
			for _, f := range m.Farmers {
				if f == farmer {
					result = append(result, *m)
					break
				}
			}
		}

		return result, nil

	case "getKaleMetricsProcessorStatus":
		return p.processor.GetStatus(), nil

	default:
		return nil, NewProcessorError(
			nil,
			ErrorTypeParsing,
			ErrorSeverityError,
		).WithContext("message", "Unknown query: "+query)
	}
}
