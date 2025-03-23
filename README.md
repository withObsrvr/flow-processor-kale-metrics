# Flow Plugin: Kale Metrics Processor

A Flow processor plugin that extracts metrics from Kale contract events and invocations. This plugin monitors events related to planting, working, and harvesting in the Kale contract, collecting metrics such as total staked amounts, rewards, zero counts, and participant data per block.

## Features

- Extracts comprehensive metrics from Kale contract events and invocations
- Monitors plant, work, and harvest events to track the full lifecycle of Kale blocks
- Provides detailed per-block metrics including total staked, total rewards, and farmer participation
- Thread-safe implementation with robust error handling
- Exposes operational statistics for monitoring
- Implements the Flow Plugin API for seamless integration

## Configuration

```json
{
  "contract_id": "required-kale-contract-id",
  "metrics_ttl_seconds": 86400
}
```

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| contract_id | Yes | string | - | The contract ID of the Kale contract to monitor |
| metrics_ttl_seconds | No | int | 86400 | Time to live for metrics in seconds (86400 = 1 day) |

## Input & Output Schema

### Input

The plugin expects input messages with:
- Payload type: `[]byte` containing JSON data
- Expected formats:
  - Contract events with `plant`, `work`, or `harvest` topics
  - Contract invocations for the specified contract ID

Example event:
```json
{
  "topic": [
    {
      "Symbol": "plant"
    }
  ],
  "data": {
    "farmer": "G5EAPH4IFMMRW5CVHW4J5WEJZ7UKTKEHBMPGPNUFMKRQNMJLVDNQ",
    "stake": 1000000000,
    "index": 12345
  },
  "ledger_sequence": 12345,
  "transaction_hash": "abcdef1234567890",
  "contract_id": "kale-contract-id"
}
```

Example invocation:
```json
{
  "function_name": "harvest",
  "arguments": [
    "G5EAPH4IFMMRW5CVHW4J5WEJZ7UKTKEHBMPGPNUFMKRQNMJLVDNQ",
    {
      "U32": 12345
    }
  ],
  "ledger_sequence": 12346,
  "transaction_hash": "abcdef1234567891",
  "contract_id": "kale-contract-id",
  "diagnostic_events": [
    {
      "type": "mint",
      "data": {
        "amount": 500000000
      }
    }
  ]
}
```

### Output

The plugin produces messages with:
- Payload type: `[]byte` containing JSON-serialized KaleBlockMetrics
- Format: KaleBlockMetrics JSON structure

Example:
```json
{
  "block_index": 12345,
  "timestamp": "2023-05-01T12:34:56Z",
  "total_staked": 1000000000,
  "total_reward": 500000000,
  "participants": 1,
  "highest_zero_count": 4,
  "farmers": ["G5EAPH4IFMMRW5CVHW4J5WEJZ7UKTKEHBMPGPNUFMKRQNMJLVDNQ"],
  "max_zeros": 4,
  "min_zeros": 2,
  "open_time_ms": 1682946896000,
  "close_time_ms": 1682950496000,
  "duration": 3600000,
  "transaction_hash": "abcdef1234567891",
  "farmer_stakes": {
    "G5EAPH4IFMMRW5CVHW4J5WEJZ7UKTKEHBMPGPNUFMKRQNMJLVDNQ": 1000000000
  },
  "farmer_rewards": {
    "G5EAPH4IFMMRW5CVHW4J5WEJZ7UKTKEHBMPGPNUFMKRQNMJLVDNQ": 500000000
  },
  "farmer_zero_counts": {
    "G5EAPH4IFMMRW5CVHW4J5WEJZ7UKTKEHBMPGPNUFMKRQNMJLVDNQ": 4
  }
}
```

## Metrics & Monitoring

The plugin exposes these operational metrics:

| Metric | Type | Description |
|--------|------|-------------|
| processed_events | Counter | Total number of contract events processed |
| processed_invocations | Counter | Total number of contract invocations processed |
| failed_events | Counter | Total number of failed event processing attempts |
| failed_invocations | Counter | Total number of failed invocation processing attempts |
| processed_blocks | Counter | Total number of blocks with metrics |
| last_block_index | Gauge | Index of the last processed block |
| last_processed_time | Timestamp | Time of the last processed message |
| uptime | Duration | Time since the plugin was initialized |

## Development

### Prerequisites

- Go 1.23.4 or compatible
- CGO enabled for plugin support
- Access to the Flow pluginapi package

### Building

```bash
# Build directly with Go
go build -buildmode=plugin -o flow-processor-kale-metrics.so .

# Build with Nix (for reproducible builds)
nix build
# The plugin will be built at ./result/lib/flow-processor-kale-metrics.so

# Copy the plugin to your plugins directory
cp flow-processor-kale-metrics.so /path/to/flow/plugins/
```

### Project Structure

- `main.go`: Entry point with New() function
- `plugin.go`: Implementation of the Flow Plugin API
- `processor.go`: Core processor implementation
- `metrics.go`: Definition of metrics data structures
- `handlers.go`: Event and invocation message handlers
- `utils.go`: Utility functions
- `errors.go`: Error types and handling

### Error Handling

The plugin uses a robust error handling system with typed errors:

```go
// Example of error handling
if err != nil {
    return NewProcessorError(
        fmt.Errorf("error processing event: %w", err),
        ErrorTypeProcessing,
        ErrorSeverityError,
    ).WithTransaction(txHash).WithBlock(blockIndex)
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

### Plugin Interface

The plugin implements the Flow plugin interface, which requires a `New` function that returns a `pluginapi.Plugin`. This function is the entry point for the plugin framework.

```go
// New creates a new KaleMetricsPlugin
// This is the entry point for the plugin framework
func New() pluginapi.Plugin {
	return NewPlugin()
}
```

The `NewPlugin` function creates a new `KaleMetricsPlugin` instance, which implements the `pluginapi.Plugin` interface.

The plugin interface requires the following methods:
- `Name() string`: Returns the name of the plugin
- `Description() string`: Returns a description of the plugin
- `Version() string`: Returns the version of the plugin
- `ProcessMessage(ctx context.Context, msg pluginapi.Message) error`: Processes a message from the flow processor
- `Subscribe(consumer pluginapi.Processor)`: Registers a consumer to receive metrics
- `Unsubscribe(consumer pluginapi.Processor)`: Removes a consumer
- `Initialize(config map[string]interface{}) error`: Initializes the plugin with the given configuration
- `Init(ctx context.Context, config json.RawMessage) error`: Initializes the plugin
- `Type() pluginapi.PluginType`: Returns the type of the plugin
- `Close() error`: Cleans up resources