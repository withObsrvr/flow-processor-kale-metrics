# flow-processor-kale-metrics

A Flow processor plugin that processes contract invocations and events specifically from the Kale smart contract.

## Overview

This processor monitors the blockchain for Kale smart contract activities, capturing both contract invocations and contract events. It extracts key metrics from the contract operations such as:

- Plant operations (amount, farmer address)
- Work operations (farmer address, nonce, hash)
- Harvest operations (index, farmer, amount)

The processor provides dual representation of data (both raw and decoded) for maximum flexibility and stores Kale-specific metrics for easier analysis.

## Building with Nix

This project uses Nix for reproducible builds.

### Prerequisites

- [Nix package manager](https://nixos.org/download.html) with flakes enabled

### Building

1. Clone the repository:
```bash
git clone https://github.com/withObsrvr/flow-processor-kale-metrics.git
cd flow-processor-kale-metrics
```

2. Build with Nix:
```bash
nix build
```

The built plugin will be available at `./result/lib/flow-processor-kale-metrics.so`.

### Development

To enter a development shell with all dependencies:
```bash
nix develop
```

This will automatically vendor dependencies if needed and provide a shell with all necessary tools.

### Manual Build (Inside Nix Shell)

Once in the development shell, you can manually build the plugin:
```bash
go mod tidy
go mod vendor
go build -buildmode=plugin -o flow-processor-kale-metrics.so .
```

## Configuration

The processor requires the following configuration parameters:

```json
{
  "network_passphrase": "Public Global Stellar Network ; September 2015",
  "kale_contract_id": "CDL74RF5BLYR2YBLCCI7F5FB6TPSCLKEJUBSD2RSVWZ4YHF3VMFAIGWA"
}
```

Parameter | Required | Type | Default | Description
----------|----------|------|---------|------------
network_passphrase | Yes | string | - | The network passphrase for the Stellar network being processed
kale_contract_id | Yes | string | - | The ID of the Kale smart contract to monitor

## Data Output

### Contract Invocations

The processor outputs contract invocation data in the following format:

```json
{
  "transaction_hash": "ab01cd...",
  "transaction_id": 123456789,
  "successful": true,
  "ledger_sequence": 42,
  "closed_at": "2023-01-01T00:00:00Z",
  "network_passphrase": "Public Global Stellar Network ; September 2015",
  "contract_id": "CDL74RF5BLYR2YBLCCI7F5FB6TPSCLKEJUBSD2RSVWZ4YHF3VMFAIGWA",
  "operation_index": 0,
  "function_name": "plant",
  "parameters": [
    {
      "name": "param_0",
      "value": {
        "type": "scvI128",
        "value": "AAAAAAAAAAAAAAAAAAAAAA=="
      }
    }
  ],
  "kale_metrics": {
    "amount": "0",
    "farmer": "GBIIUZH63Z262QXGKJIP3ZU5DS7L4L2TBTYGPXRIGQXZAF25A72YNULL"
  }
}
```

### Contract Events

The processor outputs contract event data in the following format:

```json
{
  "transaction_hash": "ab01cd...",
  "transaction_id": 123456789,
  "successful": true,
  "ledger_sequence": 42,
  "closed_at": "2023-01-01T00:00:00Z",
  "network_passphrase": "Public Global Stellar Network ; September 2015",
  "contract_id": "CDL74RF5BLYR2YBLCCI7F5FB6TPSCLKEJUBSD2RSVWZ4YHF3VMFAIGWA",
  "event_index": 0,
  "operation_index": 0,
  "type": "contract",
  "type_code": 1,
  "topics": [ ... ],
  "topics_decoded": [ ... ],
  "data": { ... },
  "data_decoded": { ... },
  "function_name": "plant",
  "kale_metrics": {
    "farmer": "GBIIUZH63Z262QXGKJIP3ZU5DS7L4L2TBTYGPXRIGQXZAF25A72YNULL",
    "amount": "0"
  },
  "tags": {
    "contract_id": "CDL74RF5BLYR2YBLCCI7F5FB6TPSCLKEJUBSD2RSVWZ4YHF3VMFAIGWA",
    "event_type": "contract",
    "successful": "true",
    "function": "plant"
  }
}
```

## Troubleshooting

### Plugin Version Compatibility

Make sure the plugin is built with the exact same Go version that Flow uses. If you see an error like "plugin was built with a different version of package internal/goarch", check that your Go version matches the one used by the Flow application.

### CGO Required

Go plugins require CGO to be enabled. The Nix build and development shell handle this automatically, but if building manually outside of Nix, ensure you've set:
```bash
export CGO_ENABLED=1
```

### Vendoring Dependencies

For reliable builds, we recommend using vendored dependencies:
```bash
go mod vendor
git add vendor
``` 