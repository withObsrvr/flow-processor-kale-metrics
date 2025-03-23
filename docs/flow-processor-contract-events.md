# .gitignore

```
# If you prefer the allow list template instead of the deny list, see community template:
# https://github.com/github/gitignore/blob/main/community/Golang/Go.AllowList.gitignore
#
# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with `go test -c`
*.test

# Output of the go coverage tool, specifically when used with LiteIDE
*.out

# Dependency directories (remove the comment below to include it)
# vendor/

# Go workspace file
go.work
go.work.sum

# env file
.env

# Nix
result
result/
.direnv/

```

# flake.lock

```lock
{
  "nodes": {
    "flake-utils": {
      "inputs": {
        "systems": "systems"
      },
      "locked": {
        "lastModified": 1731533236,
        "narHash": "sha256-l0KFg5HjrsfsO/JpG+r7fRrqm12kzFHyUHqHCVpMMbI=",
        "owner": "numtide",
        "repo": "flake-utils",
        "rev": "11707dc2f618dd54ca8739b309ec4fc024de578b",
        "type": "github"
      },
      "original": {
        "owner": "numtide",
        "repo": "flake-utils",
        "type": "github"
      }
    },
    "nixpkgs": {
      "locked": {
        "lastModified": 1742395137,
        "narHash": "sha256-WWNNjCSzQCtATpCFEijm81NNG1xqlLMVbIzXAiZysbs=",
        "owner": "NixOS",
        "repo": "nixpkgs",
        "rev": "2a725d40de138714db4872dc7405d86457aa17ad",
        "type": "github"
      },
      "original": {
        "owner": "NixOS",
        "ref": "nixpkgs-unstable",
        "repo": "nixpkgs",
        "type": "github"
      }
    },
    "root": {
      "inputs": {
        "flake-utils": "flake-utils",
        "nixpkgs": "nixpkgs"
      }
    },
    "systems": {
      "locked": {
        "lastModified": 1681028828,
        "narHash": "sha256-Vy1rq5AaRuLzOxct8nz4T6wlgyUR7zLU309k9mBC768=",
        "owner": "nix-systems",
        "repo": "default",
        "rev": "da67096a3b9bf56a91d16901293e51ba5b49a27e",
        "type": "github"
      },
      "original": {
        "owner": "nix-systems",
        "repo": "default",
        "type": "github"
      }
    }
  },
  "root": "root",
  "version": 7
}

```

# flake.nix

```nix
{
  description = "Obsrvr Flow Plugin: Contract Events Processor";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = {
          default = pkgs.buildGoModule {
            pname = "flow-processor-contract-events";
            version = "0.1.0";
            src = ./.;
            
            # Use null to skip vendoring check initially or if using vendored deps
            vendorHash = null;
            
            # Disable hardening which is required for Go plugins
            hardeningDisable = [ "all" ];
            
            # Configure build environment for plugin compilation 
            preBuild = ''
              export CGO_ENABLED=1
            '';
            
            # Build as a shared library/plugin
            buildPhase = ''
              runHook preBuild
              # Use -mod=vendor if you have vendored dependencies
              go build -mod=vendor -buildmode=plugin -o flow-processor-contract-events.so .
              runHook postBuild
            '';

            # Custom install phase for the plugin
            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib
              cp flow-processor-contract-events.so $out/lib/
              # Also install a copy of go.mod for future reference
              mkdir -p $out/share
              cp go.mod $out/share/
              if [ -f go.sum ]; then
                cp go.sum $out/share/
              fi
              runHook postInstall
            '';
            
            # Add dependencies needed for the build
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ 
              # Add C library dependencies here if needed
            ];
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ 
            # Using Go 1.23 to match your go.mod requirements
            # Note: If 1.23 isn't available in nixpkgs, you may need to use the closest available version
            go_1_21
            pkg-config
            git
            gopls
            delve
          ];
          
          # Shell setup for development environment
          shellHook = ''
            # Enable CGO which is required for plugin mode
            export CGO_ENABLED=1
            
            # Helper to vendor dependencies - greatly improves build reliability
            if [ ! -d vendor ]; then
              echo "Vendoring dependencies..."
              go mod tidy
              go mod vendor
            fi
            
            echo "Development environment ready!"
            echo "To build the plugin manually: go build -buildmode=plugin -o flow-processor-contract-events.so ."
          '';
        };
      }
    );
} 
```

# go.mod

```mod
module github.com/withObsrvr/flow-processor-contract-events

go 1.23.4

require (
	github.com/stellar/go v0.0.0-20250311234916-385ac5aca1a4
	github.com/withObsrvr/pluginapi v0.0.0-20250303141549-e645e333195c
)

exclude google.golang.org/grpc/stats/opentelemetry v0.0.0-20241028142157-ada6787961b3

require (
	cel.dev/expr v0.22.0 // indirect
	cloud.google.com/go v0.119.0 // indirect
	cloud.google.com/go/auth v0.15.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.7 // indirect
	cloud.google.com/go/compute/metadata v0.6.0 // indirect
	cloud.google.com/go/iam v1.4.2 // indirect
	cloud.google.com/go/monitoring v1.24.1 // indirect
	cloud.google.com/go/storage v1.51.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.27.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.51.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.51.0 // indirect
	github.com/Masterminds/squirrel v1.5.4 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/aws/aws-sdk-go v1.55.6 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cncf/xds/go v0.0.0-20250121191232-2f005788dc42 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/djherbis/fscache v0.10.1 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.32.4 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/fsouza/fake-gcs-server v1.52.2 // indirect
	github.com/gavv/monotime v0.0.0-20190418164738-30dba4353424 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-sql-driver/mysql v1.9.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.14.1 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/jarcoal/httpmock v1.3.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jmoiron/sqlx v1.4.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/mattn/go-sqlite3 v1.14.24 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/onsi/gomega v1.36.2 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.21.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.63.0 // indirect
	github.com/prometheus/procfs v0.16.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/segmentio/go-loggly v0.5.1-0.20171222203950-eb91657e62b2 // indirect
	github.com/sergi/go-diff v1.3.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stellar/go-xdr v0.0.0-20231122183749-b53fb00bcac2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	github.com/valyala/fasthttp v1.59.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/yalp/jsonpath v0.0.0-20180802001716-5cc68e5049a0 // indirect
	github.com/yudai/gojsondiff v1.0.0 // indirect
	github.com/yudai/golcs v0.0.0-20170316035057-ecda9a501e82 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.35.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.60.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdoutmetric v1.34.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/oauth2 v0.28.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	google.golang.org/api v0.227.0 // indirect
	google.golang.org/genproto v0.0.0-20250313205543-e70fdf4c4cb4 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250313205543-e70fdf4c4cb4 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250313205543-e70fdf4c4cb4 // indirect
	google.golang.org/grpc v1.71.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/djherbis/atime.v1 v1.0.0 // indirect
	gopkg.in/djherbis/stream.v1 v1.3.1 // indirect
	gopkg.in/gavv/httpexpect.v1 v1.1.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	moul.io/http2curl v1.0.0 // indirect
)

```

# main.go

```go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/stellar/go/strkey"
	"github.com/stellar/go/toid"

	"github.com/stellar/go/ingest"
	"github.com/stellar/go/xdr"
	"github.com/withObsrvr/pluginapi"
)

// ErrorType defines the category of an error
type ErrorType string

const (
	// Configuration errors
	ErrorTypeConfig ErrorType = "config"
	// Network-related errors
	ErrorTypeNetwork ErrorType = "network"
	// Data parsing errors
	ErrorTypeParsing ErrorType = "parsing"
	// Event processing errors
	ErrorTypeProcessing ErrorType = "processing"
	// Consumer-related errors
	ErrorTypeConsumer ErrorType = "consumer"
)

// ErrorSeverity defines how critical an error is
type ErrorSeverity string

const (
	// Fatal errors that should stop processing
	ErrorSeverityFatal ErrorSeverity = "fatal"
	// Errors that can be logged but processing can continue
	ErrorSeverityWarning ErrorSeverity = "warning"
	// Informational issues that might be useful for debugging
	ErrorSeverityInfo ErrorSeverity = "info"
)

// ProcessorError represents a structured error with context
type ProcessorError struct {
	// Original error
	Err error
	// Type categorizes the error
	Type ErrorType
	// Severity indicates how critical the error is
	Severity ErrorSeverity
	// Transaction hash related to the error, if applicable
	TransactionHash string
	// Ledger sequence related to the error, if applicable
	LedgerSequence uint32
	// Contract ID related to the error, if applicable
	ContractID string
	// Additional context as key-value pairs
	Context map[string]interface{}
}

// Error satisfies the error interface
func (e *ProcessorError) Error() string {
	contextStr := ""
	for k, v := range e.Context {
		contextStr += fmt.Sprintf(" %s=%v", k, v)
	}

	idInfo := ""
	if e.TransactionHash != "" {
		idInfo += fmt.Sprintf(" tx=%s", e.TransactionHash)
	}
	if e.LedgerSequence > 0 {
		idInfo += fmt.Sprintf(" ledger=%d", e.LedgerSequence)
	}
	if e.ContractID != "" {
		idInfo += fmt.Sprintf(" contract=%s", e.ContractID)
	}

	return fmt.Sprintf("[%s:%s]%s%s: %v", e.Type, e.Severity, idInfo, contextStr, e.Err)
}

// Unwrap returns the original error
func (e *ProcessorError) Unwrap() error {
	return e.Err
}

// IsFatal returns true if the error is fatal
func (e *ProcessorError) IsFatal() bool {
	return e.Severity == ErrorSeverityFatal
}

// NewProcessorError creates a new processor error
func NewProcessorError(err error, errType ErrorType, severity ErrorSeverity) *ProcessorError {
	return &ProcessorError{
		Err:      err,
		Type:     errType,
		Severity: severity,
		Context:  make(map[string]interface{}),
	}
}

// WithTransaction adds transaction information to the error
func (e *ProcessorError) WithTransaction(hash string) *ProcessorError {
	e.TransactionHash = hash
	return e
}

// WithLedger adds ledger information to the error
func (e *ProcessorError) WithLedger(sequence uint32) *ProcessorError {
	e.LedgerSequence = sequence
	return e
}

// WithContract adds contract information to the error
func (e *ProcessorError) WithContract(id string) *ProcessorError {
	e.ContractID = id
	return e
}

// WithContext adds additional context to the error
func (e *ProcessorError) WithContext(key string, value interface{}) *ProcessorError {
	e.Context[key] = value
	return e
}

// ContractEvent represents an event emitted by a contract with both raw and decoded data
type ContractEvent struct {
	// Transaction context
	TransactionHash   string    `json:"transaction_hash"`
	TransactionID     int64     `json:"transaction_id"`
	Successful        bool      `json:"successful"`
	LedgerSequence    uint32    `json:"ledger_sequence"`
	ClosedAt          time.Time `json:"closed_at"`
	NetworkPassphrase string    `json:"network_passphrase"`

	// Event context
	ContractID         string `json:"contract_id"`
	EventIndex         int    `json:"event_index"`
	OperationIndex     int    `json:"operation_index"`
	InSuccessfulTxCall bool   `json:"in_successful_tx_call"`

	// Event type information
	Type     string `json:"type"`
	TypeCode int32  `json:"type_code"`

	// Event data - both raw and decoded
	Topics        []TopicData `json:"topics"`
	TopicsDecoded []TopicData `json:"topics_decoded"`
	Data          EventData   `json:"data"`
	DataDecoded   EventData   `json:"data_decoded"`

	// Raw XDR for archival and debugging
	EventXDR string `json:"event_xdr"`

	// Additional diagnostic data
	DiagnosticEvents []DiagnosticData `json:"diagnostic_events,omitempty"`

	// Metadata for querying and filtering
	Tags map[string]string `json:"tags,omitempty"`
}

// TopicData represents a structured topic with type information
type TopicData struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// EventData represents the data payload of a contract event
type EventData struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// DiagnosticData contains additional diagnostic information about an event
type DiagnosticData struct {
	Event                    json.RawMessage `json:"event"`
	InSuccessfulContractCall bool            `json:"in_successful_contract_call"`
	RawXDR                   string          `json:"raw_xdr,omitempty"`
}

// ContractEventProcessor handles processing of contract events from transactions
type ContractEventProcessor struct {
	networkPassphrase string
	consumers         []pluginapi.Consumer
	mu                sync.RWMutex
	stats             struct {
		ProcessedLedgers  uint32
		EventsFound       uint64
		SuccessfulEvents  uint64
		FailedEvents      uint64
		LastLedger        uint32
		LastProcessedTime time.Time
	}
}

func (p *ContractEventProcessor) Initialize(config map[string]interface{}) error {
	networkPassphrase, ok := config["network_passphrase"].(string)
	if !ok {
		return NewProcessorError(
			errors.New("missing network_passphrase in configuration"),
			ErrorTypeConfig,
			ErrorSeverityFatal,
		)
	}

	if networkPassphrase == "" {
		return NewProcessorError(
			errors.New("network_passphrase cannot be empty"),
			ErrorTypeConfig,
			ErrorSeverityFatal,
		)
	}

	p.networkPassphrase = networkPassphrase
	return nil
}

func (p *ContractEventProcessor) RegisterConsumer(consumer pluginapi.Consumer) {
	log.Printf("ContractEventProcessor: Registering consumer %s", consumer.Name())
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consumers = append(p.consumers, consumer)
}

func (p *ContractEventProcessor) Process(ctx context.Context, msg pluginapi.Message) error {
	// Check for canceled context before starting work
	if err := ctx.Err(); err != nil {
		return NewProcessorError(
			fmt.Errorf("context canceled before processing: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityFatal,
		)
	}

	ledgerCloseMeta, ok := msg.Payload.(xdr.LedgerCloseMeta)
	if !ok {
		return NewProcessorError(
			fmt.Errorf("expected xdr.LedgerCloseMeta, got %T", msg.Payload),
			ErrorTypeParsing,
			ErrorSeverityFatal,
		)
	}

	sequence := ledgerCloseMeta.LedgerSequence()
	log.Printf("Processing ledger %d for contract events", sequence)

	txReader, err := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(p.networkPassphrase, ledgerCloseMeta)
	if err != nil {
		return NewProcessorError(
			fmt.Errorf("error creating transaction reader: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityFatal,
		).WithLedger(sequence)
	}
	defer txReader.Close()

	// Process each transaction with context handling
	for {
		// Check for context cancellation periodically
		if err := ctx.Err(); err != nil {
			return NewProcessorError(
				fmt.Errorf("context canceled during processing: %w", err),
				ErrorTypeProcessing,
				ErrorSeverityFatal,
			).WithLedger(sequence)
		}

		tx, err := txReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Continue processing despite transaction read errors
			procErr := NewProcessorError(
				fmt.Errorf("error reading transaction: %w", err),
				ErrorTypeProcessing,
				ErrorSeverityWarning,
			).WithLedger(sequence)
			log.Printf("Warning: %s", procErr.Error())
			continue
		}

		txHash := tx.Result.TransactionHash.HexString()

		// Get diagnostic events from transaction
		diagnosticEvents, err := tx.GetDiagnosticEvents()
		if err != nil {
			procErr := NewProcessorError(
				fmt.Errorf("error getting diagnostic events: %w", err),
				ErrorTypeProcessing,
				ErrorSeverityWarning,
			).WithLedger(sequence).WithTransaction(txHash)
			log.Printf("Warning: %s", procErr.Error())
			continue
		}

		// Process events
		for opIdx, events := range filterContractEvents(diagnosticEvents) {
			for eventIdx, event := range events {
				// Process with context timeout for individual event processing
				eventCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				contractEvent, err := p.processContractEvent(eventCtx, tx, opIdx, eventIdx, event, ledgerCloseMeta)
				cancel() // Always cancel to avoid context leak

				if err != nil {
					var procErr *ProcessorError
					if !errors.As(err, &procErr) {
						// Wrap the error if it's not already a ProcessorError
						procErr = NewProcessorError(
							err,
							ErrorTypeProcessing,
							ErrorSeverityWarning,
						)
					}

					procErr.WithLedger(sequence).WithTransaction(txHash)
					if event.ContractId != nil {
						contractIdByte, _ := event.ContractId.MarshalBinary()
						contractID, _ := strkey.Encode(strkey.VersionByteContract, contractIdByte)
						procErr.WithContract(contractID)
					}

					procErr.WithContext("event_index", eventIdx).
						WithContext("operation_index", opIdx)

					log.Printf("Error processing contract event: %s", procErr.Error())

					p.mu.Lock()
					p.stats.FailedEvents++
					p.mu.Unlock()
					continue
				}

				if contractEvent != nil {
					// Add debug logging
					log.Printf("Found contract event for contract ID: %s", contractEvent.ContractID)

					p.mu.Lock()
					p.stats.EventsFound++
					if contractEvent.Successful {
						p.stats.SuccessfulEvents++
					}
					p.mu.Unlock()

					// Forward with context timeout for consumer processing
					consumerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
					err := p.forwardToConsumers(consumerCtx, contractEvent)
					cancel() // Always cancel to avoid context leak

					if err != nil {
						var procErr *ProcessorError
						if !errors.As(err, &procErr) {
							// Wrap if not already a ProcessorError
							procErr = NewProcessorError(
								err,
								ErrorTypeConsumer,
								ErrorSeverityWarning,
							)
						}

						procErr.WithLedger(sequence).
							WithTransaction(txHash).
							WithContract(contractEvent.ContractID).
							WithContext("event_index", eventIdx).
							WithContext("operation_index", opIdx)

						log.Printf("Error forwarding event: %s", procErr.Error())
					}
				}
			}
		}
	}

	// Update processor stats
	p.mu.Lock()
	p.stats.ProcessedLedgers++
	p.stats.LastLedger = sequence
	p.stats.LastProcessedTime = time.Now()
	p.mu.Unlock()

	return nil
}

func (p *ContractEventProcessor) forwardToConsumers(ctx context.Context, event *ContractEvent) error {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return NewProcessorError(
			fmt.Errorf("context canceled before forwarding: %w", err),
			ErrorTypeConsumer,
			ErrorSeverityWarning,
		)
	}

	// Add debug logging
	log.Printf("Forwarding event to %d consumers", len(p.consumers))

	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return NewProcessorError(
			fmt.Errorf("error marshaling event: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		)
	}

	msg := pluginapi.Message{
		Payload:   jsonBytes,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"ledger_sequence": event.LedgerSequence,
			"contract_id":     event.ContractID,
			"transaction_id":  event.TransactionID,
			"type":            event.Type,
		},
	}

	// Lock to safely access p.consumers
	p.mu.RLock()
	consumers := make([]pluginapi.Consumer, len(p.consumers))
	copy(consumers, p.consumers)
	p.mu.RUnlock()

	for _, consumer := range consumers {
		// Check context before each consumer to allow early exit
		if err := ctx.Err(); err != nil {
			return NewProcessorError(
				fmt.Errorf("context canceled during forwarding: %w", err),
				ErrorTypeConsumer,
				ErrorSeverityWarning,
			)
		}

		log.Printf("Forwarding to consumer: %s", consumer.Name())

		// Create a consumer-specific timeout context
		consumerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := consumer.Process(consumerCtx, msg)
		cancel() // Always cancel to prevent context leak

		if err != nil {
			return NewProcessorError(
				fmt.Errorf("error in consumer %s: %w", consumer.Name(), err),
				ErrorTypeConsumer,
				ErrorSeverityWarning,
			).WithContext("consumer", consumer.Name())
		}
	}
	return nil
}

func (p *ContractEventProcessor) Name() string {
	return "flow/processor/contract-events"
}

func (p *ContractEventProcessor) Version() string {
	return "1.0.0"
}

func (p *ContractEventProcessor) Type() pluginapi.PluginType {
	return pluginapi.ProcessorPlugin
}

func New() pluginapi.Plugin {
	return &ContractEventProcessor{}
}

// filterContractEvents groups contract events by operation index
func filterContractEvents(diagnosticEvents []xdr.DiagnosticEvent) map[int][]xdr.ContractEvent {
	events := make(map[int][]xdr.ContractEvent)

	for _, diagEvent := range diagnosticEvents {
		if !diagEvent.InSuccessfulContractCall || diagEvent.Event.Type != xdr.ContractEventTypeContract {
			continue
		}

		// Use the operation index as the key
		opIndex := 0 // Default to 0 if no specific index available
		events[opIndex] = append(events[opIndex], diagEvent.Event)
	}
	return events
}

func (p *ContractEventProcessor) processContractEvent(
	ctx context.Context,
	tx ingest.LedgerTransaction,
	opIndex, eventIndex int,
	event xdr.ContractEvent,
	meta xdr.LedgerCloseMeta,
) (*ContractEvent, error) {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return nil, NewProcessorError(
			fmt.Errorf("context canceled while processing event: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		).WithContext("event_index", eventIndex).
			WithContext("operation_index", opIndex)
	}

	// Extract contract ID
	var contractID string
	if event.ContractId != nil {
		contractIdByte, err := event.ContractId.MarshalBinary()
		if err != nil {
			return nil, NewProcessorError(
				fmt.Errorf("error marshaling contract ID: %w", err),
				ErrorTypeParsing,
				ErrorSeverityWarning,
			)
		}
		contractID, err = strkey.Encode(strkey.VersionByteContract, contractIdByte)
		if err != nil {
			return nil, NewProcessorError(
				fmt.Errorf("error encoding contract ID: %w", err),
				ErrorTypeParsing,
				ErrorSeverityWarning,
			)
		}
	}

	// Get transaction context
	ledgerSequence := meta.LedgerSequence()
	transactionIndex := uint32(tx.Index)
	transactionHash := tx.Result.TransactionHash.HexString()
	transactionID := toid.New(int32(ledgerSequence), int32(transactionIndex), 0).ToInt64()

	// Get close time - converting TimePoint directly to Unix time
	closeTime := time.Unix(int64(meta.LedgerHeaderHistoryEntry().Header.ScpValue.CloseTime), 0)

	// Get the event topics
	var topics []xdr.ScVal
	var eventData xdr.ScVal

	if event.Body.V == 0 {
		v0 := event.Body.MustV0()
		topics = v0.Topics
		eventData = v0.Data
	} else {
		return nil, NewProcessorError(
			fmt.Errorf("unsupported event body version: %d", event.Body.V),
			ErrorTypeParsing,
			ErrorSeverityWarning,
		).WithContext("event_body_version", event.Body.V)
	}

	// Convert event XDR to base64
	eventXDR, err := xdr.MarshalBase64(event)
	if err != nil {
		return nil, NewProcessorError(
			fmt.Errorf("error marshaling event XDR: %w", err),
			ErrorTypeParsing,
			ErrorSeverityWarning,
		)
	}

	// Serialize topics and data
	rawTopics, decodedTopics := serializeScValArray(topics)
	rawData, decodedData := serializeScVal(eventData)

	// Determine if event was in successful transaction
	successful := tx.Result.Successful()

	// Create contract event record with enhanced structure
	contractEvent := &ContractEvent{
		// Transaction context
		TransactionHash:   transactionHash,
		TransactionID:     transactionID,
		Successful:        successful,
		LedgerSequence:    ledgerSequence,
		ClosedAt:          closeTime,
		NetworkPassphrase: p.networkPassphrase,

		// Event context
		ContractID:         contractID,
		EventIndex:         eventIndex,
		OperationIndex:     opIndex,
		InSuccessfulTxCall: successful,

		// Event type information
		Type:     event.Type.String(),
		TypeCode: int32(event.Type),

		// Event data
		Topics:        rawTopics,
		TopicsDecoded: decodedTopics,
		Data:          rawData,
		DataDecoded:   decodedData,

		// Raw XDR
		EventXDR: eventXDR,

		// Metadata for filtering
		Tags: make(map[string]string),
	}

	// Add basic tags for common filtering scenarios
	contractEvent.Tags["contract_id"] = contractID
	contractEvent.Tags["event_type"] = event.Type.String()
	contractEvent.Tags["successful"] = fmt.Sprintf("%t", successful)

	// Add diagnostic events if available
	diagnosticEvents, err := tx.GetDiagnosticEvents()
	if err == nil {
		var diagnosticData []DiagnosticData
		for _, diagEvent := range diagnosticEvents {
			// Check for context cancellation periodically
			if err := ctx.Err(); err != nil {
				return nil, NewProcessorError(
					fmt.Errorf("context canceled while processing diagnostic events: %w", err),
					ErrorTypeProcessing,
					ErrorSeverityWarning,
				)
			}

			if diagEvent.Event.Type == xdr.ContractEventTypeContract {
				eventData, err := json.Marshal(diagEvent.Event)
				if err != nil {
					continue
				}

				// Get raw XDR for the diagnostic event
				diagXDR, err := xdr.MarshalBase64(diagEvent)
				if err != nil {
					diagXDR = ""
				}

				diagnosticData = append(diagnosticData, DiagnosticData{
					Event:                    eventData,
					InSuccessfulContractCall: diagEvent.InSuccessfulContractCall,
					RawXDR:                   diagXDR,
				})
			}
		}
		contractEvent.DiagnosticEvents = diagnosticData
	}

	return contractEvent, nil
}

// serializeScVal converts an ScVal to structured data format with both raw and decoded representations
func serializeScVal(scVal xdr.ScVal) (EventData, EventData) {
	rawData := EventData{
		Type:  "n/a",
		Value: "n/a",
	}

	decodedData := EventData{
		Type:  "n/a",
		Value: "n/a",
	}

	if scValTypeName, ok := scVal.ArmForSwitch(int32(scVal.Type)); ok {
		rawData.Type = scValTypeName
		decodedData.Type = scValTypeName

		if raw, err := scVal.MarshalBinary(); err == nil {
			rawData.Value = base64.StdEncoding.EncodeToString(raw)
			decodedData.Value = scVal.String()
		}
	}

	return rawData, decodedData
}

// serializeScValArray converts an array of ScVal to structured data format
func serializeScValArray(scVals []xdr.ScVal) ([]TopicData, []TopicData) {
	rawTopics := make([]TopicData, 0, len(scVals))
	decodedTopics := make([]TopicData, 0, len(scVals))

	for _, scVal := range scVals {
		if scValTypeName, ok := scVal.ArmForSwitch(int32(scVal.Type)); ok {
			raw, err := scVal.MarshalBinary()
			if err != nil {
				continue
			}

			rawTopics = append(rawTopics, TopicData{
				Type:  scValTypeName,
				Value: base64.StdEncoding.EncodeToString(raw),
			})

			decodedTopics = append(decodedTopics, TopicData{
				Type:  scValTypeName,
				Value: scVal.String(),
			})
		}
	}

	return rawTopics, decodedTopics
}

```

# README.md

```md
# flow-processor-contract-events

A Flow processor plugin for contract events.

## Building with Nix

This project uses Nix for reproducible builds.

### Prerequisites

- [Nix package manager](https://nixos.org/download.html) with flakes enabled

### Building

1. Clone the repository:
\`\`\`bash
git clone https://github.com/withObsrvr/flow-processor-contract-events.git
cd flow-processor-contract-events
\`\`\`

2. Build with Nix:
\`\`\`bash
nix build
\`\`\`

The built plugin will be available at `./result/lib/flow-processor-contract-events.so`.

### Development

To enter a development shell with all dependencies:
\`\`\`bash
nix develop
\`\`\`

This will automatically vendor dependencies if needed and provide a shell with all necessary tools.

### Manual Build (Inside Nix Shell)

Once in the development shell, you can manually build the plugin:
\`\`\`bash
go mod tidy
go mod vendor
go build -buildmode=plugin -o flow-processor-contract-events.so .
\`\`\`

## Troubleshooting

### Plugin Version Compatibility

Make sure the plugin is built with the exact same Go version that Flow uses. If you see an error like "plugin was built with a different version of package internal/goarch", check that your Go version matches the one used by the Flow application.

### CGO Required

Go plugins require CGO to be enabled. The Nix build and development shell handle this automatically, but if building manually outside of Nix, ensure you've set:
\`\`\`bash
export CGO_ENABLED=1
\`\`\`

### Vendoring Dependencies

For reliable builds, we recommend using vendored dependencies:
\`\`\`bash
go mod vendor
git add vendor
\`\`\`
```

# result

This is a binary file of the type: Binary

