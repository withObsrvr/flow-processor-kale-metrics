# .gitattributes

```
# Mark vendored files as linguist-vendored to improve GitHub statistics
vendor/** linguist-vendored

# Nix files
*.nix linguist-detectable=true 
```

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
        "lastModified": 1742272065,
        "narHash": "sha256-ud8vcSzJsZ/CK+r8/v0lyf4yUntVmDq6Z0A41ODfWbE=",
        "owner": "NixOS",
        "repo": "nixpkgs",
        "rev": "3549532663732bfd89993204d40543e9edaec4f2",
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
  description = "Obsrvr Flow Plugin: Source BufferedStorage GCS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # Allow dirty Git working tree for development
  nixConfig = {
    allow-dirty = true;
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = {
          default = pkgs.buildGoModule {
            pname = "flow-source-bufferedstorage-gcs";
            version = "0.1.0";
            src = ./.;
            
            # Use null to skip vendoring check since we're using a vendor directory
            vendorHash = null;
            
            # Disable hardening which is required for Go plugins
            hardeningDisable = [ "all" ];
            
            # Enable CGO which is required for Go plugins
            env = {
              CGO_ENABLED = "1";
              GO111MODULE = "on";
            };
            
            # Configure build environment for plugin compilation 
            preBuild = ''
              echo "Using vendor directory for building..."
            '';
            
            # Build as a shared library/plugin
            buildPhase = ''
              runHook preBuild
              go build -mod=vendor -buildmode=plugin -o flow-source-bufferedstorage-gcs.so .
              runHook postBuild
            '';

            # Custom install phase for the plugin
            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib
              cp flow-source-bufferedstorage-gcs.so $out/lib/
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
              # Add any required C library dependencies here if needed
            ];
            
            # Use -mod=vendor flag just like the Flow application
            buildFlags = [ "-mod=vendor" ];
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ 
            go_1_23
            pkg-config
            git  # Needed for vendoring dependencies
            gopls
            delve
          ];
          
          # Shell setup for development environment
          shellHook = ''
            # Enable CGO which is required for plugin mode
            export CGO_ENABLED=1
            export GO111MODULE=on
            export GOFLAGS="-mod=vendor"
            
            # Helper to vendor dependencies - greatly improves build reliability
            if [ ! -d vendor ]; then
              echo "Vendoring dependencies..."
              go mod tidy
              go mod vendor
            fi
            
            echo "Development environment ready!"
            echo "To build the plugin manually: go build -mod=vendor -buildmode=plugin -o flow-source-bufferedstorage-gcs.so ."
          '';
        };
      }
    );
} 
```

# go.mod

```mod
module github.com/withObsrvr/flow-source-bufferedstorage-gcs

go 1.23.4

require (
	github.com/pkg/errors v0.9.1
	github.com/stellar/go v0.0.0-20250311234916-385ac5aca1a4
	github.com/withObsrvr/pluginapi v0.0.0-20250303141549-e645e333195c
	github.com/withObsrvr/stellar-cdp v0.0.0-20241220082310-1a8c717a9c8f
	github.com/withObsrvr/stellar-datastore v0.0.0-20250207023055-4074500adc35
	github.com/withObsrvr/stellar-ledgerbackend v0.0.0-20241220092445-b96fa5b9c924
)

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
	github.com/aws/aws-sdk-go v1.55.6 // indirect
	github.com/aws/aws-sdk-go-v2 v1.36.3 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.10 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.29.9 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.62 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.7.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.78.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.29.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.17 // indirect
	github.com/aws/smithy-go v1.22.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cncf/xds/go v0.0.0-20250121191232-2f005788dc42 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/djherbis/fscache v0.10.1 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.32.4 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.14.1 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jmoiron/sqlx v1.4.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.21.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.63.0 // indirect
	github.com/prometheus/procfs v0.16.0 // indirect
	github.com/segmentio/go-loggly v0.5.1-0.20171222203950-eb91657e62b2 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stellar/go-xdr v0.0.0-20231122183749-b53fb00bcac2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.35.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.60.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
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
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Force usage of the bundled opentelemetry stats in gRPC
replace google.golang.org/grpc => google.golang.org/grpc v1.71.0

// Prevent the standalone module from being used
exclude google.golang.org/grpc/stats/opentelemetry v0.0.0-20240907200651-3ffb98b2c93a

```

# main.go

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/pkg/errors"
	"github.com/stellar/go/xdr"
	cdp "github.com/withObsrvr/stellar-cdp"
	datastore "github.com/withObsrvr/stellar-datastore"
	ledgerbackend "github.com/withObsrvr/stellar-ledgerbackend"

	// Import the core plugin API definitions. Adjust the import path as needed.

	"github.com/withObsrvr/pluginapi"
)

// BufferedStorageConfig holds configuration values for the source.
type BufferedStorageConfig struct {
	BucketName        string
	BufferSize        uint32
	NumWorkers        uint32
	RetryLimit        uint32
	RetryWait         uint32
	Network           string
	StartLedger       uint32
	EndLedger         uint32
	LedgersPerFile    uint32
	FilesPerPartition uint32
}

// BufferedStorageSourceAdapter implements pluginapi.Source.
type BufferedStorageSourceAdapter struct {
	config     BufferedStorageConfig
	processors []pluginapi.Processor
}

// Name returns the plugin name.
func (adapter *BufferedStorageSourceAdapter) Name() string {
	return "BufferedStorageSourceAdapter"
}

// Version returns the plugin version.
func (adapter *BufferedStorageSourceAdapter) Version() string {
	return "1.0.0"
}

// Type indicates this is a Source plugin.
func (adapter *BufferedStorageSourceAdapter) Type() pluginapi.PluginType {
	return pluginapi.SourcePlugin
}

// verifyPipeline checks if the pipeline is properly configured
func (adapter *BufferedStorageSourceAdapter) verifyPipeline() error {
	if len(adapter.processors) == 0 {
		return errors.New("no processors registered in pipeline")
	}

	log.Printf("Pipeline verification: Found %d processors", len(adapter.processors))
	for i, proc := range adapter.processors {
		log.Printf("Pipeline processor %d: %T", i, proc)
	}

	return nil
}

// Initialize reads the configuration map and sets up the adapter.
func (adapter *BufferedStorageSourceAdapter) Initialize(config map[string]interface{}) error {
	// Helper function to safely convert interface{} to int
	getIntValue := func(v interface{}) (int, bool) {
		switch i := v.(type) {
		case int:
			return i, true
		case float64:
			return int(i), true
		case int64:
			return int(i), true
		}
		return 0, false
	}

	// Get required config values.
	startLedgerRaw, ok := config["start_ledger"]
	if !ok {
		return errors.New("start_ledger must be specified")
	}
	startLedgerInt, ok := getIntValue(startLedgerRaw)
	if !ok {
		return errors.New("invalid start_ledger value")
	}
	startLedger := uint32(startLedgerInt)

	bucketName, ok := config["bucket_name"].(string)
	if !ok {
		return errors.New("bucket_name is missing")
	}

	network, ok := config["network"].(string)
	if !ok {
		return errors.New("network must be specified")
	}

	// Get other config values with defaults.
	bufferSizeInt, _ := getIntValue(config["buffer_size"])
	if bufferSizeInt == 0 {
		bufferSizeInt = 1024
	}
	numWorkersInt, _ := getIntValue(config["num_workers"])
	if numWorkersInt == 0 {
		numWorkersInt = 10
	}
	retryLimitInt, _ := getIntValue(config["retry_limit"])
	if retryLimitInt == 0 {
		retryLimitInt = 3
	}
	retryWaitInt, _ := getIntValue(config["retry_wait"])
	if retryWaitInt == 0 {
		retryWaitInt = 5
	}

	// End ledger is optional.
	endLedgerRaw, ok := config["end_ledger"]
	var endLedger uint32
	if ok {
		endLedgerInt, ok := getIntValue(endLedgerRaw)
		if !ok {
			return errors.New("invalid end_ledger value")
		}
		endLedger = uint32(endLedgerInt)
		if endLedger > 0 && endLedger < startLedger {
			return errors.New("end_ledger must be greater than start_ledger")
		}
	}

	// Optional: ledgers per file and files per partition.
	ledgersPerFileInt, _ := getIntValue(config["ledgers_per_file"])
	if ledgersPerFileInt == 0 {
		ledgersPerFileInt = 64
	}
	filesPerPartitionInt, _ := getIntValue(config["files_per_partition"])
	if filesPerPartitionInt == 0 {
		filesPerPartitionInt = 10
	}

	adapter.config = BufferedStorageConfig{
		BucketName:        bucketName,
		Network:           network,
		BufferSize:        uint32(bufferSizeInt),
		NumWorkers:        uint32(numWorkersInt),
		RetryLimit:        uint32(retryLimitInt),
		RetryWait:         uint32(retryWaitInt),
		StartLedger:       startLedger,
		EndLedger:         endLedger,
		LedgersPerFile:    uint32(ledgersPerFileInt),
		FilesPerPartition: uint32(filesPerPartitionInt),
	}

	log.Printf("BufferedStorageSourceAdapter initialized with start_ledger=%d, end_ledger=%d, bucket=%s, network=%s",
		startLedger, endLedger, bucketName, network)

	// Add pipeline verification after initialization
	if err := adapter.verifyPipeline(); err != nil {
		log.Printf("Warning: Pipeline verification failed: %v", err)
		// Optionally return the error if you want to fail initialization
		// return err
	}

	return nil
}

// Subscribe registers a processor to receive messages.
func (adapter *BufferedStorageSourceAdapter) Subscribe(proc pluginapi.Processor) {
	adapter.processors = append(adapter.processors, proc)
}

// Start begins the processing loop.
func (adapter *BufferedStorageSourceAdapter) Start(ctx context.Context) error {

	log.Printf("Starting BufferedStorageSourceAdapter with config: %+v", adapter.config)

	if err := adapter.verifyPipeline(); err != nil {
		return fmt.Errorf("pipeline verification failed: %w", err)
	}

	// Create schema configuration
	schema := datastore.DataStoreSchema{
		LedgersPerFile:    adapter.config.LedgersPerFile,
		FilesPerPartition: adapter.config.FilesPerPartition,
	}

	log.Printf("Created schema configuration: %+v", schema)

	// Create data store configuration
	dataStoreConfig := datastore.DataStoreConfig{
		Type:   "GCS",
		Schema: schema,
		Params: map[string]string{
			"destination_bucket_path": adapter.config.BucketName,
		},
	}

	log.Printf("Attempting to connect to GCS bucket: %s", adapter.config.BucketName)

	log.Printf("Starting BufferedStorageSourceAdapter from ledger %d", adapter.config.StartLedger)
	if adapter.config.EndLedger > 0 {
		log.Printf("Will process until ledger %d", adapter.config.EndLedger)
	} else {
		log.Printf("Will process indefinitely from start ledger")
	}

	// Add debug logging for configuration
	log.Printf("Using configuration: %+v", adapter.config)
	log.Printf("Number of registered processors: %d", len(adapter.processors))

	// Create buffered storage configuration.
	bufferedConfig := cdp.DefaultBufferedStorageBackendConfig(schema.LedgersPerFile)
	bufferedConfig.BufferSize = adapter.config.BufferSize
	bufferedConfig.NumWorkers = adapter.config.NumWorkers
	bufferedConfig.RetryLimit = adapter.config.RetryLimit
	bufferedConfig.RetryWait = time.Duration(adapter.config.RetryWait) * time.Second

	publisherConfig := cdp.PublisherConfig{
		DataStoreConfig:       dataStoreConfig,
		BufferedStorageConfig: bufferedConfig,
	}

	log.Printf("Created DataStore configuration: %+v", dataStoreConfig)
	log.Printf("Created buffered configuration: %+v", bufferedConfig)
	log.Printf("Created publisher configuration: %+v", publisherConfig)

	// Determine ledger range.
	var ledgerRange ledgerbackend.Range
	if adapter.config.EndLedger > 0 {
		ledgerRange = ledgerbackend.BoundedRange(
			adapter.config.StartLedger,
			adapter.config.EndLedger,
		)
	} else {
		ledgerRange = ledgerbackend.UnboundedRange(adapter.config.StartLedger)
	}

	log.Printf("BufferedStorageSourceAdapter: processing ledger range: %v", ledgerRange)

	processedLedgers := 0
	lastLogTime := time.Now()
	lastLedgerTime := time.Now()

	// Add a ticker for periodic status updates even if no ledgers are being processed
	statusTicker := time.NewTicker(10 * time.Second)
	defer statusTicker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-statusTicker.C:
				log.Printf("Still alive - Processed %d ledgers so far", processedLedgers)
			}
		}
	}()

	err := cdp.ApplyLedgerMetadata(
		ledgerRange,
		publisherConfig,
		ctx,
		func(lcm xdr.LedgerCloseMeta) error {

			currentTime := time.Now()
			ledgerProcessingTime := currentTime.Sub(lastLedgerTime)
			lastLedgerTime = currentTime

			log.Printf("Processing ledger %d (time since last ledger: %v)", lcm.LedgerSequence(), ledgerProcessingTime)
			if err := adapter.processLedger(ctx, lcm); err != nil {
				log.Printf("Error processing ledger %d: %v", lcm.LedgerSequence(), err)
				return err
			}

			processedLedgers++
			if time.Since(lastLogTime) > 10*time.Second {
				rate := float64(processedLedgers) / time.Since(lastLogTime).Seconds()
				log.Printf("Processed %d ledgers (%.2f ledgers/sec)", processedLedgers, rate)
				lastLogTime = time.Now()
			}
			return nil
		},
	)

	if err != nil {
		log.Printf("BufferedStorageSourceAdapter encountered an error: %v", err)
		return err
	}

	duration := time.Since(lastLogTime)
	rate := float64(processedLedgers) / duration.Seconds()
	log.Printf("BufferedStorageSourceAdapter completed. Processed %d ledgers in %v (%.2f ledgers/sec)", processedLedgers, duration, rate)
	return nil
}

// processLedger processes each ledger by passing it to registered processors.
func (adapter *BufferedStorageSourceAdapter) processLedger(ctx context.Context, ledger xdr.LedgerCloseMeta) error {
	sequence := ledger.LedgerSequence()
	log.Printf("Starting to process ledger %d", sequence)

	// Check if we have any processors
	if len(adapter.processors) == 0 {
		log.Printf("Warning: No processors registered for ledger %d", sequence)
		return nil
	}

	// Create message once for all processors
	msg := pluginapi.Message{
		Payload:   ledger,
		Timestamp: time.Now(),
	}

	// Process through each processor in sequence
	for i, proc := range adapter.processors {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			procStart := time.Now()

			// Add processor-specific context
			processorCtx := context.WithValue(ctx, "processor_index", i)
			processorCtx = context.WithValue(processorCtx, "processor_type", fmt.Sprintf("%T", proc))

			if err := proc.Process(processorCtx, msg); err != nil {
				log.Printf("Error in processor %d (%T) for ledger %d: %v", i, proc, sequence, err)
				// You might want to implement retry logic here
				return errors.Wrapf(err, "processor %d (%T) failed", i, proc)
			}

			processingTime := time.Since(procStart)
			if processingTime > time.Second {
				log.Printf("Warning: Processor %d (%T) took %v to process ledger %d",
					i, proc, processingTime, sequence)
			} else {
				log.Printf("Processor %d (%T) successfully processed ledger %d in %v",
					i, proc, sequence, processingTime)
			}
		}
	}

	log.Printf("Successfully completed processing ledger %d through %d processors",
		sequence, len(adapter.processors))
	return nil
}

// Stop halts the adapter. For this example, it simply returns nil.
func (adapter *BufferedStorageSourceAdapter) Stop() error {
	// Implement any necessary cleanup here.
	log.Println("BufferedStorageSourceAdapter stopped")
	return nil
}

// Close is a convenience alias for Stop.
func (adapter *BufferedStorageSourceAdapter) Close() error {
	return adapter.Stop()
}

// Exported New function to allow dynamic loading.
func New() pluginapi.Plugin {
	// Return a new instance. Configuration will be provided via Initialize.
	return &BufferedStorageSourceAdapter{}
}

```

# README.md

```md
# flow-source-bufferedstorage-gcs

A Flow source plugin that implements the BufferedStorage interface for Google Cloud Storage (GCS).

## Building with Nix

This project uses Nix for reproducible builds.

### Prerequisites

- [Nix package manager](https://nixos.org/download.html) with flakes enabled

### Building

1. Clone the repository:
\`\`\`bash
git clone https://github.com/withObsrvr/flow-source-bufferedstorage-gcs.git
cd flow-source-bufferedstorage-gcs
\`\`\`

2. Build with Nix:
\`\`\`bash
nix build
\`\`\`

The built plugin will be available at `./result/lib/flow-source-bufferedstorage-gcs.so`.

### Development

To enter a development shell with all dependencies:
\`\`\`bash
nix develop
\`\`\`

This will automatically vendor dependencies if needed and provide a shell with all necessary tools.

## Troubleshooting

If you encounter build issues, ensure you have:

1. Enabled flakes in your Nix configuration
2. Properly vendored dependencies with `go mod vendor`
3. Committed all changes (or use `--impure` flag with uncommitted changes)
```

# result

This is a binary file of the type: Binary

