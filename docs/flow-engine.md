# .dockerignore

```
# Git
.git
.gitignore

# Build artifacts
bin/*
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test
*.out

# Database files
*.db
*.db-journal
*.sqlite
*.sqlite-journal

# Temporary files
tmp/
temp/
*.tmp
*.bak
*.swp

# IDE files
.idea/
.vscode/
*.sublime-*
*.code-workspace

# Logs
*.log

# OS specific
.DS_Store
Thumbs.db

# Docker files (to avoid recursion)
Dockerfile
docker-compose.yml
.dockerignore 
```

# .github/workflows/build-and-release.yml

```yml
name: Build and Release Flow with Plugins

on:
  push:
    tags:
      - 'v*.*.*'
  workflow_dispatch:
    inputs:
      release_tag:
        description: 'Release tag (e.g., v0.1.0)'
        required: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout flow
        uses: actions/checkout@v4
        with:
          path: flow

      - name: Checkout flow-consumer-sqlite
        uses: actions/checkout@v4
        with:
          repository: withObsrvr/flow-consumer-sqlite
          path: flow-consumer-sqlite
          
      - name: Checkout flow-processor-latestledger
        uses: actions/checkout@v4
        with:
          repository: withObsrvr/flow-processor-latestledger
          path: flow-processor-latestledger

      - name: Checkout flow-source-bufferedstorage-gcs
        uses: actions/checkout@v4
        with:
          repository: withObsrvr/flow-source-bufferedstorage-gcs
          path: flow-source-bufferedstorage-gcs

      - name: Install Nix
        uses: cachix/install-nix-action@v25
        with:
          github_access_token: ${{ secrets.GITHUB_TOKEN }}
          
      - name: Configure Nix Substituters
        run: |
          mkdir -p ~/.config/nix
          echo 'substituters = https://cache.nixos.org/' > ~/.config/nix/nix.conf
          echo 'trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=' >> ~/.config/nix/nix.conf
          echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf

      - name: Build Flow
        run: |
          cd flow
          nix build
          mkdir -p ../dist/bin
          cp -r result/bin/* ../dist/bin/
          
          # Store Go version for documentation
          go_version=$(nix shell nixpkgs#go_1_23 -c go version)
          echo "$go_version" > ../dist/GO_VERSION.txt

      - name: Build flow-consumer-sqlite
        run: |
          cd flow-consumer-sqlite
          nix build
          mkdir -p ../dist/plugins
          cp result/lib/* ../dist/plugins/

      - name: Build flow-processor-latestledger
        run: |
          cd flow-processor-latestledger
          nix build
          cp result/lib/* ../dist/plugins/

      - name: Build flow-source-bufferedstorage-gcs
        run: |
          cd flow-source-bufferedstorage-gcs
          nix build
          cp result/lib/* ../dist/plugins/
          
      - name: Generate checksums
        run: |
          cd dist
          # Generate SHA256 checksums for all files
          find . -type f -not -name "SHA256SUMS" | sort | xargs sha256sum > SHA256SUMS

      - name: Generate documentation
        run: |
          cat > dist/README.md << EOF
          # Flow with Plugins Release
          
          This release contains the Flow application and its plugins, all built with the same Go toolchain to ensure compatibility.
          
          ## Build Information
          
          $(cat dist/GO_VERSION.txt)
          
          ## Components
          
          - Flow executables in \`bin/\` directory
          - Plugins in \`plugins/\` directory
          
          ## Installation
          
          1. Copy the Flow executables to your preferred location
          2. Copy the plugins to your Flow plugins directory
          3. Configure Flow to load these plugins
          
          ## Compatibility
          
          These plugins are only compatible with the Flow binary included in this release (or built with the same Go toolchain) due to Go plugin linking requirements.
          
          ## Verification
          
          Verify the integrity of your downloads using the provided SHA256SUMS file:
          \`\`\`
          sha256sum -c SHA256SUMS
          \`\`\`
          EOF

      - name: Create Release
        id: create_release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ github.event.inputs.release_tag || github.ref_name }}
          name: Flow Release ${{ github.event.inputs.release_tag || github.ref_name }}
          draft: true
          generate_release_notes: true
          files: |
            dist/**/*
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  build-docker:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        
      - name: Download release assets
        uses: robinraju/release-downloader@v1.9
        with:
          tag: ${{ github.event.inputs.release_tag || github.ref_name }}
          zipBall: false
          tarBall: false
          out-file-path: "dist"
          
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
        
      - name: Login to DockerHub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
          
      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: |
            withobsrvr/flow:latest
            withobsrvr/flow:${{ github.event.inputs.release_tag || github.ref_name }} 
```

# .github/workflows/nix-build.yml

```yml
name: Build with Nix

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Nix
        uses: cachix/install-nix-action@v26
        with:
          nix_path: nixpkgs=channel:nixos-unstable
          extra_nix_config: |
            experimental-features = nix-command flakes
      
      - name: Build Flow
        run: nix build
      
      - name: Test Flow Binary
        run: ./result/bin/flow --help 
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
*.secret.yaml

# env file
.env
Flow

cdp-pipeline-workflow.md
flow-consumer*.md
flow-processor*.md
flow-source*.md
flow-soroswap*.md
stellar-xdr-json.md
flow.md
flow_upgraded_implementation_plan.md
flow-engine.md

bin/flow
bin/graphql-api
bin/schema-registry
bin/query_accounts
*.db
*.db-wal
*.db-shm
*.db-journal
*.pid

# Nix
result
result-*
.direnv/
.envrc
vendor/

```

# build.sh

```sh
#!/bin/bash

# Exit on any error
set -e

echo "Building Flow application and plugins..."

# Function to update all dependencies in current directory
update_dependencies() {
    echo "Updating all dependencies in $(pwd)"
    
    # Get list of all direct dependencies
    echo "Getting list of dependencies..."
    deps=$(go list -m all | tail -n +2 | cut -d' ' -f1)
    
    # Try to update each dependency individually
    for dep in $deps; do
        echo "Attempting to update $dep..."
        go get -u "$dep" || echo "Warning: Could not update $dep, skipping..."
    done
    
    echo "Running go mod tidy..."
    go mod tidy || echo "Warning: go mod tidy had some issues, continuing..."
}

# Function to verify all dependency versions
verify_versions() {
    echo "Verifying all dependency versions in $(pwd)"
    go list -m all  # Lists all dependencies and their versions
}

# Update and build main application
echo "Updating and building main application..."
cd ~/projects/obsrvr/flow
update_dependencies
verify_versions
go build -buildmode=pie -o Flow

# Update and build source plugin
echo "Updating and building source plugin..."
cd ../flow-source-bufferedstorage-gcs
update_dependencies
verify_versions
go build -buildmode=plugin -o ../flow/plugins/flow-source-bufferedstorage-gcs.so

# Update and build processor plugin
echo "Updating and building processor plugin..."
cd ../flow-processor-latestledger
update_dependencies
verify_versions
go build -buildmode=plugin -o ../flow/plugins/flow-processor-latestledger.so

# Update and build processor plugin 
echo "Updating and building processor plugin..."
cd ../flow-processor-contract-events
update_dependencies
verify_versions
go build -buildmode=plugin -o ../flow/plugins/flow-processor-contract-events.so

# Update and build processor plugin
echo "Updating and building processor plugin..."
cd ../flow-processor-kale-metrics
update_dependencies
verify_versions
go build -buildmode=plugin -o ../flow/plugins/flow-processor-kale-metrics.so

# Update and build consumer plugin
echo "Updating and building consumer plugin..."
cd ../flow-consumer-zeromq
update_dependencies
verify_versions
go build -buildmode=plugin -o ../flow/plugins/flow-consumer-zeromq.so



echo "Build complete!" 
```

# cmd/graphql-api/dynamic_schema.go

```go
package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/graphql-go/graphql"
)

// buildDynamicSchema builds a GraphQL schema from the database structure
func buildDynamicSchema(db *sql.DB) (*graphql.Schema, error) {
	// Create a map to hold all the fields for the root query
	fields := graphql.Fields{}

	// Add a simple health check query
	fields["health"] = &graphql.Field{
		Type: graphql.String,
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			return "OK", nil
		},
	}

	// Get all tables in the database
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, tableName)
	}

	// Process each table
	for _, tableName := range tables {
		// Skip internal tables
		if tableName == "sqlite_sequence" || tableName == "flow_metadata" {
			continue
		}

		log.Printf("Building schema for table: %s", tableName)

		// Get table schema
		schemaRows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			log.Printf("Error getting schema for table %s: %v", tableName, err)
			continue
		}

		// Create fields for the type
		typeFields := graphql.Fields{}
		var columns []string
		var columnTypes []string

		for schemaRows.Next() {
			var cid int
			var name, typeName string
			var notNull, pk int
			var defaultValue interface{}

			if err := schemaRows.Scan(&cid, &name, &typeName, &notNull, &defaultValue, &pk); err != nil {
				log.Printf("Error scanning column info: %v", err)
				continue
			}

			columns = append(columns, name)
			columnTypes = append(columnTypes, typeName)

			// Map SQL type to GraphQL type
			var fieldType graphql.Type
			switch strings.ToUpper(typeName) {
			case "INTEGER", "INT", "SMALLINT", "MEDIUMINT", "BIGINT":
				fieldType = graphql.Int
			case "REAL", "FLOAT", "DOUBLE", "NUMERIC", "DECIMAL":
				fieldType = graphql.Float
			case "TEXT", "VARCHAR", "CHAR", "CLOB":
				fieldType = graphql.String
			case "BOOLEAN":
				fieldType = graphql.Boolean
			default:
				fieldType = graphql.String // Default to string for unknown types
			}

			// Make non-nullable if required
			if notNull == 1 && pk == 0 { // Primary keys can be auto-increment, so they might appear null initially
				fieldType = graphql.NewNonNull(fieldType)
			}

			typeFields[name] = &graphql.Field{
				Type: fieldType,
			}
		}
		schemaRows.Close()

		// Create the type
		typeName := pascalCase(singularize(tableName))
		objType := graphql.NewObject(graphql.ObjectConfig{
			Name:   typeName,
			Fields: typeFields,
		})

		// Create query for getting a single item by ID
		singleQueryName := camelCase(singularize(tableName))
		idField := findIdField(columns)
		if idField != "" {
			fields[singleQueryName] = &graphql.Field{
				Type: objType,
				Args: graphql.FieldConfigArgument{
					idField: &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: createSingleItemResolver(db, tableName, columns, idField),
			}
		}

		// Create query for getting a list of items
		listQueryName := camelCase(pluralize(tableName))
		fields[listQueryName] = &graphql.Field{
			Type: graphql.NewList(objType),
			Args: graphql.FieldConfigArgument{
				"first": &graphql.ArgumentConfig{
					Type:         graphql.Int,
					DefaultValue: 10,
					Description:  "Number of items to return",
				},
				"after": &graphql.ArgumentConfig{
					Type:        graphql.String,
					Description: "Cursor for pagination",
				},
			},
			Resolve: createListResolver(db, tableName, columns, idField),
		}
	}

	// Create the schema
	schemaConfig := graphql.SchemaConfig{
		Query: graphql.NewObject(graphql.ObjectConfig{
			Name:   "Query",
			Fields: fields,
		}),
	}

	schema, err := graphql.NewSchema(schemaConfig)
	if err != nil {
		return nil, err
	}

	return &schema, nil
}

// createSingleItemResolver creates a resolver for a single item query
func createSingleItemResolver(db *sql.DB, tableName string, columns []string, idField string) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		id, ok := p.Args[idField].(string)
		if !ok {
			return nil, fmt.Errorf("invalid ID argument")
		}

		log.Printf("Querying %s with %s=%s", tableName, idField, id)

		query := fmt.Sprintf("SELECT * FROM %s WHERE %s = ?", tableName, idField)
		row := db.QueryRow(query, id)

		// Create a map to hold the result
		result := make(map[string]interface{})
		scanArgs := make([]interface{}, len(columns))
		scanValues := make([]interface{}, len(columns))
		for i := range columns {
			scanValues[i] = new(interface{})
			scanArgs[i] = scanValues[i]
		}

		if err := row.Scan(scanArgs...); err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Populate the result map
		for i, col := range columns {
			val := *(scanValues[i].(*interface{}))
			if val == nil {
				result[col] = nil
				continue
			}

			// Handle different types
			switch v := val.(type) {
			case []byte:
				// Try to convert to string
				result[col] = string(v)
			default:
				result[col] = v
			}
		}

		return result, nil
	}
}

// createListResolver creates a resolver for a list query
func createListResolver(db *sql.DB, tableName string, columns []string, idField string) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		limit, _ := p.Args["first"].(int)
		if limit <= 0 {
			limit = 10
		}

		after, _ := p.Args["after"].(string)

		log.Printf("Querying %s with limit=%d, after=%s", tableName, limit, after)

		query := fmt.Sprintf("SELECT * FROM %s", tableName)
		args := []interface{}{}

		if after != "" && idField != "" {
			query += fmt.Sprintf(" WHERE %s > ?", idField)
			args = append(args, after)
		}

		if idField != "" {
			query += fmt.Sprintf(" ORDER BY %s", idField)
		}

		query += " LIMIT ?"
		args = append(args, limit)

		rows, err := db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("error querying database: %w", err)
		}
		defer rows.Close()

		var results []interface{}
		for rows.Next() {
			// Create a map to hold the result
			result := make(map[string]interface{})
			scanArgs := make([]interface{}, len(columns))
			scanValues := make([]interface{}, len(columns))
			for i := range columns {
				scanValues[i] = new(interface{})
				scanArgs[i] = scanValues[i]
			}

			if err := rows.Scan(scanArgs...); err != nil {
				return nil, fmt.Errorf("error scanning row: %w", err)
			}

			// Populate the result map
			for i, col := range columns {
				val := *(scanValues[i].(*interface{}))
				if val == nil {
					result[col] = nil
					continue
				}

				// Handle different types
				switch v := val.(type) {
				case []byte:
					// Try to convert to string
					result[col] = string(v)
				default:
					result[col] = v
				}
			}

			results = append(results, result)
		}

		return results, nil
	}
}

// Helper functions

// findIdField finds the ID field in a list of columns
func findIdField(columns []string) string {
	// Common ID field names
	idFields := []string{"id", "account_id", "sequence", "hash"}

	for _, field := range idFields {
		for _, col := range columns {
			if strings.EqualFold(col, field) {
				return col
			}
		}
	}

	return ""
}

// singularize converts a plural word to singular
func singularize(s string) string {
	if strings.HasSuffix(s, "ies") {
		return s[:len(s)-3] + "y"
	}
	if strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss") {
		return s[:len(s)-1]
	}
	return s
}

// pluralize converts a singular word to plural
func pluralize(s string) string {
	if strings.HasSuffix(s, "y") {
		return s[:len(s)-1] + "ies"
	}
	if !strings.HasSuffix(s, "s") {
		return s + "s"
	}
	return s
}

// pascalCase converts a string to PascalCase
func pascalCase(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}

	return strings.Join(words, "")
}

// camelCase converts a string to camelCase
func camelCase(s string) string {
	pascal := pascalCase(s)
	if len(pascal) > 0 {
		return strings.ToLower(pascal[:1]) + pascal[1:]
	}
	return ""
}

```

# cmd/graphql-api/main.go

```go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/handler"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v2"
)

// ErrorCode represents a specific error type
type ErrorCode string

const (
	// Database error codes
	ErrDatabaseConnection ErrorCode = "DATABASE_CONNECTION_ERROR"
	ErrDatabaseQuery      ErrorCode = "DATABASE_QUERY_ERROR"

	// GraphQL error codes
	ErrSchemaBuilding ErrorCode = "SCHEMA_BUILDING_ERROR"
	ErrInvalidQuery   ErrorCode = "INVALID_QUERY"

	// Subscription error codes
	ErrSubscriptionFailed ErrorCode = "SUBSCRIPTION_FAILED"

	// Configuration error codes
	ErrInvalidConfig ErrorCode = "INVALID_CONFIGURATION"

	// General error codes
	ErrInternal   ErrorCode = "INTERNAL_ERROR"
	ErrNotFound   ErrorCode = "NOT_FOUND"
	ErrBadRequest ErrorCode = "BAD_REQUEST"
)

// AppError represents an application error with context
type AppError struct {
	Code    ErrorCode
	Message string
	Err     error
	Context map[string]interface{}
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s - %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error
func (e *AppError) Unwrap() error {
	return e.Err
}

// NewError creates a new AppError
func NewError(code ErrorCode, message string, err error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
		Context: make(map[string]interface{}),
	}
}

// WithContext adds context to an AppError
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	e.Context[key] = value
	return e
}

// ToGraphQLError converts an AppError to a GraphQL error response
func (e *AppError) ToGraphQLError() map[string]interface{} {
	extensions := map[string]interface{}{
		"code": e.Code,
	}

	// Add context if available
	if len(e.Context) > 0 {
		extensions["context"] = e.Context
	}

	return map[string]interface{}{
		"message":    e.Message,
		"extensions": extensions,
	}
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

// GetAppError extracts an AppError from an error
func GetAppError(err error) *AppError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return NewError(ErrInternal, "An unexpected error occurred", err)
}

// PubSub is a simple publish-subscribe system for GraphQL subscriptions
type PubSub struct {
	subscribers map[string]map[string]chan interface{}
	mutex       sync.RWMutex
}

// NewPubSub creates a new PubSub instance
func NewPubSub() *PubSub {
	return &PubSub{
		subscribers: make(map[string]map[string]chan interface{}),
	}
}

// Subscribe adds a subscriber for a topic
func (ps *PubSub) Subscribe(topic string, id string) chan interface{} {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if _, ok := ps.subscribers[topic]; !ok {
		ps.subscribers[topic] = make(map[string]chan interface{})
	}

	ch := make(chan interface{}, 1)
	ps.subscribers[topic][id] = ch
	return ch
}

// Unsubscribe removes a subscriber from a topic
func (ps *PubSub) Unsubscribe(topic string, id string) {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if _, ok := ps.subscribers[topic]; !ok {
		return
	}

	if ch, ok := ps.subscribers[topic][id]; ok {
		close(ch)
		delete(ps.subscribers[topic], id)
	}
}

// Publish sends a message to all subscribers of a topic
func (ps *PubSub) Publish(topic string, data interface{}) {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	if _, ok := ps.subscribers[topic]; !ok {
		return
	}

	for _, ch := range ps.subscribers[topic] {
		select {
		case ch <- data:
		default:
			// Channel is full, skip this message
		}
	}
}

// PipelineConfig represents the structure of a pipeline configuration file
type PipelineConfig struct {
	Pipelines map[string]PipelineDefinition `yaml:"pipelines"`
}

// PipelineDefinition represents a single pipeline definition
type PipelineDefinition struct {
	Source struct {
		Type   string                 `yaml:"type"`
		Config map[string]interface{} `yaml:"config"`
	} `yaml:"source"`
	Processors []struct {
		Type   string                 `yaml:"type"`
		Config map[string]interface{} `yaml:"config"`
	} `yaml:"processors"`
	Consumers []struct {
		Type   string                 `yaml:"type"`
		Config map[string]interface{} `yaml:"config"`
	} `yaml:"consumers"`
}

// Metrics tracks various metrics for the GraphQL API
type Metrics struct {
	StartTime           time.Time
	TotalQueries        uint64
	TotalMutations      uint64
	TotalSubscriptions  uint64
	ActiveSubscriptions int32
	ErrorCount          uint64
	SlowQueries         uint64
	QueryTimes          []time.Duration // Last 100 query times
	mutex               sync.RWMutex
}

// NewMetrics creates a new Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		StartTime:  time.Now(),
		QueryTimes: make([]time.Duration, 0, 100),
	}
}

// RecordQuery records a query execution
func (m *Metrics) RecordQuery(duration time.Duration) {
	atomic.AddUint64(&m.TotalQueries, 1)

	// Record slow queries (over 500ms)
	if duration > 500*time.Millisecond {
		atomic.AddUint64(&m.SlowQueries, 1)
	}

	// Record query time
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.QueryTimes = append(m.QueryTimes, duration)
	if len(m.QueryTimes) > 100 {
		m.QueryTimes = m.QueryTimes[1:]
	}
}

// RecordMutation records a mutation execution
func (m *Metrics) RecordMutation() {
	atomic.AddUint64(&m.TotalMutations, 1)
}

// RecordSubscription records a new subscription
func (m *Metrics) RecordSubscription() {
	atomic.AddUint64(&m.TotalSubscriptions, 1)
	atomic.AddInt32(&m.ActiveSubscriptions, 1)
}

// RecordUnsubscribe records an unsubscribe event
func (m *Metrics) RecordUnsubscribe() {
	atomic.AddInt32(&m.ActiveSubscriptions, -1)
}

// RecordError records an error
func (m *Metrics) RecordError() {
	atomic.AddUint64(&m.ErrorCount, 1)
}

// GetMetrics returns the current metrics
func (m *Metrics) GetMetrics() map[string]interface{} {
	uptime := time.Since(m.StartTime).Truncate(time.Second)

	// Calculate average query time
	var avgQueryTime time.Duration
	m.mutex.RLock()
	if len(m.QueryTimes) > 0 {
		var total time.Duration
		for _, t := range m.QueryTimes {
			total += t
		}
		avgQueryTime = total / time.Duration(len(m.QueryTimes))
	}
	m.mutex.RUnlock()

	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"uptime":              uptime.String(),
		"totalQueries":        atomic.LoadUint64(&m.TotalQueries),
		"totalMutations":      atomic.LoadUint64(&m.TotalMutations),
		"totalSubscriptions":  atomic.LoadUint64(&m.TotalSubscriptions),
		"activeSubscriptions": atomic.LoadInt32(&m.ActiveSubscriptions),
		"errorCount":          atomic.LoadUint64(&m.ErrorCount),
		"slowQueries":         atomic.LoadUint64(&m.SlowQueries),
		"avgQueryTime":        avgQueryTime.String(),
		"memoryUsage": map[string]interface{}{
			"alloc":      memStats.Alloc,
			"totalAlloc": memStats.TotalAlloc,
			"sys":        memStats.Sys,
			"numGC":      memStats.NumGC,
		},
	}
}

// GraphQLAPI represents the GraphQL API service
type GraphQLAPI struct {
	schemaRegistryURL     string
	httpServer            *http.Server
	schema                *graphql.Schema
	db                    *sql.DB
	pipelineConfigFile    string
	mutex                 *sync.Mutex
	pubsub                *PubSub
	upgrader              websocket.Upgrader
	metrics               *Metrics
	schemaRefreshInterval time.Duration
	lastSchemaRefresh     time.Time
}

// NewGraphQLAPI creates a new GraphQL API service
func NewGraphQLAPI(port, schemaRegistryURL, pipelineConfigFile string) *GraphQLAPI {
	// Create a new HTTP server
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Add a health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create the WebSocket upgrader
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
		Subprotocols: []string{"graphql-ws", "graphql-transport-ws"},
	}

	return &GraphQLAPI{
		schemaRegistryURL:     schemaRegistryURL,
		httpServer:            server,
		pipelineConfigFile:    pipelineConfigFile,
		mutex:                 &sync.Mutex{},
		pubsub:                NewPubSub(),
		upgrader:              upgrader,
		metrics:               NewMetrics(),
		schemaRefreshInterval: 5 * time.Minute, // Refresh schema every 5 minutes
		lastSchemaRefresh:     time.Now(),
	}
}

// Start begins the GraphQL API service
func (api *GraphQLAPI) Start() error {
	// Find the SQLite database path from the pipeline configuration
	dbPath, err := api.findSQLiteConsumer()
	if err != nil {
		log.Printf("Warning: Failed to find SQLite consumer in pipeline config: %v", err)

		// Check if this is a "not found" error
		if appErr, ok := err.(*AppError); ok && appErr.Code == ErrNotFound {
			log.Printf("No SQLite consumer found in pipeline config. GraphQL API will run without database access.")

			// Create a minimal schema with just the health endpoint
			queryType := graphql.NewObject(graphql.ObjectConfig{
				Name: "Query",
				Fields: graphql.Fields{
					"health": &graphql.Field{
						Type: graphql.String,
						Resolve: func(p graphql.ResolveParams) (interface{}, error) {
							return "OK", nil
						},
						Description: "Health check endpoint",
					},
				},
			})

			// Create a minimal subscription type
			subscriptionType := graphql.NewObject(graphql.ObjectConfig{
				Name: "Subscription",
				Fields: graphql.Fields{
					"healthUpdates": &graphql.Field{
						Type: graphql.String,
						Resolve: func(p graphql.ResolveParams) (interface{}, error) {
							return "OK", nil
						},
						Description: "Health check subscription",
					},
				},
			})

			// Create a minimal schema
			schemaConfig := graphql.SchemaConfig{
				Query:        queryType,
				Subscription: subscriptionType,
			}

			schema, err := graphql.NewSchema(schemaConfig)
			if err != nil {
				return fmt.Errorf("failed to create minimal schema: %w", err)
			}

			api.schema = &schema

			// Start the HTTP server without database access
			log.Printf("Starting GraphQL API on :%s", api.httpServer.Addr)
			return api.httpServer.ListenAndServe()
		}

		// For other errors, use the default database path
		log.Printf("Using default database path: flow_data_soroswap_2.db")
		dbPath = "flow_data_soroswap_2.db"
	}

	// Connect to the SQLite database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	api.db = db

	// Test the connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}
	log.Printf("Connected to SQLite database: %s", dbPath)

	// Log database tables for debugging
	rows, err := api.db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		log.Printf("Warning: Failed to query tables: %v", err)
	} else {
		defer rows.Close()
		log.Printf("Tables in database %s:", dbPath)
		for rows.Next() {
			var tableName string
			if err := rows.Scan(&tableName); err != nil {
				log.Printf("Error scanning table name: %v", err)
				continue
			}
			log.Printf("  Table: %s", tableName)

			// Count rows in the table
			count, err := api.countRows(tableName)
			if err != nil {
				log.Printf("    Error counting rows: %v", err)
			} else {
				log.Printf("    Row count: %d", count)
			}
		}
	}

	// Initial schema build
	if err := api.refreshSchema(); err != nil {
		return fmt.Errorf("failed to build initial schema: %w", err)
	}

	// Create the GraphQL handler with the current schema
	h := handler.New(&handler.Config{
		Schema: func() *graphql.Schema {
			return api.getSchema()
		}(),
		Pretty:   true,
		GraphiQL: true,
	})

	// Add the GraphQL endpoint with metrics middleware
	api.httpServer.Handler.(*http.ServeMux).Handle("/graphql", api.metricsMiddleware(h))

	// Add WebSocket endpoint for subscriptions
	api.httpServer.Handler.(*http.ServeMux).HandleFunc("/subscriptions", api.handleWebSocket)

	// Add metrics endpoint
	api.httpServer.Handler.(*http.ServeMux).HandleFunc("/metrics", api.handleMetrics)

	// Start the schema refresh loop in a goroutine
	go api.refreshSchemaLoop()

	// Start the database change monitoring in a goroutine
	go api.monitorDatabaseChanges()

	// Start the HTTP server
	log.Printf("Starting GraphQL API on :%s", api.httpServer.Addr)
	return api.httpServer.ListenAndServe()
}

// refreshSchemaLoop periodically refreshes the GraphQL schema
func (api *GraphQLAPI) refreshSchemaLoop() {
	ticker := time.NewTicker(api.schemaRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := api.refreshSchema(); err != nil {
				log.Printf("Error refreshing schema: %v", err)
			}
		}
	}
}

// refreshSchema refreshes the GraphQL schema
func (api *GraphQLAPI) refreshSchema() error {
	log.Printf("Refreshing GraphQL schema...")

	// Try to fetch schema from registry
	schemaStr, err := api.fetchSchema()
	if err != nil {
		log.Printf("Warning: Failed to fetch schema from registry: %v", err)
		log.Printf("Will build schema from database structure")
		schemaStr = ""
	} else {
		log.Printf("Successfully fetched schema from registry")
	}

	// Build the schema
	schema, err := api.buildSchema(schemaStr)
	if err != nil {
		return fmt.Errorf("failed to build schema: %w", err)
	}

	// Update the API's schema
	api.mutex.Lock()
	api.schema = schema
	api.lastSchemaRefresh = time.Now()
	api.mutex.Unlock()

	log.Printf("Schema refreshed successfully")
	return nil
}

// getSchema returns the current schema, refreshing it if necessary
func (api *GraphQLAPI) getSchema() *graphql.Schema {
	api.mutex.Lock()
	defer api.mutex.Unlock()

	// If the schema is nil or it's time to refresh, refresh it
	if api.schema == nil || time.Since(api.lastSchemaRefresh) > api.schemaRefreshInterval {
		api.mutex.Unlock()
		if err := api.refreshSchema(); err != nil {
			log.Printf("Error refreshing schema: %v", err)
		}
		api.mutex.Lock()
	}

	return api.schema
}

// metricsMiddleware wraps a handler with metrics recording
func (api *GraphQLAPI) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record start time
		startTime := time.Now()

		// Create a response recorder to capture the status code
		rr := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default status code
		}

		// Process the request
		next.ServeHTTP(rr, r)

		// Record metrics
		duration := time.Since(startTime)

		// Parse the request to determine if it's a query or mutation
		if r.Method == http.MethodPost {
			var requestBody struct {
				OperationName string `json:"operationName"`
				Query         string `json:"query"`
			}

			// Try to decode the request body
			if r.Body != nil {
				bodyBytes, _ := io.ReadAll(r.Body)
				r.Body.Close()

				// Create a new reader with the same bytes for the next handler
				r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

				// Parse the body
				_ = json.Unmarshal(bodyBytes, &requestBody)

				// Record the appropriate metric based on operation type
				if strings.Contains(requestBody.Query, "mutation") {
					api.metrics.RecordMutation()
				} else {
					api.metrics.RecordQuery(duration)
				}
			}
		}

		// Record errors
		if rr.statusCode >= 400 {
			api.metrics.RecordError()
		}
	})
}

// responseRecorder is a wrapper for http.ResponseWriter that records the status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader records the status code and calls the wrapped ResponseWriter's WriteHeader
func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

// handleWebSocket handles WebSocket connections for GraphQL subscriptions
func (api *GraphQLAPI) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Configure the upgrader to allow any origin
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
		Subprotocols: []string{"graphql-ws", "graphql-transport-ws"},
	}

	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading to WebSocket: %v", err)
		return
	}
	defer conn.Close()

	// Generate a unique client ID
	clientID := fmt.Sprintf("client-%d", time.Now().UnixNano())
	log.Printf("WebSocket client connected: %s from %s", clientID, r.RemoteAddr)

	// Keep track of active subscriptions for this client
	subscriptions := make(map[string]chan interface{})
	defer func() {
		// Clean up subscriptions when the client disconnects
		for subID, ch := range subscriptions {
			log.Printf("Cleaning up subscription %s for client %s", subID, clientID)
			api.pubsub.Unsubscribe(subID, clientID+":"+subID)
			close(ch)
			delete(subscriptions, subID)
		}
		log.Printf("WebSocket client disconnected: %s", clientID)
	}()

	// Set up a ping handler to keep the connection alive
	conn.SetPingHandler(func(data string) error {
		log.Printf("Received ping from client %s", clientID)
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(10*time.Second))
	})

	// Set up a pong handler to respond to server pings
	conn.SetPongHandler(func(data string) error {
		log.Printf("Received pong from client %s", clientID)
		return nil
	})

	// Start a goroutine to send periodic pings to keep the connection alive
	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, []byte("keepalive"), time.Now().Add(10*time.Second)); err != nil {
					log.Printf("Error sending ping to client %s: %v", clientID, err)
					return
				}
				log.Printf("Sent ping to client %s", clientID)
			case <-stopPing:
				return
			}
		}
	}()
	defer close(stopPing)

	// Handle incoming messages
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			} else {
				log.Printf("WebSocket closed: %v", err)
			}
			break
		}

		// Log the received message for debugging
		log.Printf("Received WebSocket message from %s: %s", clientID, string(message))

		// Parse the message as JSON
		var request map[string]interface{}
		if err := json.Unmarshal(message, &request); err != nil {
			log.Printf("Error parsing WebSocket message: %v", err)
			sendErrorResponse(conn, "invalid_json", "Invalid JSON")
			continue
		}

		// Check if this is a GraphQL subscription request
		if typ, ok := request["type"].(string); ok {
			switch typ {
			case "connection_init":
				// Client is initializing the connection
				log.Printf("Client %s initialized connection", clientID)
				sendResponse(conn, "connection_ack", nil)

			case "start":
				// Client is starting a subscription
				id, ok := request["id"].(string)
				if !ok {
					sendErrorResponse(conn, "invalid_request", "Missing subscription ID")
					continue
				}

				payload, ok := request["payload"].(map[string]interface{})
				if !ok {
					sendErrorResponse(conn, "invalid_request", "Missing payload")
					continue
				}

				query, ok := payload["query"].(string)
				if !ok {
					sendErrorResponse(conn, "invalid_request", "Missing query")
					continue
				}

				variables, _ := payload["variables"].(map[string]interface{})

				log.Printf("Client %s starting subscription %s with query: %s", clientID, id, query)

				// Process the subscription request in a separate goroutine
				go api.handleSubscription(conn, clientID, id, query, variables, subscriptions)

			case "stop":
				// Client is stopping a subscription
				id, ok := request["id"].(string)
				if !ok {
					sendErrorResponse(conn, "invalid_request", "Missing subscription ID")
					continue
				}

				log.Printf("Client %s stopping subscription %s", clientID, id)

				// Unsubscribe from the topic
				if ch, ok := subscriptions[id]; ok {
					api.pubsub.Unsubscribe(id, clientID+":"+id)
					close(ch)
					delete(subscriptions, id)
				}

				sendResponse(conn, "complete", map[string]string{"id": id})

			default:
				log.Printf("Unknown message type from client %s: %s", clientID, typ)
				sendErrorResponse(conn, "unknown_type", fmt.Sprintf("Unknown message type: %s", typ))
			}
		} else {
			sendErrorResponse(conn, "invalid_request", "Missing message type")
		}
	}
}

// handleSubscription processes a GraphQL subscription request
func (api *GraphQLAPI) handleSubscription(
	conn *websocket.Conn,
	clientID string,
	subscriptionID string,
	query string,
	variables map[string]interface{},
	subscriptions map[string]chan interface{},
) {
	// Parse the GraphQL query
	document, err := parser.Parse(parser.ParseParams{
		Source: query,
	})
	if err != nil {
		sendErrorResponse(conn, "invalid_query", fmt.Sprintf("Invalid GraphQL query: %v", err))
		return
	}

	// Extract the operation name and subscription field
	var operationName string
	var fieldName string
	var args map[string]interface{}

	for _, definition := range document.Definitions {
		if operationDefinition, ok := definition.(*ast.OperationDefinition); ok {
			if operationDefinition.Operation == "subscription" {
				if operationDefinition.Name != nil {
					operationName = operationDefinition.Name.Value
				}

				// Get the subscription field name and arguments
				if len(operationDefinition.SelectionSet.Selections) > 0 {
					if field, ok := operationDefinition.SelectionSet.Selections[0].(*ast.Field); ok {
						fieldName = field.Name.Value

						// Extract arguments
						args = make(map[string]interface{})
						for _, arg := range field.Arguments {
							if arg.Value != nil {
								switch value := arg.Value.(type) {
								case *ast.StringValue:
									args[arg.Name.Value] = value.Value
								case *ast.IntValue:
									args[arg.Name.Value] = value.Value
								case *ast.FloatValue:
									args[arg.Name.Value] = value.Value
								case *ast.BooleanValue:
									args[arg.Name.Value] = value.Value
								case *ast.EnumValue:
									args[arg.Name.Value] = value.Value
								case *ast.ListValue:
									// Handle list values (simplified)
									listValues := []interface{}{}
									for _, item := range value.Values {
										if strItem, ok := item.(*ast.StringValue); ok {
											listValues = append(listValues, strItem.Value)
										}
									}
									args[arg.Name.Value] = listValues
								case *ast.ObjectValue:
									// Handle object values (simplified)
									objValues := map[string]interface{}{}
									for _, field := range value.Fields {
										if strField, ok := field.Value.(*ast.StringValue); ok {
											objValues[field.Name.Value] = strField.Value
										}
									}
									args[arg.Name.Value] = objValues
								}
							}
						}
					}
				}
				break
			}
		}
	}

	if fieldName == "" {
		sendErrorResponse(conn, "invalid_subscription", "No subscription field found")
		return
	}

	log.Printf("Subscription request: client=%s, id=%s, operation=%s, field=%s, args=%v",
		clientID, subscriptionID, operationName, fieldName, args)

	// Extract the ID argument if present
	var id interface{}
	if idArg, ok := args["id"]; ok && idArg != "" {
		id = idArg
	}

	// Construct the topic based on the field name and ID
	var topic string
	if id != nil && id != "" {
		// If an ID is provided, subscribe to changes for that specific entity
		topic = fmt.Sprintf("%s:%v:changed", fieldName, id)
		log.Printf("Subscribing to specific topic: %s", topic)
	} else {
		// Otherwise, subscribe to all changes for this entity type
		topic = fmt.Sprintf("%s:all:changed", fieldName)
		log.Printf("Subscribing to wildcard topic: %s", topic)
	}

	// Subscribe to the topic
	subKey := clientID + ":" + subscriptionID
	ch := api.pubsub.Subscribe(topic, subKey)
	subscriptions[subscriptionID] = ch

	// Send an initial confirmation that the subscription is active
	response := map[string]interface{}{
		"type": "next",
		"id":   subscriptionID,
		"payload": map[string]interface{}{
			"data": map[string]interface{}{
				fieldName: nil,
			},
		},
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling initial subscription response: %v", err)
	} else {
		if err := conn.WriteMessage(websocket.TextMessage, jsonResponse); err != nil {
			log.Printf("Error sending initial subscription response: %v", err)
			return
		}
	}

	// Listen for messages on this subscription
	for data := range ch {
		log.Printf("Received data on topic %s: %v", topic, data)

		// Add a type assertion for the data
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			log.Printf("Error: received data is not a map[string]interface{}, got %T", data)
			continue
		}

		// Execute the GraphQL query with the data
		params := graphql.Params{
			Schema:         *api.getSchema(),
			RequestString:  query,
			VariableValues: variables,
			OperationName:  operationName,
			Context:        context.Background(),
			RootObject:     dataMap,
		}
		result := graphql.Do(params)

		if len(result.Errors) > 0 {
			log.Printf("GraphQL execution errors: %v", result.Errors)
		}

		// Send the result to the client
		response := map[string]interface{}{
			"type":    "next",
			"id":      subscriptionID,
			"payload": result,
		}

		jsonResponse, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshaling subscription response: %v", err)
			continue
		}

		log.Printf("Sending subscription data to client %s: %s", clientID, string(jsonResponse))
		if err := conn.WriteMessage(websocket.TextMessage, jsonResponse); err != nil {
			log.Printf("Error sending subscription data: %v", err)
			return
		}
	}

	log.Printf("Subscription %s for client %s ended", subscriptionID, clientID)
}

// sendResponse sends a response to the WebSocket client
func sendResponse(conn *websocket.Conn, typ string, payload interface{}) {
	response := map[string]interface{}{
		"type": typ,
	}
	if payload != nil {
		response["payload"] = payload
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, jsonResponse); err != nil {
		log.Printf("Error sending response: %v", err)
	}
}

// sendErrorResponse sends an error response to the WebSocket client
func sendErrorResponse(conn *websocket.Conn, code string, message string) {
	response := map[string]interface{}{
		"type": "error",
		"payload": map[string]string{
			"code":    code,
			"message": message,
		},
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling error response: %v", err)
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, jsonResponse); err != nil {
		log.Printf("Error sending error response: %v", err)
	}
}

// Stop gracefully stops the GraphQL API service
func (api *GraphQLAPI) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := api.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	if api.db != nil {
		if err := api.db.Close(); err != nil {
			return err
		}
	}

	return nil
}

// findSQLiteConsumer finds the SQLite consumer in the pipeline configuration
func (api *GraphQLAPI) findSQLiteConsumer() (string, error) {
	// Check if a database path is provided via environment variable
	if dbPath := os.Getenv("GRAPHQL_API_DB_PATH"); dbPath != "" {
		log.Printf("Using database path from environment variable: %s", dbPath)
		return dbPath, nil
	}

	// Read the pipeline configuration file
	data, err := os.ReadFile(api.pipelineConfigFile)
	if err != nil {
		return "", NewError(ErrInvalidConfig, "Failed to read pipeline config file", err).
			WithContext("file", api.pipelineConfigFile)
	}

	// Parse the YAML configuration
	var config PipelineConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return "", NewError(ErrInvalidConfig, "Failed to parse pipeline config", err).
			WithContext("file", api.pipelineConfigFile)
	}

	// Look for a SQLite consumer in any pipeline
	for pipelineName, pipeline := range config.Pipelines {
		for _, consumer := range pipeline.Consumers {
			// Check if this is a SQLite consumer (case-insensitive substring match)
			if strings.Contains(strings.ToLower(consumer.Type), "sqlite") {
				if dbPath, ok := consumer.Config["db_path"].(string); ok && dbPath != "" {
					log.Printf("Found SQLite consumer in pipeline %s with db_path: %s", pipelineName, dbPath)
					return dbPath, nil
				}
			}
		}
	}

	return "", NewError(ErrNotFound, "No SQLite consumer found in pipeline config", nil).
		WithContext("file", api.pipelineConfigFile)
}

// fetchSchema fetches the schema from the schema registry
func (api *GraphQLAPI) fetchSchema() (string, error) {
	// Set up HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Try to fetch the schema with retries
	var resp *http.Response
	var err error
	maxRetries := 3
	retryDelay := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		// Make the request
		resp, err = client.Get(api.schemaRegistryURL + "/schema")
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}

		if err != nil {
			log.Printf("Attempt %d: Error connecting to schema registry: %v", i+1, err)
		} else {
			log.Printf("Attempt %d: Schema registry returned status: %d", i+1, resp.StatusCode)
			resp.Body.Close()
		}

		if i < maxRetries-1 {
			log.Printf("Retrying in %v...", retryDelay)
			time.Sleep(retryDelay)
		}
	}

	if err != nil {
		return "", NewError(ErrSchemaBuilding, "Failed to connect to schema registry", err).
			WithContext("url", api.schemaRegistryURL).
			WithContext("retries", maxRetries)
	}

	if resp.StatusCode != http.StatusOK {
		return "", NewError(ErrSchemaBuilding, "Schema registry returned non-OK status", nil).
			WithContext("url", api.schemaRegistryURL).
			WithContext("status", resp.StatusCode)
	}

	defer resp.Body.Close()
	schema, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", NewError(ErrSchemaBuilding, "Failed to read schema response", err).
			WithContext("url", api.schemaRegistryURL)
	}

	return string(schema), nil
}

// buildSchema builds a GraphQL schema from the registry schema
func (api *GraphQLAPI) buildSchema(registrySchema string) (*graphql.Schema, error) {
	// Create fields for query and subscription
	queryFields := graphql.Fields{
		"health": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				return "OK", nil
			},
			Description: "Health check endpoint",
		},
	}

	subscriptionFields := graphql.Fields{}

	// Create the root query type
	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name:   "Query",
		Fields: queryFields,
	})

	// Create the root subscription type
	subscriptionType := graphql.NewObject(graphql.ObjectConfig{
		Name:   "Subscription",
		Fields: subscriptionFields,
	})

	// Add fields from the database
	if err := api.buildSchemaFromDatabase(queryFields); err != nil {
		return nil, fmt.Errorf("failed to build schema from database: %w", err)
	}

	// Add subscription fields
	if err := api.buildSubscriptionFields(subscriptionFields); err != nil {
		return nil, fmt.Errorf("failed to build subscription fields: %w", err)
	}

	// Create the schema with both query and subscription types
	schemaConfig := graphql.SchemaConfig{
		Query:        queryType,
		Subscription: subscriptionType,
	}

	schema, err := graphql.NewSchema(schemaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &schema, nil
}

// buildSchemaFromDatabase builds a GraphQL schema from the database structure
func (api *GraphQLAPI) buildSchemaFromDatabase(fields graphql.Fields) error {
	// Get all tables in the database
	rows, err := api.db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, tableName)
	}

	// Process each table
	for _, tableName := range tables {
		// Skip internal tables
		if tableName == "sqlite_sequence" || tableName == "flow_metadata" {
			continue
		}

		log.Printf("Building schema for table: %s", tableName)

		// Get table schema
		schemaRows, err := api.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			log.Printf("Error getting schema for table %s: %v", tableName, err)
			continue
		}

		// Create fields for the type
		typeFields := graphql.Fields{}
		var columns []string
		var idField string
		var columnTypes []string

		for schemaRows.Next() {
			var cid int
			var name, typeName string
			var notNull, pk int
			var defaultValue interface{}

			if err := schemaRows.Scan(&cid, &name, &typeName, &notNull, &defaultValue, &pk); err != nil {
				log.Printf("Error scanning column info: %v", err)
				continue
			}

			columns = append(columns, name)
			columnTypes = append(columnTypes, typeName)

			// Identify the ID field (primary key)
			if pk == 1 {
				idField = name
			}

			// Map SQL type to GraphQL type
			var fieldType graphql.Type
			switch strings.ToUpper(typeName) {
			case "INTEGER", "INT", "SMALLINT", "MEDIUMINT", "BIGINT":
				fieldType = graphql.Int
			case "REAL", "FLOAT", "DOUBLE", "NUMERIC", "DECIMAL":
				fieldType = graphql.Float
			case "TEXT", "VARCHAR", "CHAR", "CLOB":
				fieldType = graphql.String
			case "BOOLEAN":
				fieldType = graphql.Boolean
			default:
				fieldType = graphql.String // Default to string for unknown types
			}

			// Make non-nullable if required
			if notNull == 1 && pk == 0 { // Primary keys can be auto-increment, so they might appear null initially
				fieldType = graphql.NewNonNull(fieldType)
			}

			// Add field with description
			typeFields[name] = &graphql.Field{
				Type:        fieldType,
				Description: fmt.Sprintf("The %s field from the %s table", name, tableName),
				// Add metadata about the field
				Args: graphql.FieldConfigArgument{},
				// Add resolver for nested objects if needed
			}
		}
		schemaRows.Close()

		// If no columns were found, skip this table
		if len(columns) == 0 {
			log.Printf("No columns found for table %s, skipping", tableName)
			continue
		}

		// If no ID field was found, use the first column
		if idField == "" {
			idField = columns[0]
			log.Printf("No primary key found for table %s, using first column %s as ID", tableName, idField)
		}

		// Create the object type with description
		// Add "DB" prefix to avoid conflicts with existing types
		typeName := "DB" + api.pascalCase(api.singularize(tableName))
		objectType := graphql.NewObject(graphql.ObjectConfig{
			Name:        typeName,
			Fields:      typeFields,
			Description: fmt.Sprintf("Represents a %s record from the database", api.singularize(tableName)),
		})

		// Create the edge type for connections
		edgeType := graphql.NewObject(graphql.ObjectConfig{
			Name: typeName + "Edge",
			Fields: graphql.Fields{
				"node": &graphql.Field{
					Type:        objectType,
					Description: fmt.Sprintf("The %s node", api.singularize(tableName)),
				},
				"cursor": &graphql.Field{
					Type:        graphql.String,
					Description: "A cursor for pagination",
				},
			},
			Description: fmt.Sprintf("An edge containing a %s node and its cursor", api.singularize(tableName)),
		})

		// Create the page info type if it doesn't exist yet
		var pageInfoType *graphql.Object
		if _, exists := fields["pageInfo"]; !exists {
			pageInfoType = graphql.NewObject(graphql.ObjectConfig{
				Name: "PageInfo",
				Fields: graphql.Fields{
					"hasNextPage": &graphql.Field{
						Type:        graphql.NewNonNull(graphql.Boolean),
						Description: "Indicates if there are more pages to fetch",
					},
					"endCursor": &graphql.Field{
						Type:        graphql.String,
						Description: "The cursor to continue pagination",
					},
				},
				Description: "Information about pagination in a connection",
			})
			fields["pageInfo"] = &graphql.Field{
				Type:        pageInfoType,
				Description: "Information about pagination in a connection",
			}
		}

		// Create the connection type
		connectionType := graphql.NewObject(graphql.ObjectConfig{
			Name: typeName + "Connection",
			Fields: graphql.Fields{
				"edges": &graphql.Field{
					Type:        graphql.NewList(edgeType),
					Description: fmt.Sprintf("A list of %s edges", api.singularize(tableName)),
				},
				"pageInfo": &graphql.Field{
					Type:        graphql.NewNonNull(pageInfoType),
					Description: "Information to aid in pagination",
				},
			},
			Description: fmt.Sprintf("A connection to a list of %s items", api.singularize(tableName)),
		})

		// Add query fields for this table
		fields[api.camelCase(api.singularize(tableName))] = &graphql.Field{
			Type:        objectType,
			Description: fmt.Sprintf("Get a single %s by ID", api.singularize(tableName)),
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type:        graphql.NewNonNull(graphql.ID),
					Description: fmt.Sprintf("The ID of the %s", api.singularize(tableName)),
				},
			},
			Resolve: api.createSingleItemResolver(tableName, columns, idField),
		}

		fields[api.camelCase(api.pluralize(tableName))] = &graphql.Field{
			Type:        connectionType,
			Description: fmt.Sprintf("Get a list of %s", api.pluralize(tableName)),
			Args: graphql.FieldConfigArgument{
				"first": &graphql.ArgumentConfig{
					Type:        graphql.Int,
					Description: "Returns the first n elements from the list",
				},
				"after": &graphql.ArgumentConfig{
					Type:        graphql.String,
					Description: "Returns the elements that come after the specified cursor",
				},
				"last": &graphql.ArgumentConfig{
					Type:        graphql.Int,
					Description: "Returns the last n elements from the list",
				},
				"before": &graphql.ArgumentConfig{
					Type:        graphql.String,
					Description: "Returns the elements that come before the specified cursor",
				},
			},
			Resolve: api.createListResolver(tableName, columns, idField),
		}
	}

	return nil
}

// createSingleItemResolver creates a resolver for a single item query
func (api *GraphQLAPI) createSingleItemResolver(tableName string, columns []string, idField string) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		id, ok := p.Args[idField].(string)
		if !ok {
			return nil, fmt.Errorf("invalid ID argument")
		}

		log.Printf("Querying %s with %s=%s", tableName, idField, id)

		query := fmt.Sprintf("SELECT * FROM %s WHERE %s = ?", tableName, idField)
		row := api.db.QueryRow(query, id)

		// Create a map to hold the result
		result := make(map[string]interface{})
		scanArgs := make([]interface{}, len(columns))
		scanValues := make([]interface{}, len(columns))
		for i := range columns {
			scanValues[i] = new(interface{})
			scanArgs[i] = scanValues[i]
		}

		if err := row.Scan(scanArgs...); err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, fmt.Errorf("error scanning row: %w", err)
		}

		// Populate the result map
		for i, col := range columns {
			val := *(scanValues[i].(*interface{}))
			if val == nil {
				result[col] = nil
				continue
			}

			// Handle different types
			switch v := val.(type) {
			case []byte:
				// Try to convert to string
				result[col] = string(v)
			default:
				result[col] = v
			}
		}

		return result, nil
	}
}

// createListResolver creates a resolver for a list query
func (api *GraphQLAPI) createListResolver(tableName string, columns []string, idField string) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (interface{}, error) {
		// Get pagination arguments
		first, _ := p.Args["first"].(int)
		if first <= 0 {
			first = 10 // Default limit
		}

		after, _ := p.Args["after"].(string)

		// Get filtering arguments
		filter, _ := p.Args["filter"].(map[string]interface{})

		// Get sorting arguments
		orderBy, _ := p.Args["orderBy"].(string)
		orderDir, _ := p.Args["orderDirection"].(string)
		if orderDir == "" {
			orderDir = "ASC" // Default sort direction
		}

		log.Printf("Querying %s with first=%d, after=%s, filter=%v, orderBy=%s, orderDir=%s",
			tableName, first, after, filter, orderBy, orderDir)

		// Build the query
		query := fmt.Sprintf("SELECT * FROM %s", tableName)
		args := []interface{}{}

		// Add WHERE clauses for filtering
		whereConditions := []string{}

		// Add after cursor condition if provided
		if after != "" && idField != "" {
			whereConditions = append(whereConditions, fmt.Sprintf("%s > ?", idField))
			args = append(args, after)
		}

		// Add filter conditions if provided
		if filter != nil {
			for field, value := range filter {
				// Skip if the field doesn't exist in the table
				if !contains(columns, field) {
					continue
				}

				// Handle different filter operations based on value type
				switch v := value.(type) {
				case map[string]interface{}:
					// Complex filter with operators
					for op, opValue := range v {
						switch op {
						case "eq":
							whereConditions = append(whereConditions, fmt.Sprintf("%s = ?", field))
							args = append(args, opValue)
						case "neq":
							whereConditions = append(whereConditions, fmt.Sprintf("%s != ?", field))
							args = append(args, opValue)
						case "gt":
							whereConditions = append(whereConditions, fmt.Sprintf("%s > ?", field))
							args = append(args, opValue)
						case "gte":
							whereConditions = append(whereConditions, fmt.Sprintf("%s >= ?", field))
							args = append(args, opValue)
						case "lt":
							whereConditions = append(whereConditions, fmt.Sprintf("%s < ?", field))
							args = append(args, opValue)
						case "lte":
							whereConditions = append(whereConditions, fmt.Sprintf("%s <= ?", field))
							args = append(args, opValue)
						case "like":
							whereConditions = append(whereConditions, fmt.Sprintf("%s LIKE ?", field))
							args = append(args, fmt.Sprintf("%%%s%%", opValue))
						case "in":
							// Handle IN operator with array of values
							if values, ok := opValue.([]interface{}); ok && len(values) > 0 {
								placeholders := make([]string, len(values))
								for i := range values {
									placeholders[i] = "?"
									args = append(args, values[i])
								}
								whereConditions = append(whereConditions, fmt.Sprintf("%s IN (%s)", field, strings.Join(placeholders, ",")))
							}
						}
					}
				default:
					// Simple equality filter
					whereConditions = append(whereConditions, fmt.Sprintf("%s = ?", field))
					args = append(args, v)
				}
			}
		}

		// Add WHERE clause to query if we have conditions
		if len(whereConditions) > 0 {
			query += " WHERE " + strings.Join(whereConditions, " AND ")
		}

		// Add ORDER BY clause
		if orderBy != "" && contains(columns, orderBy) {
			// Sanitize order direction
			if orderDir != "ASC" && orderDir != "DESC" {
				orderDir = "ASC"
			}
			query += fmt.Sprintf(" ORDER BY %s %s", orderBy, orderDir)
		} else if idField != "" {
			// Default sort by ID
			query += fmt.Sprintf(" ORDER BY %s ASC", idField)
		}

		// Request one more than needed to determine if there are more pages
		query += " LIMIT ?"
		args = append(args, first+1)

		rows, err := api.db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("error querying database: %w", err)
		}
		defer rows.Close()

		// Process the results
		var edges []map[string]interface{}
		var hasNextPage bool
		var lastCursor string
		count := 0

		for rows.Next() {
			// If we've reached our limit, just set hasNextPage and break
			if count >= first {
				hasNextPage = true
				break
			}

			// Create a map to hold the result
			result := make(map[string]interface{})
			scanArgs := make([]interface{}, len(columns))
			scanValues := make([]interface{}, len(columns))
			for i := range columns {
				scanValues[i] = new(interface{})
				scanArgs[i] = scanValues[i]
			}

			if err := rows.Scan(scanArgs...); err != nil {
				return nil, fmt.Errorf("error scanning row: %w", err)
			}

			// Populate the result map
			for i, col := range columns {
				val := *(scanValues[i].(*interface{}))
				if val == nil {
					result[col] = nil
					continue
				}

				// Handle different types
				switch v := val.(type) {
				case []byte:
					// Try to convert to string
					result[col] = string(v)
				default:
					result[col] = v
				}
			}

			// Get the cursor (ID) for this edge
			var cursor string
			if idVal, ok := result[idField]; ok && idVal != nil {
				cursor = fmt.Sprintf("%v", idVal)
				lastCursor = cursor
			}

			// Create the edge
			edge := map[string]interface{}{
				"node":   result,
				"cursor": cursor,
			}

			edges = append(edges, edge)
			count++
		}

		// Create the connection result
		connection := map[string]interface{}{
			"edges": edges,
			"pageInfo": map[string]interface{}{
				"hasNextPage": hasNextPage,
				"endCursor":   lastCursor,
			},
		}

		return connection, nil
	}
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Helper functions

// countRows counts the number of rows in a table
func (api *GraphQLAPI) countRows(tableName string) (int, error) {
	row := api.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName))
	var count int
	err := row.Scan(&count)
	return count, err
}

// findIdField finds the ID field in a list of columns
func (api *GraphQLAPI) findIdField(columns []string) string {
	// Common ID field names
	idFields := []string{"id", "account_id", "sequence", "hash"}

	for _, field := range idFields {
		for _, col := range columns {
			if strings.EqualFold(col, field) {
				return col
			}
		}
	}

	return ""
}

// singularize converts a plural word to singular
func (api *GraphQLAPI) singularize(s string) string {
	if strings.HasSuffix(s, "ies") {
		return s[:len(s)-3] + "y"
	}
	if strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss") {
		return s[:len(s)-1]
	}
	return s
}

// pluralize converts a singular word to plural
func (api *GraphQLAPI) pluralize(s string) string {
	if strings.HasSuffix(s, "y") {
		return s[:len(s)-1] + "ies"
	}
	if !strings.HasSuffix(s, "s") {
		return s + "s"
	}
	return s
}

// pascalCase converts a string to PascalCase
func (api *GraphQLAPI) pascalCase(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}

	return strings.Join(words, "")
}

// camelCase converts a string to camelCase
func (api *GraphQLAPI) camelCase(s string) string {
	pascal := api.pascalCase(s)
	if len(pascal) > 0 {
		return strings.ToLower(pascal[:1]) + pascal[1:]
	}
	return ""
}

// buildSubscriptionFields builds the subscription fields for the GraphQL schema
func (api *GraphQLAPI) buildSubscriptionFields(fields graphql.Fields) error {
	// Get all tables in the database
	rows, err := api.db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return fmt.Errorf("failed to scan table name: %w", err)
		}

		// Skip internal tables
		if tableName == "sqlite_sequence" || tableName == "flow_metadata" {
			continue
		}

		tables = append(tables, tableName)
	}

	// Process each table for subscriptions
	for _, tableName := range tables {
		// Get table schema
		schemaRows, err := api.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			log.Printf("Error getting schema for table %s: %v", tableName, err)
			continue
		}

		var columns []string
		var idField string

		for schemaRows.Next() {
			var cid int
			var name, typeName string
			var notNull, pk int
			var defaultValue interface{}

			if err := schemaRows.Scan(&cid, &name, &typeName, &notNull, &defaultValue, &pk); err != nil {
				log.Printf("Error scanning column info: %v", err)
				continue
			}

			columns = append(columns, name)

			// Identify the ID field (primary key)
			if pk == 1 {
				idField = name
			}
		}
		schemaRows.Close()

		// If we found an ID field, create a subscription for this table
		if idField != "" {
			// Create the subscription field
			singularName := api.singularize(tableName)

			// Find the corresponding object type from the query fields
			objectType, err := api.getObjectTypeForTable(tableName)
			if err != nil {
				log.Printf("Warning: Could not create subscription for %s: %v", tableName, err)
				continue
			}

			// Add the subscription field
			fields[singularName+"Changed"] = &graphql.Field{
				Type: objectType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{
						Type:        graphql.String,
						Description: "Optional account ID. If not provided, subscribes to all account changes.",
					},
				},
				// Implement the resolver to handle both regular queries and subscription events
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					// Get the ID from arguments (now optional)
					var id string
					if idArg, ok := p.Args["id"].(string); ok && idArg != "" {
						id = idArg
					}

					// If this is a subscription event (has Source data)
					if p.Source != nil {
						log.Printf("Processing subscription event with source type: %T, value: %v", p.Source, p.Source)

						// Try different formats that might be used in the payload
						if payload, ok := p.Source.(map[string]interface{}); ok {
							log.Printf("Payload keys: %v", getMapKeys(payload))

							// If we have an ID filter, check if this event is for the requested ID
							if id != "" {
								// Check if the payload has an ID that matches our filter
								if payloadID, ok := payload["id"]; ok && fmt.Sprintf("%v", payloadID) != id {
									// This event is for a different account, skip it
									return nil, fmt.Errorf("event is for a different account")
								}
							}

							// Option 1: Check if we have a data field
							if data, ok := payload["data"].(map[string]interface{}); ok {
								log.Printf("Found data in payload: %v", data)
								return data, nil
							}

							// Option 2: If no data field, maybe the payload itself is the data
							// Check if it has an ID field
							if _, ok := payload["id"]; ok {
								log.Printf("Using payload as data: %v", payload)
								return payload, nil
							}

							// Option 3: For GraphiQL direct queries, just return the row from the database
							if _, ok := payload["query"]; ok {
								log.Printf("GraphiQL direct query detected")
								if id != "" {
									return api.fetchRecordFromDatabase(tableName, idField, id, columns)
								} else {
									// For wildcard subscriptions in GraphiQL, return a placeholder
									return map[string]interface{}{
										"account_id":           "PLACEHOLDER",
										"balance":              "0",
										"sequence":             "0",
										"num_subentries":       0,
										"flags":                0,
										"last_modified_ledger": 0,
									}, nil
								}
							}

							// Option 4: Maybe the payload is just a wrapper and we need to return something
							// This is a fallback that might work in some cases
							if id != "" {
								return map[string]interface{}{
									"account_id":           id,
									"balance":              "0",
									"sequence":             "0",
									"num_subentries":       0,
									"flags":                0,
									"last_modified_ledger": 0,
								}, nil
							} else {
								return map[string]interface{}{
									"account_id":           "PLACEHOLDER",
									"balance":              "0",
									"sequence":             "0",
									"num_subentries":       0,
									"flags":                0,
									"last_modified_ledger": 0,
								}, nil
							}
						}

						// If we got here, we couldn't extract the data
						return nil, fmt.Errorf("could not extract data from event payload")
					}

					// If this is a regular query (no Source data), fetch from database
					if id == "" {
						// For wildcard queries, return a placeholder
						return map[string]interface{}{
							"account_id":           "PLACEHOLDER",
							"balance":              "0",
							"sequence":             "0",
							"num_subentries":       0,
							"flags":                0,
							"last_modified_ledger": 0,
						}, nil
					}

					log.Printf("Processing regular query for %s with ID: %s", tableName, id)
					return api.fetchRecordFromDatabase(tableName, idField, id, columns)
				},
				Description: fmt.Sprintf("Subscribe to changes to a %s. If no ID is provided, subscribes to all changes.", singularName),
			}
		}
	}

	return nil
}

// getObjectTypeForTable finds the GraphQL object type for a given table
func (api *GraphQLAPI) getObjectTypeForTable(tableName string) (*graphql.Object, error) {
	// Get table schema
	schemaRows, err := api.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, fmt.Errorf("error getting schema for table %s: %w", tableName, err)
	}
	defer schemaRows.Close()

	// Create fields for the type
	typeFields := graphql.Fields{}

	for schemaRows.Next() {
		var cid int
		var name, typeName string
		var notNull, pk int
		var defaultValue interface{}

		if err := schemaRows.Scan(&cid, &name, &typeName, &notNull, &defaultValue, &pk); err != nil {
			return nil, fmt.Errorf("error scanning column info: %w", err)
		}

		// Map SQL type to GraphQL type
		var fieldType graphql.Type
		switch strings.ToUpper(typeName) {
		case "INTEGER", "INT", "SMALLINT", "MEDIUMINT", "BIGINT":
			fieldType = graphql.Int
		case "REAL", "FLOAT", "DOUBLE", "NUMERIC", "DECIMAL":
			fieldType = graphql.Float
		case "TEXT", "VARCHAR", "CHAR", "CLOB":
			fieldType = graphql.String
		case "BOOLEAN":
			fieldType = graphql.Boolean
		default:
			fieldType = graphql.String // Default to string for unknown types
		}

		typeFields[name] = &graphql.Field{
			Type: fieldType,
		}
	}

	// Create the object type
	return graphql.NewObject(graphql.ObjectConfig{
		Name:   api.pascalCase(api.singularize(tableName)),
		Fields: typeFields,
	}), nil
}

// monitorDatabaseChanges monitors the database for changes and publishes events to subscribers
func (api *GraphQLAPI) monitorDatabaseChanges() {
	log.Printf("Starting database change monitoring")

	// Get all tables in the database
	rows, err := api.db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		log.Printf("Error querying tables for monitoring: %v", err)
		return
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			log.Printf("Error scanning table name: %v", err)
			continue
		}

		// Skip internal tables
		if tableName == "sqlite_sequence" || tableName == "flow_metadata" {
			continue
		}

		tables = append(tables, tableName)
	}

	// Create a map to store the last known row counts for each table
	lastCounts := make(map[string]int)

	// Initialize the last counts
	for _, tableName := range tables {
		count, err := api.countRows(tableName)
		if err != nil {
			log.Printf("Error counting rows in %s: %v", tableName, err)
			continue
		}
		lastCounts[tableName] = count
	}

	// Poll for changes every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, tableName := range tables {
				// Get the current row count
				currentCount, err := api.countRows(tableName)
				if err != nil {
					log.Printf("Error counting rows in %s: %v", tableName, err)
					continue
				}

				// If the count has changed, something has been added or removed
				if currentCount != lastCounts[tableName] {
					log.Printf("Detected change in table %s: %d -> %d rows", tableName, lastCounts[tableName], currentCount)

					// Determine if rows were added or removed
					if currentCount > lastCounts[tableName] {
						// Rows were added - find the new rows
						api.handleRowsAdded(tableName, lastCounts[tableName], currentCount)
					} else {
						// Rows were removed - we can't easily determine which ones
						// Just notify that something changed
						api.pubsub.Publish(tableName+":changed", map[string]interface{}{
							"table":  tableName,
							"action": "removed",
						})
					}

					// Update the last known count
					lastCounts[tableName] = currentCount
				}
			}
		}
	}
}

// handleRowsAdded handles the case where rows were added to a table
func (api *GraphQLAPI) handleRowsAdded(tableName string, oldCount, newCount int) {
	// Get the schema for this table
	schemaRows, err := api.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		log.Printf("Error getting schema for table %s: %v", tableName, err)
		return
	}
	defer schemaRows.Close()

	var columns []string
	var idField string

	for schemaRows.Next() {
		var cid int
		var name, typeName string
		var notNull, pk int
		var defaultValue interface{}

		if err := schemaRows.Scan(&cid, &name, &typeName, &notNull, &defaultValue, &pk); err != nil {
			log.Printf("Error scanning column info: %v", err)
			continue
		}

		columns = append(columns, name)

		// Identify the ID field (primary key)
		if pk == 1 {
			idField = name
		}
	}

	// If we couldn't find an ID field, use the first column
	if idField == "" && len(columns) > 0 {
		idField = columns[0]
	}

	// If we still don't have an ID field, we can't proceed
	if idField == "" {
		log.Printf("Could not find ID field for table %s", tableName)
		return
	}

	log.Printf("Processing %d new rows in table %s with ID field %s", newCount-oldCount, tableName, idField)

	// Query for the new rows
	// This is a simplistic approach - in a real system, you might want to use timestamps or sequence numbers
	query := fmt.Sprintf("SELECT * FROM %s ORDER BY %s DESC LIMIT ?", tableName, idField)
	rows, err := api.db.Query(query, newCount-oldCount)
	if err != nil {
		log.Printf("Error querying new rows: %v", err)
		return
	}
	defer rows.Close()

	// Process each new row
	for rows.Next() {
		// Create a map to hold the result
		result := make(map[string]interface{})
		scanArgs := make([]interface{}, len(columns))
		scanValues := make([]interface{}, len(columns))
		for i := range columns {
			scanValues[i] = new(interface{})
			scanArgs[i] = scanValues[i]
		}

		if err := rows.Scan(scanArgs...); err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		// Populate the result map
		for i, col := range columns {
			val := *(scanValues[i].(*interface{}))
			if val == nil {
				result[col] = nil
				continue
			}

			// Handle different types
			switch v := val.(type) {
			case []byte:
				// Try to convert to string
				result[col] = string(v)
			default:
				result[col] = v
			}
		}

		// Get the ID value
		idValue, ok := result[idField]
		if !ok {
			log.Printf("ID field %s not found in result", idField)
			continue
		}

		// Create the singular name for the subscription field
		singularName := api.singularize(tableName)
		subscriptionField := singularName + "Changed"

		// Create a payload that matches the expected format for subscriptions
		payload := map[string]interface{}{
			"id":           idValue,
			"mutationType": "CREATED",
			"data":         result,
		}

		// For direct compatibility with GraphQL resolvers, also include the data at the top level
		for k, v := range result {
			payload[k] = v
		}

		// Log the payload for debugging
		payloadJSON, _ := json.Marshal(payload)
		log.Printf("Publishing to topics for %s with payload: %s", subscriptionField, string(payloadJSON))

		// Publish to the specific topic for this entity
		specificTopic := fmt.Sprintf("%s:%v:changed", subscriptionField, idValue)
		api.pubsub.Publish(specificTopic, payload)

		// Also publish to the wildcard topic for all entities of this type
		wildcardTopic := fmt.Sprintf("%s:all:changed", subscriptionField)
		api.pubsub.Publish(wildcardTopic, payload)
	}
}

// handleMetrics handles requests for metrics
func (api *GraphQLAPI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := api.metrics.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// getMapKeys returns the keys of a map as a slice
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// fetchRecordFromDatabase fetches a record from the database by ID
func (api *GraphQLAPI) fetchRecordFromDatabase(tableName, idField, id string, columns []string) (interface{}, error) {
	// Query the database for this record
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s = ?", tableName, idField)
	row := api.db.QueryRow(query, id)

	// Create a map to hold the result
	result := make(map[string]interface{})
	scanArgs := make([]interface{}, len(columns))
	scanValues := make([]interface{}, len(columns))
	for i := range columns {
		scanValues[i] = new(interface{})
		scanArgs[i] = scanValues[i]
	}

	if err := row.Scan(scanArgs...); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("record not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Populate the result map
	for i, col := range columns {
		val := *(scanValues[i].(*interface{}))
		if val == nil {
			result[col] = nil
			continue
		}

		// Handle different types
		switch v := val.(type) {
		case []byte:
			// Try to convert to string
			result[col] = string(v)
		default:
			result[col] = v
		}
	}

	return result, nil
}

func main() {
	// Parse command line arguments
	port := flag.String("port", "8080", "Port to listen on")
	schemaRegistryURL := flag.String("schema-registry", "http://localhost:8081", "URL of the schema registry")
	pipelineConfigFile := flag.String("pipeline-config", "", "Path to the pipeline configuration file")
	dbPath := flag.String("db-path", "", "Path to the SQLite database file")
	flag.Parse()

	// Check for positional arguments if flags are not provided
	args := flag.Args()
	if *port == "8080" && len(args) > 0 {
		*port = args[0]
	}
	if *schemaRegistryURL == "http://localhost:8081" && len(args) > 1 {
		*schemaRegistryURL = args[1]
	}
	if *pipelineConfigFile == "" && len(args) > 2 {
		*pipelineConfigFile = args[2]
	}
	if *dbPath == "" && len(args) > 3 {
		*dbPath = args[3]
	}

	// Check if pipeline config file is provided
	if *pipelineConfigFile == "" {
		log.Fatal("Pipeline configuration file is required")
	}

	// Log the arguments for debugging
	log.Printf("Starting GraphQL API with port=%s, schema-registry=%s, pipeline-config=%s, db-path=%s",
		*port, *schemaRegistryURL, *pipelineConfigFile, *dbPath)

	// Create the GraphQL API
	api := NewGraphQLAPI(*port, *schemaRegistryURL, *pipelineConfigFile)

	// If a database path is provided, set it as an environment variable for the findSQLiteConsumer method
	if *dbPath != "" {
		os.Setenv("GRAPHQL_API_DB_PATH", *dbPath)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the API in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- api.Start()
	}()

	// Wait for signal or error
	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting GraphQL API: %v", err)
		}
	case sig := <-sigChan:
		log.Printf("Received signal: %v", sig)
		if err := api.Stop(); err != nil {
			log.Fatalf("Error stopping GraphQL API: %v", err)
		}
		log.Println("GraphQL API stopped")
	}
}

```

# cmd/schema-registry/main.go

```go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // Import SQLite driver
	"github.com/withObsrvr/Flow/pkg/schemaapi"
	"gopkg.in/yaml.v3"
)

// SchemaRegistry stores and manages GraphQL schema components
type SchemaRegistry struct {
	schemas    map[string]string
	queries    map[string]string
	mutex      sync.RWMutex
	httpServer *http.Server
}

// NewSchemaRegistry creates a new schema registry service
func NewSchemaRegistry(port string) *SchemaRegistry {
	registry := &SchemaRegistry{
		schemas: make(map[string]string),
		queries: make(map[string]string),
	}

	// Set up HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/register", registry.handleRegister)
	mux.HandleFunc("/schema", registry.handleGetSchema)
	mux.HandleFunc("/health", registry.handleHealth)

	registry.httpServer = &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	return registry
}

// Start begins the schema registry service
func (sr *SchemaRegistry) Start() error {
	log.Printf("Starting Schema Registry on %s", sr.httpServer.Addr)
	return sr.httpServer.ListenAndServe()
}

// Stop gracefully shuts down the schema registry service
func (sr *SchemaRegistry) Stop() error {
	log.Println("Shutting down Schema Registry...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return sr.httpServer.Shutdown(ctx)
}

// handleRegister processes schema registration requests
func (sr *SchemaRegistry) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var registration schemaapi.SchemaRegistration

	if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sr.mutex.Lock()
	sr.schemas[registration.PluginName] = registration.Schema
	sr.queries[registration.PluginName] = registration.Queries
	sr.mutex.Unlock()

	log.Printf("Registered schema for plugin: %s", registration.PluginName)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleGetSchema returns the complete GraphQL schema
func (sr *SchemaRegistry) handleGetSchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	// Compose the full schema
	var schemaBuilder strings.Builder
	var queryBuilder strings.Builder

	for _, schema := range sr.schemas {
		schemaBuilder.WriteString(schema)
		schemaBuilder.WriteString("\n")
	}

	for _, query := range sr.queries {
		queryBuilder.WriteString(query)
		queryBuilder.WriteString("\n")
	}

	fullSchema := fmt.Sprintf(`
%s

type Query {
%s
}
`, schemaBuilder.String(), queryBuilder.String())

	w.Header().Set("Content-Type", "application/graphql")
	w.Write([]byte(fullSchema))
}

// handleHealth provides a health check endpoint
func (sr *SchemaRegistry) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// GenerateDynamicSchemas generates GraphQL schemas from database tables
func (sr *SchemaRegistry) GenerateDynamicSchemas(dbPath string) error {
	// If no database path is provided, create a minimal schema
	if dbPath == "" {
		log.Printf("No database path provided, creating minimal schema")

		// Register a minimal type schema
		sr.mutex.Lock()
		sr.schemas["minimal"] = `
type Status {
  status: String!
  message: String!
  timestamp: String!
}
`
		// Register a minimal query
		sr.queries["minimal"] = `
status: Status!
`
		sr.mutex.Unlock()

		return nil
	}

	// Check if the database file exists
	_, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		log.Printf("Database file %s does not exist yet, will check again later", dbPath)

		// Start a goroutine to periodically check for the database
		go sr.watchForDatabase(dbPath)
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to check database file: %w", err)
	}

	// Connect to the SQLite database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Get a list of all tables
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	// Process each table
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return fmt.Errorf("failed to scan table name: %w", err)
		}

		// Skip internal SQLite tables
		if strings.HasPrefix(tableName, "sqlite_") {
			continue
		}

		log.Printf("Generating schema for table: %s", tableName)

		// Get table schema
		schemaRows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			return fmt.Errorf("failed to get schema for table %s: %w", tableName, err)
		}

		// Generate GraphQL type
		var typeBuilder strings.Builder
		typeBuilder.WriteString(fmt.Sprintf("type %s {\n", pascalCase(tableName)))

		// Track fields for queries
		var fields []string
		var primaryKey string

		// Process each column
		for schemaRows.Next() {
			var cid int
			var name, typeName string
			var notNull, pk int
			var dfltValue interface{}

			if err := schemaRows.Scan(&cid, &name, &typeName, &notNull, &dfltValue, &pk); err != nil {
				schemaRows.Close()
				return fmt.Errorf("failed to scan column info: %w", err)
			}

			// Convert SQLite type to GraphQL type
			gqlType := "String"
			switch strings.ToUpper(typeName) {
			case "INTEGER", "NUMERIC", "REAL":
				gqlType = "Int"
			case "BOOLEAN":
				gqlType = "Boolean"
			}

			// Add non-null if required
			if notNull == 1 {
				gqlType += "!"
			}

			// Add field to type definition
			typeBuilder.WriteString(fmt.Sprintf("  %s: %s\n", camelCase(name), gqlType))

			// Track field for queries
			fields = append(fields, name)

			// Track primary key
			if pk == 1 {
				primaryKey = name
			}
		}
		schemaRows.Close()

		typeBuilder.WriteString("}\n\n")

		// Register the type schema
		sr.mutex.Lock()
		sr.schemas[tableName] = typeBuilder.String()
		sr.mutex.Unlock()

		// Generate queries if we have a primary key
		if primaryKey != "" {
			var queryBuilder strings.Builder

			// Single item query
			queryBuilder.WriteString(fmt.Sprintf("%s(%s: %s!): %s\n",
				camelCase(tableName),
				camelCase(primaryKey),
				sqlTypeToGraphQL(db, tableName, primaryKey),
				pascalCase(tableName)))

			// List query
			queryBuilder.WriteString(fmt.Sprintf("%s(first: Int, after: String): [%s!]!\n",
				pluralize(camelCase(tableName)),
				pascalCase(tableName)))

			sr.mutex.Lock()
			sr.queries[tableName] = queryBuilder.String()
			sr.mutex.Unlock()
		}
	}

	return nil
}

// watchForDatabase periodically checks for the database file and generates schemas when it exists
func (sr *SchemaRegistry) watchForDatabase(dbPath string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Set a timeout of 30 seconds (6 attempts at 5-second intervals)
	timeout := time.After(30 * time.Second)
	attempts := 0

	for {
		select {
		case <-ticker.C:
			attempts++

			// Check if the database file exists now
			_, err := os.Stat(dbPath)
			if os.IsNotExist(err) {
				log.Printf("Database file %s still does not exist, waiting... (attempt %d/6)", dbPath, attempts)
				continue
			} else if err != nil {
				log.Printf("Error checking database file: %v", err)
				continue
			}

			// Database exists, try to generate schemas
			log.Printf("Database file %s now exists, generating schemas", dbPath)
			if err := sr.GenerateDynamicSchemas(dbPath); err != nil {
				log.Printf("Error generating schemas: %v", err)
				continue
			}

			// Success, stop watching
			log.Printf("Successfully generated schemas from database %s", dbPath)
			return

		case <-timeout:
			// Timeout reached, create a minimal schema and stop watching
			log.Printf("Timeout reached waiting for database file %s, creating minimal schema", dbPath)

			// Register a minimal type schema
			sr.mutex.Lock()
			sr.schemas["minimal"] = `
type Status {
  status: String!
  message: String!
  timestamp: String!
}
`
			// Register a minimal query
			sr.queries["minimal"] = `
status: Status!
`
			sr.mutex.Unlock()

			return
		}
	}
}

// Helper functions for schema generation
func pascalCase(s string) string {
	// Convert snake_case to PascalCase
	parts := strings.Split(s, "_")
	for i := range parts {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

func camelCase(s string) string {
	// Convert snake_case to camelCase
	pascal := pascalCase(s)
	if len(pascal) > 0 {
		return strings.ToLower(pascal[:1]) + pascal[1:]
	}
	return ""
}

func pluralize(s string) string {
	// Simple pluralization
	if strings.HasSuffix(s, "y") {
		return s[:len(s)-1] + "ies"
	}
	return s + "s"
}

func sqlTypeToGraphQL(db *sql.DB, table, column string) string {
	// Get column type
	var typeName string
	row := db.QueryRow(fmt.Sprintf("SELECT type FROM pragma_table_info('%s') WHERE name='%s'", table, column))
	if err := row.Scan(&typeName); err != nil {
		return "String"
	}

	// Convert SQLite type to GraphQL type
	switch strings.ToUpper(typeName) {
	case "INTEGER", "NUMERIC", "REAL":
		return "Int"
	case "BOOLEAN":
		return "Boolean"
	default:
		return "String"
	}
}

// Add this new method to extract the database path from pipeline config
func findDatabasePathInConfig(pipelineConfigFile string) (string, error) {
	// Read the pipeline configuration file
	data, err := os.ReadFile(pipelineConfigFile)
	if err != nil {
		return "", fmt.Errorf("failed to read pipeline config file: %w", err)
	}

	// Define a struct to parse the YAML configuration
	type PipelineConfig struct {
		Pipelines map[string]struct {
			Source struct {
				Type   string                 `yaml:"type"`
				Config map[string]interface{} `yaml:"config"`
			} `yaml:"source"`
			Processors []struct {
				Type   string                 `yaml:"type"`
				Config map[string]interface{} `yaml:"config"`
			} `yaml:"processors"`
			Consumers []struct {
				Type   string                 `yaml:"type"`
				Config map[string]interface{} `yaml:"config"`
			} `yaml:"consumers"`
		} `yaml:"pipelines"`
	}

	// Parse the YAML configuration
	var config PipelineConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("failed to parse pipeline config: %w", err)
	}

	// Look for a SQLite consumer in any pipeline
	var hasSqliteConsumer bool
	for pipelineName, pipeline := range config.Pipelines {
		for _, consumer := range pipeline.Consumers {
			// Check if this is a SQLite consumer
			if strings.Contains(strings.ToLower(consumer.Type), "sqlite") {
				hasSqliteConsumer = true
				log.Printf("Found SQLite consumer in pipeline %s", pipelineName)

				// Get the database path from the consumer config
				if dbPath, ok := consumer.Config["db_path"].(string); ok {
					log.Printf("Using database path from config: %s", dbPath)
					return dbPath, nil
				}
			}
		}
	}

	// If no SQLite consumer was found at all, return a special error
	if !hasSqliteConsumer {
		return "", fmt.Errorf("no_sqlite_consumer: Pipeline does not contain any SQLite consumers")
	}

	// Default to flow_data.db if SQLite consumer found but no path specified
	return "flow_data.db", nil
}

func main() {
	// Parse command line flags
	port := "8081"
	dbPath := ""
	pipelineConfigFile := ""

	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	if len(os.Args) > 2 {
		// The second argument can be either a direct DB path or a pipeline config file
		arg := os.Args[2]

		// Check if the argument is a YAML file (likely a pipeline config)
		if strings.HasSuffix(arg, ".yaml") || strings.HasSuffix(arg, ".yml") {
			pipelineConfigFile = arg
			log.Printf("Using pipeline config file: %s", pipelineConfigFile)

			// Extract the database path from the pipeline config
			extractedPath, err := findDatabasePathInConfig(pipelineConfigFile)
			if err != nil {
				if strings.HasPrefix(err.Error(), "no_sqlite_consumer:") {
					log.Printf("No SQLite consumers found in pipeline config. Schema Registry will run with minimal schema.")
					dbPath = ""
				} else {
					log.Printf("Warning: Failed to extract database path from config: %v", err)
					log.Printf("Using default database path: flow_data.db")
					dbPath = "flow_data.db"
				}
			} else {
				dbPath = extractedPath
			}
		} else {
			// Assume it's a direct database path
			dbPath = arg
		}
	}

	// Create and start the schema registry
	registry := NewSchemaRegistry(port)

	// Generate dynamic schemas if database path is provided
	if dbPath != "" {
		log.Printf("Generating dynamic schemas from database: %s", dbPath)
		if err := registry.GenerateDynamicSchemas(dbPath); err != nil {
			log.Printf("Warning: Failed to generate dynamic schemas: %v", err)
		}
	}

	// Handle graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := registry.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting schema registry: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-stop

	// Gracefully shutdown
	if err := registry.Stop(); err != nil {
		log.Fatalf("Error shutting down schema registry: %v", err)
	}

	log.Println("Schema Registry stopped")
}

```

# DISTRIBUTION.md

```md
# Flow Distribution Strategy

This document outlines the distribution strategy for Flow and its plugins, ensuring compatibility and ease of use across different environments.

## Distribution Methods

Flow and its plugins are distributed through multiple channels:

### 1. GitHub Releases

Pre-built binaries are available on GitHub Releases, containing:
- Flow executables (`flow`, `graphql-api`, `schema-registry`)
- Plugin shared objects (`.so` files)
- Documentation and checksums

These releases are built using Nix to ensure reproducibility and consistent toolchain versions.

### 2. Docker Images

Docker images are available on Docker Hub with all components pre-installed:
\`\`\`
docker pull withobsrvr/flow:latest
\`\`\`

The Docker images contain the Flow executables and all plugins in the appropriate locations.

### 3. Nix Flakes

For users of Nix, we provide flakes for building Flow and its plugins:

\`\`\`bash
# Install the complete Flow distribution
nix profile install github:withObsrvr/flow

# Build from source
nix build github:withObsrvr/flow
\`\`\`

For a complete distribution including all plugins, use the meta-flake:

\`\`\`bash
nix build github:withObsrvr/flow#meta
\`\`\`

## Go Plugin Compatibility

Go plugins require exact compatibility between the host application and the plugins. To ensure this:

1. All components are built with the same Go version (currently 1.23)
2. All binaries in a release are built by the same workflow
3. The Nix builds ensure consistent toolchain versions

**Important:** Always use plugins with the Flow version they were built for. Mixing plugins from different releases may cause runtime errors or crashes.

## Development and Testing

For development, we recommend using the meta-flake's development shell:

\`\`\`bash
nix develop github:withObsrvr/flow#meta
\`\`\`

This provides a complete development environment with all the necessary dependencies.

## Release Process

1. New tags (e.g., `v0.1.0`) trigger the GitHub Actions workflow
2. The workflow builds Flow and all plugins with the same toolchain
3. A release is created with all binaries and documentation
4. A Docker image is built and pushed to Docker Hub

## Adding New Plugins

To add a new plugin to the distribution:

1. Ensure the plugin has a working Nix build
2. Add the plugin to the GitHub workflow in `.github/workflows/build-and-release.yml`
3. Add the plugin to the meta-flake in `meta-flake.nix`
4. Update documentation to mention the new plugin

## Versioning

We follow semantic versioning:
- Major version: Breaking changes to the Flow API
- Minor version: New features, non-breaking changes
- Patch version: Bug fixes and minor improvements

Plugin version numbers should align with the Flow version they are compatible with. 
```

# docker-compose.yml

```yml
services:
  # Schema Registry Service
  schema-registry:
    build:
      context: .
      dockerfile: Dockerfile
    image: obsrvr/flow:latest
    entrypoint: ["/app/bin/schema-registry"]
    command: ["8081", "${DB_PATH:-/app/data/flow_data.db}"]
    volumes:
      - ./data:/app/data
      - ${PIPELINE_DIR:-./examples/pipelines}:/app/pipelines
      - ./healthcheck.sh:/app/healthcheck.sh
    ports:
      - "8081:8081"
    healthcheck:
      test: ["CMD-SHELL", "/app/healthcheck.sh"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 5s
    restart: unless-stopped

  # Flow Core Service
  flow-core:
    build:
      context: .
      dockerfile: Dockerfile
    image: obsrvr/flow:latest
    depends_on:
      schema-registry:
        condition: service_healthy
    entrypoint: ["/app/bin/flow"]
    command: ["--pipeline=${PIPELINE_FILE:-/app/pipelines/pipeline_default.yaml}", "--instance-id=${INSTANCE_ID:-docker}", "--tenant-id=${TENANT_ID:-docker}", "--api-key=${API_KEY:-docker-key}", "--plugins=/app/plugins"]
    volumes:
      - ${PIPELINE_DIR:-./examples/pipelines}:/app/pipelines
      - ./data:/app/data
      - ./plugins:/app/plugins
    environment:
      - FLOW_DATA_DIR=/app/data
      - PIPELINE_FILE=${PIPELINE_FILE:-/app/pipelines/pipeline_default.yaml}
      - INSTANCE_ID=${INSTANCE_ID:-docker}
      - TENANT_ID=${TENANT_ID:-docker}
      - API_KEY=${API_KEY:-docker-key}
      - DB_PATH=${DB_PATH:-/app/data/flow_data.db}
    restart: unless-stopped

  # GraphQL API Service
  graphql-api:
    build:
      context: .
      dockerfile: Dockerfile
    image: obsrvr/flow:latest
    depends_on:
      schema-registry:
        condition: service_healthy
    entrypoint: ["/app/bin/graphql-api"]
    command: ["--port=8080", "--schema-registry=http://schema-registry:8081", "--pipeline-config=${PIPELINE_FILE:-/app/pipelines/pipeline_default.yaml}", "--db-path=${DB_PATH:-/app/data/flow_data.db}"]
    volumes:
      - ${PIPELINE_DIR:-./examples/pipelines}:/app/pipelines
      - ./data:/app/data
    ports:
      - "8080:8080"
    environment:
      - PIPELINE_FILE=${PIPELINE_FILE:-/app/pipelines/pipeline_default.yaml}
      - DB_PATH=${DB_PATH:-/app/data/flow_data.db}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 5s
    restart: unless-stopped 
```

# DOCKER.md

```md
# Running Flow with Docker

This document explains how to run the Flow application using Docker and Docker Compose.

## Prerequisites

- Docker
- Docker Compose

## Quick Start

To quickly start all services with default settings:

\`\`\`bash
./run_docker.sh
\`\`\`

This will start the following services:
- Schema Registry on port 8081
- Flow Core service
- GraphQL API on port 8080

## Configuration Options

The `run_docker.sh` script accepts several options to customize the deployment:

\`\`\`bash
./run_docker.sh --help
\`\`\`

Options:
- `--pipeline PATH`: Path to pipeline configuration file (default: examples/pipelines/pipeline_default.yaml)
- `--instance-id ID`: Instance ID (default: docker)
- `--tenant-id ID`: Tenant ID (default: docker)
- `--api-key KEY`: API key (default: docker-key)
- `--db-path PATH`: Database path (default: flow_data.db)
- `--build`: Build Docker images before starting containers
- `--detach, -d`: Run containers in the background
- `--help, -h`: Show help message

## Examples

### Build and run with a custom pipeline configuration:

\`\`\`bash
./run_docker.sh --pipeline examples/pipelines/pipeline_accounts.yaml --build
\`\`\`

### Run in detached mode:

\`\`\`bash
./run_docker.sh --detach
\`\`\`

### Use a custom database path:

\`\`\`bash
./run_docker.sh --db-path my_custom_database.db
\`\`\`

## Using Environment Variables

You can also set configuration using environment variables:

\`\`\`bash
PIPELINE_FILE="/app/pipelines/my_pipeline.yaml" \
PIPELINE_DIR="./my_pipelines" \
INSTANCE_ID="my-instance" \
TENANT_ID="my-tenant" \
API_KEY="my-key" \
DB_PATH="/app/data/my_database.db" \
./run_docker.sh
\`\`\`

## Running Docker Compose Directly

If you prefer to use Docker Compose directly:

\`\`\`bash
# Set environment variables
export PIPELINE_FILE="/app/pipelines/my_pipeline.yaml"
export PIPELINE_DIR="./my_pipelines"
export INSTANCE_ID="my-instance"
export TENANT_ID="my-tenant"
export API_KEY="my-key"
export DB_PATH="/app/data/my_database.db"

# Run Docker Compose
docker compose up
\`\`\`

## Accessing the Services

- GraphQL API: http://localhost:8080/graphql
- Schema Registry: http://localhost:8081/schema

## Stopping the Services

If you started the services in the foreground, press Ctrl+C to stop them.

If you started the services in detached mode, run:

\`\`\`bash
docker compose down
\`\`\`

## Data Persistence

Data is stored in the `./data` directory, which is mounted as a volume in the containers. This data persists even after the containers are stopped or removed.

## Custom Pipeline Files

Pipeline files are mounted from the host into the container. By default, the `examples/pipelines` directory is mounted to `/app/pipelines` in the container.

If you specify a custom pipeline file with `--pipeline`, the directory containing that file will be mounted to `/app/pipelines` in the container.

## Custom Database Path

If you specify a relative database path with `--db-path`, it will be created in the `/app/data` directory inside the container.

If you specify an absolute path, it will be used as-is.

## Building the Docker Image Manually

If you want to build the Docker image manually:

\`\`\`bash
docker build -t obsrvr/flow:latest .
\`\`\`

## Troubleshooting

### Checking Logs

To check the logs of a specific service:

\`\`\`bash
docker compose logs schema-registry
docker compose logs flow-core
docker compose logs graphql-api
\`\`\`

### Accessing a Container Shell

To access a shell in a running container:

\`\`\`bash
docker compose exec flow-core sh
docker compose exec schema-registry sh
docker compose exec graphql-api sh
\`\`\`

### Restarting Services

To restart a specific service:

\`\`\`bash
docker compose restart flow-core
docker compose restart schema-registry
docker compose restart graphql-api
\`\`\` 
```

# Dockerfile

```
FROM alpine:3.19

# Install dependencies
RUN apk add --no-cache ca-certificates libc6-compat

# Create app directories
RUN mkdir -p /app/bin /app/plugins /app/config

# Copy binaries
COPY dist/bin/* /app/bin/
COPY dist/plugins/* /app/plugins/

# Copy documentation
COPY dist/README.md /app/
COPY dist/SHA256SUMS /app/

# Set environment variables
ENV PATH="/app/bin:${PATH}"
ENV FLOW_PLUGINS_DIR="/app/plugins"
ENV FLOW_CONFIG_DIR="/app/config"

# Set working directory
WORKDIR /app

# Set the entrypoint
ENTRYPOINT ["/app/bin/flow"]
CMD ["--help"] 
```

# examples/pipelines/kale_metrics.yaml

```yaml
pipelines:
  KaleMetricsPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-mainnet-data/landing/"
        network: "mainnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 56099668
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/contract-invocations"
        config:
          network_passphrase: "Public Global Stellar Network ; September 2015"
      - type: "flow/processor/kale-metrics"
        config:
          contract_id: "CDL74RF5BLYR2YBLCCI7F5FB6TPSCLKEJUBSD2RSVWZ4YHF3VMFAIGWA"
    consumers:
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5555" 

```

# examples/pipelines/pipeline_accounts.yaml

```yaml
pipelines:
  AccountsPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-testnet-data/landing/"
        network: "testnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 2
        end_ledger: 200
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/accounts"
        config:
          network_passphrase: "Test SDF Network ; September 2015"
    consumers:
      - type: "flow/consumer/sqlite"
        config:
          db_path: "flow_data_accounts_6.db"

```

# examples/pipelines/pipeline_contract_data.yaml

```yaml
pipelines:
  ContractDataPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-testnet-data/landing/"
        network: "testnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 2
        end_ledger: 7000
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/contract-data"
        config:
          network_passphrase: "Test SDF Network ; September 2015"
    consumers:
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5555"
```

# examples/pipelines/pipeline_contract_example.yaml

```yaml
pipelines:
  ContractEventsPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-mainnet-data/landing/"
        network: "mainnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 56272029
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/contract-events"
        config:
          network_passphrase: "Public Global Stellar Network ; September 2015"
    consumers:
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5555"

```

# examples/pipelines/pipeline_contract_invocations.yaml

```yaml
pipelines:
  KaleMetricsPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-mainnet-data/landing/"
        network: "mainnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 55807000
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/contract-invocations"
        config:
          network_passphrase: "Public Global Stellar Network ; September 2015"
    consumers:
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5555"

```

# examples/pipelines/pipeline_example.yaml

```yaml
pipelines:
  LatestLedgerPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-testnet-data/landing/ledgers"
        network: "testnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 3
        end_ledger: 3000
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/latest-ledger"
        config:
          network_passphrase: "Test SDF Network ; September 2015"
    consumers:
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5555"
      - type: "flow/consumer/sqlite"
        config:
          db_path: "flow_data_3.db"


```

# examples/pipelines/pipeline_kale_metrics.yaml

```yaml
pipelines:
  KaleMetricsPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-mainnet-data/landing/"
        network: "mainnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 56137394
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/contract-invocations"
        config:
          network_passphrase: "Public Global Stellar Network ; September 2015"
      - type: "flow/processor/kale-metrics"
        config:
          contract_id: "CDL74RF5BLYR2YBLCCI7F5FB6TPSCLKEJUBSD2RSVWZ4YHF3VMFAIGWA"
    consumers:
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5555"

```

# examples/pipelines/pipeline_latest_ledger.yaml

```yaml
pipelines:
  SoroswapPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-mainnet-data/landing/"
        network: "mainnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 56146570
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/latest-ledger"
        config:
          network_passphrase: "Public Global Stellar Network ; September 2015"
    consumers:
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5556"

```

# examples/pipelines/pipeline_soroswap_docker.yaml

```yaml
pipelines:
  SoroswapPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-mainnet-data/landing/"
        network: "mainnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 55808036
        end_ledger: 55808038
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/contract-events"
        config:
          network_passphrase: "Public Global Stellar Network ; September 2015"
      - type: "flow/processor/soroswap"
        config: {}
    consumers:
      - type: "flow/consumer/sqlite"
        config:
          db_path: "flow_soroswap_2.db" 
```

# examples/pipelines/pipeline_soroswap_router.yaml

```yaml
pipelines:
  SoroswapRouterPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-mainnet-data/landing/"
        network: "mainnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 56075000
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/contract-events"
        config:
          network_passphrase: "Public Global Stellar Network ; September 2015"
      - type: "flow/processor/soroswap-router"
        config: {}
    consumers:
      - type: "flow/consumer/soroswap-router-sqlite"
        config:
          db_path: "flow_data_soroswap_router_2.db"
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5555" 
```

# examples/pipelines/pipeline_soroswap.yaml

```yaml
pipelines:
  SoroswapPipeline:
    source:
      type: "BufferedStorageSourceAdapter"
      config:
        bucket_name: "obsrvr-stellar-ledger-data-mainnet-data/landing/"
        network: "mainnet"
        num_workers: 10
        retry_limit: 3
        retry_wait: 5
        start_ledger: 56075000
        ledgers_per_file: 1
        files_per_partition: 64000
    processors:
      - type: "flow/processor/contract-events"
        config:
          network_passphrase: "Public Global Stellar Network ; September 2015"
      - type: "flow/processor/soroswap"
        config: {}
    consumers:
      - type: "flow/consumer/soroswap-sqlite"
        config:
          db_path: "flow_data_soroswap_10.db"
      - type: "SaveToZeroMQ"
        config:
          address: "tcp://127.0.0.1:5555"

```

# examples/pipelines/pipeline_wasm_sample.yaml

```yaml
pipeline:
  name: wasm-sample-pipeline
  description: Pipeline demonstrating WASM plugin usage

  # Source for events - using a simple RPC source
  source:
    name: flow-blockchain
    type: rpc
    config:
      access_node: access.mainnet.nodes.onflow.org:9000
      collection_guarantee_included: true
      transaction_result: true
      block_sealed: true
      heartbeat:
        interval_seconds: 30

  # Processors 
  processors:
    # Basic RPC processor
    - name: rpc-processor
      type: processor
      plugin: ./plugins/flow-processor-rpc.so
    
    # WASM sample consumer plugin
    - name: wasm-sample
      type: consumer
      plugin: ./examples/wasm-plugin-sample/wasm-sample.wasm
      config:
        example_key: "example_value"
        demo_setting: true
        numeric_value: 42

    # SQLite consumer for persistence
    - name: sqlite
      type: consumer
      plugin: ./plugins/flow-consumer-sqlite.so
      config:
        database_path: "./data/flow.db"
        schema_path: "./plugins/schema.sql"

graphql:
  enabled: true
  port: 8080

schema_registry:
  enabled: true
  port: 8081 
```

# examples/wasm-plugin-sample/go.mod

```mod
module github.com/withObsrvr/flow/examples/wasm-plugin-sample

go 1.20

require github.com/withObsrvr/pluginapi v0.0.0

replace github.com/withObsrvr/pluginapi => ../../pluginapi 
```

# examples/wasm-plugin-sample/main.go

```go
package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"unsafe"
)

// Global variables to store plugin information
var (
	pluginName    = "flow/consumer/wasm-sample"
	pluginVersion = "1.0.0"
	pluginType    = 2 // ConsumerPlugin
	config        map[string]interface{}
	initialized   bool
)

// Memory management functions
//
//export alloc
func alloc(size uint64) uint64 {
	buf := make([]byte, size)
	return uint64(uintptr(unsafe.Pointer(&buf[0])))
}

//export free
func free(ptr uint64, size uint64) {
	// In Go with WASM, memory is handled by the Go runtime
	// This is a no-op function for compatibility
}

// Plugin interface functions

//export name
func name() (uint64, uint64) {
	buf := []byte(pluginName)
	ptr := &buf[0]
	unsafePtr := uintptr(unsafe.Pointer(ptr))
	return uint64(unsafePtr), uint64(len(buf))
}

//export version
func version() (uint64, uint64) {
	buf := []byte(pluginVersion)
	ptr := &buf[0]
	unsafePtr := uintptr(unsafe.Pointer(ptr))
	return uint64(unsafePtr), uint64(len(buf))
}

//export type
func type_() uint64 {
	return uint64(pluginType)
}

//export initialize
func initialize(configPtr uint64, configLen uint64) uint64 {
	if initialized {
		return 0 // Success
	}

	// Read the config from memory
	configBytes := readMemory(configPtr, configLen)

	// Parse the config
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Printf("Error parsing config: %v\n", err)
		return 1 // Error
	}

	// Print out the config for debugging
	fmt.Printf("Initialized WASM plugin %s with config: %v\n", pluginName, config)

	initialized = true
	return 0 // Success
}

//export process
func process(msgPtr uint64, msgLen uint64) uint64 {
	if !initialized {
		fmt.Println("Plugin not initialized")
		return 1 // Error
	}

	// Read the message from memory
	msgBytes := readMemory(msgPtr, msgLen)

	// Parse the message
	var message map[string]interface{}
	err := json.Unmarshal(msgBytes, &message)
	if err != nil {
		fmt.Printf("Error parsing message: %v\n", err)
		return 1 // Error
	}

	// Print the message for demonstration purposes
	fmt.Printf("WASM plugin %s received message: %v\n", pluginName, message)

	return 0 // Success
}

//export close
func close() uint64 {
	if !initialized {
		return 0 // Success
	}

	fmt.Printf("Closing WASM plugin %s\n", pluginName)

	initialized = false
	return 0 // Success
}

// Helper function to read memory
func readMemory(ptr uint64, size uint64) []byte {
	// Convert the pointer to a slice
	var buf []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	sh.Data = uintptr(ptr)
	sh.Len = int(size)
	sh.Cap = int(size)

	// Make a copy of the data to avoid issues with GC
	result := make([]byte, size)
	copy(result, buf)

	return result
}

func main() {
	// This function is required by TinyGo, but is not used when the module is loaded by Wazero
	fmt.Println("WASM plugin loaded")
}

```

# examples/wasm-plugin-sample/Makefile

```
.PHONY: build clean

# Output WASM file
WASM_FILE = wasm-sample.wasm

# Default target
all: build

# Build the WASM plugin
build:
	@echo "Building WASM plugin..."
	tinygo build -o $(WASM_FILE) -target=wasi ./main.go
	@echo "Build complete: $(WASM_FILE)"

# Copy the built WASM file to the Flow plugins directory
install: build
	@echo "Installing WASM plugin to Flow plugins directory..."
	mkdir -p ../../plugins
	cp $(WASM_FILE) ../../plugins/
	@echo "Installation complete"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(WASM_FILE)
	@echo "Clean complete"

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Default target, builds the WASM plugin"
	@echo "  build    - Build the WASM plugin"
	@echo "  install  - Build and install the WASM plugin to the Flow plugins directory"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Display this help message" 
```

# examples/wasm-plugin-sample/README.md

```md
# WASM Plugin Sample for Flow

This is a sample WebAssembly (WASM) plugin for the Flow project. It demonstrates how to create a simple consumer plugin that can be loaded using the WASM runtime.

## Prerequisites

- TinyGo (required for building WASM plugins)
- Go 1.20 or higher

## Building the Plugin

To build the plugin, use TinyGo with the WASI target:

\`\`\`bash
tinygo build -o wasm-sample.wasm -target=wasi ./main.go
\`\`\`

Alternatively, if you're using the Nix development environment provided with Flow, you can use the `buildWasmPlugin` function in the flake.nix file.

## Plugin Structure

This sample plugin implements the basic interface required for Flow plugins in WebAssembly:

- Memory management functions: `alloc` and `free`
- Plugin interface functions:
  - `name`: Returns the plugin name
  - `version`: Returns the plugin version
  - `type_`: Returns the plugin type (2 for ConsumerPlugin)
  - `initialize`: Initializes the plugin with configuration
  - `process`: Processes incoming messages
  - `close`: Cleans up resources when the plugin is closed

## Usage in Flow

To use this plugin with Flow, add it to your pipeline configuration:

\`\`\`yaml
pipeline:
  processors:
    - name: wasm-sample
      type: consumer
      plugin: ./examples/wasm-plugin-sample/wasm-sample.wasm
      config:
        # Custom configuration for your plugin
        key: value
\`\`\`

## Understanding the WASM Plugin Interface

The WASM plugin interface uses exported functions and memory management to communicate between the host (Flow) and the plugin:

1. The host initializes the plugin by calling the `initialize` function with a JSON configuration.
2. Messages are passed to the plugin via the `process` function, which receives memory pointers.
3. The plugin reads data from memory, processes it, and returns a success/error code.

This approach allows for safe cross-language plugin development while maintaining performance. 
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
  description = "Obsrvr Flow Data Indexer";

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
            pname = "flow";
            version = "0.1.0";
            src = ./.;
            # Use vendoring with the correct hash
            vendorHash = "sha256-07UGAsWkSltp4gIJbFQWzVTpPS8yxiR9t2xcX44S6tk=";
            # Make sure we're using the vendor directory
            proxyVendor = true;
            # Skip go mod verification/download by using -mod=vendor 
            buildFlags = [ "-mod=vendor" ];
            # Set environment variables for go builds
            env = {
              GO111MODULE = "on";
            };
            # Ensure vendor directory is complete and correct before building
            preBuild = ''
              echo "Using vendor directory for building..."
            '';
            # Specify the main packages to build
            subPackages = [ 
              "cmd/flow" 
              "cmd/graphql-api"
              "cmd/schema-registry"
            ];
          };
        };

        devShell = pkgs.mkShell {
          buildInputs = [ 
            pkgs.go_1_23
          ];
          # Set a helpful shell configuration
          shellHook = ''
            echo "Flow development environment"
            export GO111MODULE="on"
          '';
        };
      }
    );
}

```

# go.mod

```mod
module github.com/withObsrvr/Flow

go 1.23.4

require (
	github.com/gorilla/websocket v1.5.3
	github.com/graphql-go/graphql v0.8.1
	github.com/graphql-go/handler v0.2.4
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/prometheus/client_golang v1.21.1
	github.com/stretchr/testify v1.10.0
	github.com/tetratelabs/wazero v1.6.0
	github.com/withObsrvr/pluginapi v0.0.0-20250303141549-e645e333195c
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.63.0 // indirect
	github.com/prometheus/procfs v0.16.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/sys v0.31.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
)

```

# healthcheck.sh

```sh
#!/bin/sh
# Simple health check script for schema-registry
# This script will return success (exit 0) if the service is running,
# even if the database file doesn't exist yet

# Try to access the health endpoint
curl -s -f http://localhost:8081/health > /dev/null 2>&1

# If curl succeeded, return success
if [ $? -eq 0 ]; then
  exit 0
fi

# If curl failed, check if the service is running by checking the port
nc -z localhost 8081 > /dev/null 2>&1

# Return the result of the netcat check
exit $? 
```

# internal/metrics/metrics.go

```go
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Pipeline metrics
	MessagesProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_messages_processed_total",
			Help: "The total number of processed messages",
		},
		[]string{"tenant_id", "instance_id", "pipeline", "processor"},
	)

	ProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "flow_message_processing_duration_seconds",
			Help:    "Time spent processing messages",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant_id", "instance_id", "pipeline", "processor"},
	)

	ProcessingErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_processing_errors_total",
			Help: "The total number of processing errors",
		},
		[]string{"tenant_id", "instance_id", "pipeline", "processor", "error_type"},
	)

	// Consumer metrics
	MessagesConsumed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_messages_consumed_total",
			Help: "The total number of consumed messages",
		},
		[]string{"tenant_id", "instance_id", "pipeline", "consumer"},
	)

	// Ledger specific metrics
	LedgersProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_ledgers_processed_total",
			Help: "The total number of ledgers processed",
		},
		[]string{"tenant_id", "instance_id", "pipeline", "source"},
	)

	LedgerProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "flow_ledger_processing_duration_seconds",
			Help:    "Time spent processing ledgers",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant_id", "instance_id", "pipeline", "source"},
	)
)

```

# internal/pluginmanager/loader.go

```go
package pluginmanager

import (
	"fmt"
	"path/filepath"
	"plugin"

	"github.com/withObsrvr/pluginapi"
)

// PluginLoader is an interface for loading plugins from files
type PluginLoader interface {
	// CanLoad returns true if this loader can load the given file
	CanLoad(path string) bool

	// LoadPlugin loads a plugin from the given path
	LoadPlugin(path string) (pluginapi.Plugin, error)
}

// NativePluginLoader loads native Go plugins (.so files)
type NativePluginLoader struct{}

// CanLoad returns true if the file has a .so extension
func (l *NativePluginLoader) CanLoad(path string) bool {
	return filepath.Ext(path) == ".so"
}

// LoadPlugin loads a native Go plugin from the given path
func (l *NativePluginLoader) LoadPlugin(path string) (pluginapi.Plugin, error) {
	// Use the Go plugin package to load the .so file
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin %s: %w", path, err)
	}

	// Look up the New symbol
	newSymbol, err := p.Lookup("New")
	if err != nil {
		return nil, fmt.Errorf("plugin %s does not export New: %w", path, err)
	}

	// Check that the New symbol is a function that returns a pluginapi.Plugin
	newFunc, ok := newSymbol.(func() pluginapi.Plugin)
	if !ok {
		return nil, fmt.Errorf("plugin %s New symbol has wrong type", path)
	}

	// Create an instance of the plugin
	return newFunc(), nil
}

// getRegisteredLoaders returns all registered plugin loaders
func getRegisteredLoaders() []PluginLoader {
	return []PluginLoader{
		&NativePluginLoader{},
		&WASMPluginLoader{},
	}
}

```

# internal/pluginmanager/loader.go.bak

```bak
package pluginmanager

import (
	"fmt"
	"path/filepath"
	"plugin"

	"github.com/withObsrvr/pluginapi"
)

// PluginLoader is an interface for loading plugins from files
type PluginLoader interface {
	// CanLoad returns true if this loader can load the given file
	CanLoad(path string) bool

	// LoadPlugin loads a plugin from the given path
	LoadPlugin(path string) (pluginapi.Plugin, error)
}

// NativePluginLoader loads native Go plugins (.so files)
type NativePluginLoader struct{}

// CanLoad returns true if the file has a .so extension
func (l *NativePluginLoader) CanLoad(path string) bool {
	return filepath.Ext(path) == ".so"
}

// LoadPlugin loads a native Go plugin from the given path
func (l *NativePluginLoader) LoadPlugin(path string) (pluginapi.Plugin, error) {
	// Use the Go plugin package to load the .so file
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin %s: %w", path, err)
	}

	// Look up the New symbol
	newSymbol, err := p.Lookup("New")
	if err != nil {
		return nil, fmt.Errorf("plugin %s does not export New: %w", path, err)
	}

	// Check that the New symbol is a function that returns a pluginapi.Plugin
	newFunc, ok := newSymbol.(func() pluginapi.Plugin)
	if !ok {
		return nil, fmt.Errorf("plugin %s New symbol has wrong type", path)
	}

	// Create an instance of the plugin
	return newFunc(), nil
}


// LoadPlugin loads a WebAssembly plugin from the given path
func (l *WASMPluginLoader) LoadPlugin(path string) (pluginapi.Plugin, error) {
	// Use the Go plugin package to load the .wasm file
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin %s: %w", path, err)
	}

	// Look up the New symbol
	newSymbol, err := p.Lookup("New")
	if err != nil {
		return nil, fmt.Errorf("plugin %s does not export New: %w", path, err)
	}

	// Check that the New symbol is a function that returns a pluginapi.Plugin
	newFunc, ok := newSymbol.(func() pluginapi.Plugin)
	if !ok {
		return nil, fmt.Errorf("plugin %s New symbol has wrong type", path)
	}

	// Create an instance of the plugin
	return newFunc(), nil
}

// getRegisteredLoaders returns all registered plugin loaders
func getRegisteredLoaders() []PluginLoader {
	return []PluginLoader{
		&NativePluginLoader{},
		&WASMPluginLoader{},
	}
}

```

# internal/pluginmanager/plugin_manager.go

```go
package pluginmanager

import (
	"fmt"
	"log"
	"os"
	"github.com/withObsrvr/pluginapi"
	"path/filepath"
)

// PluginManager handles loading and initializing plugins
type PluginManager struct {
	Registry *PluginRegistry
	loaders  []PluginLoader
}

// NewPluginManager creates a new plugin manager
func NewPluginManager() *PluginManager {
	return &PluginManager{
		Registry: NewPluginRegistry(),
		loaders:  getRegisteredLoaders(),
	}
}

// LoadPlugins loads all plugins from the specified directory
func (pm *PluginManager) LoadPlugins(dir string, config map[string]interface{}) error {
	log.Printf("Loading plugins from directory: %s", dir)
	// Make sure the directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("plugin directory %s does not exist", dir)
	}

	// Walk through the directory and load all plugin files
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Find a loader that can handle this file
		for _, loader := range pm.loaders {
			if loader.CanLoad(path) {
				log.Printf("Loading plugin from %s", path)
				return pm.loadPluginWithLoader(path, loader, config)
			}
		}

		// No loader found for this file, skip it
		log.Printf("Skipping %s: no loader available for this file type", path)
		return nil
	})
}

// loadPluginWithLoader loads a plugin using the specified loader
func (pm *PluginManager) loadPluginWithLoader(path string, loader PluginLoader, config map[string]interface{}) error {
	// Load the plugin
	instance, err := loader.LoadPlugin(path)
	if err != nil {
		return fmt.Errorf("failed to load plugin %s: %w", path, err)
	}

	// Initialize the plugin with the provided config
	pluginConfig, _ := config[instance.Name()].(map[string]interface{})
	if err := instance.Initialize(pluginConfig); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", instance.Name(), err)
	}

	// Register the plugin
	if err := pm.Registry.Register(instance); err != nil {
		return fmt.Errorf("failed to register plugin %s: %w", instance.Name(), err)
	}

	log.Printf("Plugin %s v%s loaded successfully", instance.Name(), instance.Version())
	return nil
}

// RegisterLoader adds a new plugin loader to the manager
func (pm *PluginManager) RegisterLoader(loader PluginLoader) {
	pm.loaders = append(pm.loaders, loader)
}

```

# internal/pluginmanager/plugin_registry.go

```go
package pluginmanager

import (
	"fmt"

	"github.com/withObsrvr/pluginapi"
)

// PluginRegistry holds references to all registered plugins, categorized by type
type PluginRegistry struct {
	Sources    map[string]pluginapi.Source
	Processors map[string]pluginapi.Processor
	Consumers  map[string]pluginapi.Consumer
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		Sources:    make(map[string]pluginapi.Source),
		Processors: make(map[string]pluginapi.Processor),
		Consumers:  make(map[string]pluginapi.Consumer),
	}
}

// Register adds a plugin to the registry based on its type
func (pr *PluginRegistry) Register(p pluginapi.Plugin) error {
	switch p.Type() {
	case pluginapi.SourcePlugin:
		source, ok := p.(pluginapi.Source)
		if !ok {
			return fmt.Errorf("plugin %s claims to be a Source but does not implement the Source interface", p.Name())
		}
		pr.Sources[p.Name()] = source
	case pluginapi.ProcessorPlugin:
		processor, ok := p.(pluginapi.Processor)
		if !ok {
			return fmt.Errorf("plugin %s claims to be a Processor but does not implement the Processor interface", p.Name())
		}
		pr.Processors[p.Name()] = processor
	case pluginapi.ConsumerPlugin:
		consumer, ok := p.(pluginapi.Consumer)
		if !ok {
			return fmt.Errorf("plugin %s claims to be a Consumer but does not implement the Consumer interface", p.Name())
		}
		pr.Consumers[p.Name()] = consumer
	default:
		return fmt.Errorf("unknown plugin type %v for plugin %s", p.Type(), p.Name())
	}
	return nil
}

// GetSource returns a source plugin by name
func (pr *PluginRegistry) GetSource(name string) (pluginapi.Source, error) {
	source, ok := pr.Sources[name]
	if !ok {
		return nil, fmt.Errorf("source plugin %s not found", name)
	}
	return source, nil
}

// GetProcessor returns a processor plugin by name
func (pr *PluginRegistry) GetProcessor(name string) (pluginapi.Processor, error) {
	processor, ok := pr.Processors[name]
	if !ok {
		return nil, fmt.Errorf("processor plugin %s not found", name)
	}
	return processor, nil
}

// GetConsumer returns a consumer plugin by name
func (pr *PluginRegistry) GetConsumer(name string) (pluginapi.Consumer, error) {
	consumer, ok := pr.Consumers[name]
	if !ok {
		return nil, fmt.Errorf("consumer plugin %s not found", name)
	}
	return consumer, nil
}

```

# internal/pluginmanager/wasm_loader.go

```go
package pluginmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/withObsrvr/pluginapi"
)

// WASMPlugin implements the Plugin interface for WASM plugins
type WASMPlugin struct {
	name           string
	version        string
	pluginType     pluginapi.PluginType
	ctx            context.Context
	runtime        wazero.Runtime
	module         api.Module
	initializeFunc api.Function
	processFunc    api.Function
	closeFunc      api.Function
	allocFunc      api.Function
	freeFunc       api.Function
	initialized    bool
	config         map[string]interface{}
}

// Make sure WASMPlugin implements the Plugin interfaces
var _ pluginapi.Plugin = (*WASMPlugin)(nil)
var _ pluginapi.Source = (*WASMPlugin)(nil)
var _ pluginapi.Processor = (*WASMPlugin)(nil)
var _ pluginapi.Consumer = (*WASMPlugin)(nil)

// WASMPluginLoader loads WebAssembly plugins (.wasm files)
type WASMPluginLoader struct{}

// CanLoad returns true if the file has a .wasm extension
func (l *WASMPluginLoader) CanLoad(path string) bool {
	return filepath.Ext(path) == ".wasm"
}

// LoadPlugin loads a WASM plugin from the given path
func (l *WASMPluginLoader) LoadPlugin(path string) (pluginapi.Plugin, error) {
	log.Printf("Loading WASM plugin from %s", path)

	// Read the WASM file
	wasmBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read WASM file %s: %w", path, err)
	}

	// Create a context
	ctx := context.Background()

	// Create a new WebAssembly Runtime
	runtime := wazero.NewRuntime(ctx)

	// Add WASI support to the runtime
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	// Compile the WASM module
	module, err := runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compile WASM module %s: %w", path, err)
	}

	// Get module name and exit if none
	modName := filepath.Base(path)
	if module.Name() != "" {
		modName = module.Name()
	}

	// Create a configuration for the module
	config := wazero.NewModuleConfig().
		WithName(modName).
		WithStdout(log.Writer()).
		WithStderr(log.Writer())

	// Instantiate the module
	instance, err := runtime.InstantiateModule(ctx, module, config)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate WASM module %s: %w", path, err)
	}

	// Look up the functions we need
	nameFunc := instance.ExportedFunction("name")
	versionFunc := instance.ExportedFunction("version")
	typeFunc := instance.ExportedFunction("type")
	initializeFunc := instance.ExportedFunction("initialize")
	processFunc := instance.ExportedFunction("process")
	closeFunc := instance.ExportedFunction("close")
	allocFunc := instance.ExportedFunction("alloc")
	freeFunc := instance.ExportedFunction("free")

	// Check that all required functions are present
	if nameFunc == nil || versionFunc == nil || typeFunc == nil ||
		initializeFunc == nil || processFunc == nil || closeFunc == nil ||
		allocFunc == nil || freeFunc == nil {
		return nil, fmt.Errorf("WASM module %s is missing required exports", path)
	}

	// Call the name function to get the plugin name
	nameResult, err := nameFunc.Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to call name function: %w", err)
	}

	namePtr, nameLen := nameResult[0], nameResult[1]
	nameBuf, ok := instance.Memory().Read(uint32(namePtr), uint32(nameLen))
	if !ok {
		return nil, fmt.Errorf("failed to read name from memory")
	}
	name := string(nameBuf)

	// Call the version function to get the plugin version
	versionResult, err := versionFunc.Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to call version function: %w", err)
	}

	versionPtr, versionLen := versionResult[0], versionResult[1]
	versionBuf, ok := instance.Memory().Read(uint32(versionPtr), uint32(versionLen))
	if !ok {
		return nil, fmt.Errorf("failed to read version from memory")
	}
	version := string(versionBuf)

	// Call the type function to get the plugin type
	typeResult, err := typeFunc.Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to call type function: %w", err)
	}

	pluginType := pluginapi.PluginType(typeResult[0])

	// Create the WASM plugin
	return &WASMPlugin{
		name:           name,
		version:        version,
		pluginType:     pluginType,
		ctx:            ctx,
		runtime:        runtime,
		module:         instance,
		initializeFunc: initializeFunc,
		processFunc:    processFunc,
		closeFunc:      closeFunc,
		allocFunc:      allocFunc,
		freeFunc:       freeFunc,
		initialized:    false,
	}, nil
}

// Name implements the Plugin interface
func (p *WASMPlugin) Name() string {
	return p.name
}

// Version implements the Plugin interface
func (p *WASMPlugin) Version() string {
	return p.version
}

// Type implements the Plugin interface
func (p *WASMPlugin) Type() pluginapi.PluginType {
	return p.pluginType
}

// Initialize implements the Plugin interface
func (p *WASMPlugin) Initialize(config map[string]interface{}) error {
	if p.initialized {
		return nil
	}

	p.config = config

	// Convert the config to JSON
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	// Allocate memory for the config
	allocResult, err := p.allocFunc.Call(p.ctx, uint64(len(configJSON)))
	if err != nil {
		return fmt.Errorf("failed to allocate memory for config: %w", err)
	}

	configPtr := allocResult[0]

	// Write the config to memory
	ok := p.module.Memory().Write(uint32(configPtr), configJSON)
	if !ok {
		return fmt.Errorf("failed to write config to memory")
	}

	// Call the initialize function
	_, err = p.initializeFunc.Call(p.ctx, configPtr, uint64(len(configJSON)))
	if err != nil {
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}

	// Free the memory
	_, err = p.freeFunc.Call(p.ctx, configPtr, uint64(len(configJSON)))
	if err != nil {
		return fmt.Errorf("failed to free memory: %w", err)
	}

	p.initialized = true
	return nil
}

// Process implements the Processor and Consumer interfaces
func (p *WASMPlugin) Process(ctx context.Context, msg pluginapi.Message) error {
	if !p.initialized {
		return fmt.Errorf("plugin not initialized")
	}

	// Convert the message to JSON
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message to JSON: %w", err)
	}

	// Allocate memory for the message
	allocResult, err := p.allocFunc.Call(p.ctx, uint64(len(msgJSON)))
	if err != nil {
		return fmt.Errorf("failed to allocate memory for message: %w", err)
	}

	msgPtr := allocResult[0]

	// Write the message to memory
	ok := p.module.Memory().Write(uint32(msgPtr), msgJSON)
	if !ok {
		return fmt.Errorf("failed to write message to memory")
	}

	// Call the process function
	_, err = p.processFunc.Call(p.ctx, msgPtr, uint64(len(msgJSON)))
	if err != nil {
		return fmt.Errorf("failed to process message: %w", err)
	}

	// Free the memory
	_, err = p.freeFunc.Call(p.ctx, msgPtr, uint64(len(msgJSON)))
	if err != nil {
		return fmt.Errorf("failed to free memory: %w", err)
	}

	return nil
}

// Subscribe implements the Source interface
func (p *WASMPlugin) Subscribe(processor pluginapi.Processor) {
	// This is a placeholder - we can't directly call the Subscribe function in WASM
	// In a real implementation, we would need to handle this differently
	log.Printf("Subscribe called on WASM plugin %s, this is not fully implemented yet", p.name)
}

// Start implements the Source interface
func (p *WASMPlugin) Start(ctx context.Context) error {
	// This is a placeholder - we can't directly call the Start function in WASM
	// In a real implementation, we would need to handle this differently
	log.Printf("Start called on WASM plugin %s, this is not fully implemented yet", p.name)
	return nil
}

// Stop implements the Source interface
func (p *WASMPlugin) Stop() error {
	// This is a placeholder - we can't directly call the Stop function in WASM
	// In a real implementation, we would need to handle this differently
	log.Printf("Stop called on WASM plugin %s, this is not fully implemented yet", p.name)
	return nil
}

// RegisterConsumer implements the Processor interface
func (p *WASMPlugin) RegisterConsumer(consumer pluginapi.Consumer) {
	// This is a placeholder - we can't directly call the RegisterConsumer function in WASM
	// In a real implementation, we would need to handle this differently
	log.Printf("RegisterConsumer called on WASM plugin %s, this is not fully implemented yet", p.name)
}

// Close implements the Plugin interface
func (p *WASMPlugin) Close() error {
	if !p.initialized {
		return nil
	}

	// Call the close function
	_, err := p.closeFunc.Call(p.ctx)
	if err != nil {
		return fmt.Errorf("failed to close plugin: %w", err)
	}

	// Close the runtime
	err = p.runtime.Close(p.ctx)
	if err != nil {
		return fmt.Errorf("failed to close runtime: %w", err)
	}

	p.initialized = false
	return nil
}

```

# meta-flake.nix

```nix
{
  description = "Obsrvr Flow with all plugins";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    
    # Main Flow repository
    flow = {
      url = "github:withObsrvr/flow";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
    
    # Flow plugins
    flow-consumer-sqlite = {
      url = "github:withObsrvr/flow-consumer-sqlite";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
    
    flow-processor-latestledger = {
      url = "github:withObsrvr/flow-processor-latestledger";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
    
    flow-source-bufferedstorage-gcs = {
      url = "github:withObsrvr/flow-source-bufferedstorage-gcs";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = { self, nixpkgs, flake-utils, flow, flow-consumer-sqlite, 
              flow-processor-latestledger, flow-source-bufferedstorage-gcs }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        # Access packages from all inputs
        flowPackage = flow.packages.${system}.default;
        sqlitePlugin = flow-consumer-sqlite.packages.${system}.default;
        latestLedgerPlugin = flow-processor-latestledger.packages.${system}.default;
        gcsPlugin = flow-source-bufferedstorage-gcs.packages.${system}.default;
      in
      {
        packages = {
          default = pkgs.symlinkJoin {
            name = "flow-complete";
            paths = [
              flowPackage
              sqlitePlugin
              latestLedgerPlugin
              gcsPlugin
            ];
            
            # Create a clean directory structure
            postBuild = ''
              mkdir -p $out/plugins
              
              # Move plugin .so files to plugins directory
              find $out/lib -name "*.so" -exec mv {} $out/plugins/ \;
              
              # Clean up empty directories
              find $out -type d -empty -delete
              
              # Create version documentation
              mkdir -p $out/doc
              cat > $out/doc/README.md << EOF
              # Flow Complete Distribution
              
              This package contains the Flow application and the following plugins:
              
              - SQLite Consumer
              - Latest Ledger Processor
              - GCS Buffered Storage Source
              
              All components were built with the same Go toolchain (${pkgs.go_1_23.version}) to ensure compatibility.
              
              ## Directory Structure
              
              - \`bin/\` - Flow executables
              - \`plugins/\` - Plugin files (.so)
              
              ## Version Information
              
              - Flow: $(cat ${flowPackage}/VERSION 2>/dev/null || echo "unknown")
              - Built with Go ${pkgs.go_1_23.version}
              - Built on: $(date)
              
              EOF
            '';
          };
          
          # Also expose individual components
          flow = flowPackage;
          sqlite-plugin = sqlitePlugin;
          latestledger-plugin = latestLedgerPlugin;
          gcs-plugin = gcsPlugin;
        };
        
        # Development shell with all tools needed for the project
        devShell = pkgs.mkShell {
          buildInputs = [
            pkgs.go_1_23
            pkgs.sqlite
            pkgs.protobuf
          ];
          
          shellHook = ''
            echo "Flow development environment with all plugins"
            echo "Go version: $(go version)"
            echo ""
            echo "Available components:"
            echo "- Flow: ${flowPackage}"
            echo "- SQLite Consumer: ${sqlitePlugin}"
            echo "- Latest Ledger Processor: ${latestLedgerPlugin}"
            echo "- GCS Storage Source: ${gcsPlugin}"
            echo ""
            echo "To build everything: nix build"
            export GO111MODULE="on"
          '';
        };
      }
    );
} 
```

# pkg/schemaapi/schema.go

```go
package schemaapi

// SchemaRegistration represents a schema registration request
type SchemaRegistration struct {
	PluginName string `json:"plugin_name"`
	Schema     string `json:"schema"`
	Queries    string `json:"queries"`
}

// SchemaProvider is an interface for plugins that provide GraphQL schema components
type SchemaProvider interface {
	// GetSchemaDefinition returns GraphQL type definitions for this plugin
	GetSchemaDefinition() string

	// GetQueryDefinitions returns GraphQL query definitions for this plugin
	GetQueryDefinitions() string
}

```

# plugin_config_example.json

```json
{
    "address": "tcp://127.0.0.1:5555"
  }
  
```

# README.md

```md
# Flow - Data Processing Pipeline Framework

Flow is a plugin-based data processing pipeline framework that allows you to ingest, process, and output data through a configurable pipeline.

## Repository Structure

This repository is organized as a monorepo containing multiple components:

\`\`\`
/flow-project
  /cmd                  # Command-line applications
    /flow              # Main Flow engine
    /schema-registry   # Schema Registry service
    /graphql-api       # GraphQL API service
  
  /internal             # Internal packages
    /flow              # Core Flow engine code
    /metrics           # Metrics collection
    /pluginmanager     # Plugin loading and management
  
  /pkg                  # Public packages
    /pluginapi         # Plugin API interfaces
    /schemaapi         # Schema API interfaces
    /common            # Shared utilities
  
  /plugins              # Plugin .so and .wasm files
  
  /scripts              # Utility scripts
    run_local.sh       # Script to run all components locally
    test_wasm_plugin.sh # Script to test WASM plugin functionality
  
  /examples             # Example configurations
    /pipelines         # Example pipeline configurations
    /wasm-plugin-sample # Sample WASM plugin implementation
\`\`\`

## Components

### Flow Engine

The core Flow engine loads plugins and executes data processing pipelines based on configuration.

### Schema Registry

The Schema Registry service collects GraphQL schema definitions from plugins and composes them into a complete schema.

### GraphQL API

The GraphQL API service provides a query interface to access data processed by Flow pipelines.

## Plugin Support

Flow supports two types of plugins:

1. **Native Go Plugins** (.so files): Traditional Go plugins compiled as shared libraries.
2. **WebAssembly (WASM) Plugins** (.wasm files): Portable plugins that run in a sandboxed environment with improved security and cross-platform compatibility.

See [Plugin Support Documentation](docs/plugin_support.md) for details on creating and using both types of plugins.

## Running Locally

To run all components locally, use the provided script:

\`\`\`bash
./scripts/run_local.sh --pipeline your_pipeline.yaml
\`\`\`

Options:
- `--pipeline`: Path to pipeline configuration file (default: pipeline_example.yaml)
- `--plugins`: Directory containing plugin .so files (default: ./plugins)
- `--instance-id`: Unique ID for this instance (default: local-dev)
- `--tenant-id`: Tenant ID (default: local)
- `--api-key`: API key (default: local-dev-key)
- `--schema-port`: Port for Schema Registry (default: 8081)
- `--api-port`: Port for GraphQL API (default: 8080)

## Creating Plugins

Plugins can be created in two formats:

### Native Go Plugins

\`\`\`bash
go build -buildmode=plugin -o myplugin.so
\`\`\`

### WASM Plugins

\`\`\`bash
tinygo build -o myplugin.wasm -target=wasi ./main.go
\`\`\`

A plugin can be a:
- **Source**: Fetches data from an external system
- **Processor**: Transforms data
- **Consumer**: Outputs data to an external system

Plugins can also implement the `SchemaProvider` interface to contribute to the GraphQL schema.

## Pipeline Configuration

Pipelines are defined in YAML files:

\`\`\`yaml
pipelines:
  MyPipeline:
    source:
      type: "MySource"
      config:
        # Source configuration
    processors:
      - type: "MyProcessor"
        plugin: "./plugins/my-processor.so"  # or ".wasm" for WASM plugins
        config:
          # Processor configuration
    consumers:
      - type: "MyConsumer"
        plugin: "./plugins/my-consumer.wasm"  # WASM consumer example
        config:
          # Consumer configuration
\`\`\`

## GraphQL API

The GraphQL API provides a query interface to access data processed by Flow pipelines. It dynamically generates its schema based on the plugins used in your pipelines.

Access the GraphQL playground at: http://localhost:8080/graphql

## Development

To build all components:

\`\`\`bash
go build -o bin/flow cmd/flow/main.go
go build -o bin/schema-registry cmd/schema-registry/main.go
go build -o bin/graphql-api cmd/graphql-api/main.go
\`\`\`

## License

[License information]

```

# result

This is a binary file of the type: Binary

# run_docker.sh

```sh
#!/bin/bash

# run_docker.sh - Script to run Flow components using Docker Compose

# Default values
PIPELINE_FILE="/app/examples/pipelines/pipeline_default.yaml"
PIPELINE_DIR="./examples/pipelines"
INSTANCE_ID="docker"
TENANT_ID="docker"
API_KEY="docker-key"
DB_PATH="/app/data/flow_data.db"
BUILD=false
DETACH=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --pipeline)
      # Extract the filename from the path
      PIPELINE_FILENAME=$(basename "$2")
      # Extract the directory from the path and convert to absolute path if needed
      if [[ "$2" == /* ]]; then
        # Absolute path
        PIPELINE_DIR="$2"
      else
        # Relative path - get absolute path
        PIPELINE_DIR="$(cd "$(dirname "$2")" && pwd)"
      fi
      # Set the full path inside the container
      PIPELINE_FILE="/app/pipelines/${PIPELINE_FILENAME}"
      shift 2
      ;;
    --instance-id)
      INSTANCE_ID="$2"
      shift 2
      ;;
    --tenant-id)
      TENANT_ID="$2"
      shift 2
      ;;
    --api-key)
      API_KEY="$2"
      shift 2
      ;;
    --db-path)
      # If it's an absolute path, use it directly
      if [[ "$2" == /* ]]; then
        DB_PATH="$2"
      else
        # If it's a relative path, make it relative to /app/data in the container
        DB_PATH="/app/data/$(basename "$2")"
      fi
      shift 2
      ;;
    --build)
      BUILD=true
      shift
      ;;
    --detach|-d)
      DETACH=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo "Options:"
      echo "  --pipeline PATH     Path to pipeline configuration file (default: examples/pipelines/pipeline_default.yaml)"
      echo "  --instance-id ID    Instance ID (default: $INSTANCE_ID)"
      echo "  --tenant-id ID      Tenant ID (default: $TENANT_ID)"
      echo "  --api-key KEY       API key (default: $API_KEY)"
      echo "  --db-path PATH      Database path (default: flow_data.db)"
      echo "  --build             Build Docker images before starting containers"
      echo "  --detach, -d        Run containers in the background"
      echo "  --help, -h          Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help to see available options"
      exit 1
      ;;
  esac
done

# Export environment variables for docker compose
export PIPELINE_FILE
export PIPELINE_DIR
export INSTANCE_ID
export TENANT_ID
export API_KEY
export DB_PATH

# Print the configuration
echo "Starting Flow with the following configuration:"
echo "  Pipeline file: $PIPELINE_FILE"
echo "  Pipeline directory: $PIPELINE_DIR"
echo "  Instance ID: $INSTANCE_ID"
echo "  Tenant ID: $TENANT_ID"
echo "  API Key: $API_KEY"
echo "  Database path: $DB_PATH"

# Determine the Docker Compose command to use
if command -v docker-compose &> /dev/null; then
  COMPOSE_CMD="docker-compose"
else
  COMPOSE_CMD="docker compose"
fi

# Build and start the containers
if [ "$BUILD" = true ]; then
  if [ "$DETACH" = true ]; then
    $COMPOSE_CMD up --build -d
  else
    $COMPOSE_CMD up --build
  fi
else
  if [ "$DETACH" = true ]; then
    $COMPOSE_CMD up -d
  else
    $COMPOSE_CMD up
  fi
fi

# Function to clean up on exit
cleanup() {
  echo "Shutting down services..."
  $COMPOSE_CMD down
  echo "All services stopped"
  exit 0
}

# Handle termination if not detached
if [ "$DETACH" = false ]; then
  # Handle termination
  trap cleanup SIGINT SIGTERM

  echo "All services started. Press Ctrl+C to stop."
  echo "GraphQL API available at: http://localhost:8080/graphql"
  echo "Schema Registry available at: http://localhost:8081/schema"

  # Wait for user to press Ctrl+C
  wait
else
  echo "Services started in detached mode."
  echo "GraphQL API available at: http://localhost:8080/graphql"
  echo "Schema Registry available at: http://localhost:8081/schema"
  echo "To stop the services, run: $COMPOSE_CMD down"
fi 
```

# scripts/run_local.sh

```sh
#!/bin/bash
# run_local.sh - Script to run Flow components locally

# Default values
SCHEMA_REGISTRY_PORT=8081
GRAPHQL_API_PORT=8080
PLUGINS_DIR="./plugins"
PIPELINE_CONFIG="examples/pipelines/pipeline_example.yaml"
INSTANCE_ID="local-dev"
TENANT_ID="local"
API_KEY="local-dev-key"
DB_PATH=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --pipeline)
      PIPELINE_CONFIG="$2"
      shift 2
      ;;
    --plugins)
      PLUGINS_DIR="$2"
      shift 2
      ;;
    --instance-id)
      INSTANCE_ID="$2"
      shift 2
      ;;
    --tenant-id)
      TENANT_ID="$2"
      shift 2
      ;;
    --api-key)
      API_KEY="$2"
      shift 2
      ;;
    --schema-port)
      SCHEMA_REGISTRY_PORT="$2"
      shift 2
      ;;
    --api-port)
      GRAPHQL_API_PORT="$2"
      shift 2
      ;;
    --db-path)
      DB_PATH="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Ensure the binaries are built
echo "Building components..."
go build -buildmode=pie -o bin/flow cmd/flow/main.go
go build -buildmode=pie -o bin/schema-registry cmd/schema-registry/main.go
go build -buildmode=pie -o bin/graphql-api cmd/graphql-api/main.go

# Create a temporary directory for PID files
mkdir -p tmp

# Start Schema Registry in the background
echo "Starting Schema Registry on port $SCHEMA_REGISTRY_PORT..."
if [ -n "$DB_PATH" ]; then
  # If DB_PATH is explicitly provided, use it
  bin/schema-registry $SCHEMA_REGISTRY_PORT "$DB_PATH" &
else
  # Otherwise, pass the pipeline config file to extract the DB path
  bin/schema-registry $SCHEMA_REGISTRY_PORT "$PIPELINE_CONFIG" &
fi
SCHEMA_PID=$!
echo $SCHEMA_PID > tmp/schema-registry.pid

# Wait for Schema Registry to start
sleep 1

# Start Flow with user's configuration
echo "Starting Flow with pipeline config: $PIPELINE_CONFIG..."
bin/flow \
  --instance-id "$INSTANCE_ID" \
  --tenant-id "$TENANT_ID" \
  --api-key "$API_KEY" \
  --plugins "$PLUGINS_DIR" \
  --pipeline "$PIPELINE_CONFIG" &
FLOW_PID=$!
echo $FLOW_PID > tmp/flow.pid

# Wait for Flow to register schemas
sleep 2

# Start GraphQL API service
echo "Starting GraphQL API on port $GRAPHQL_API_PORT..."
bin/graphql-api $GRAPHQL_API_PORT "http://localhost:$SCHEMA_REGISTRY_PORT" "$PIPELINE_CONFIG" &
API_PID=$!
echo $API_PID > tmp/graphql-api.pid

# Function to clean up on exit
cleanup() {
  echo "Shutting down services..."
  
  if [ -f tmp/flow.pid ]; then
    kill $(cat tmp/flow.pid) 2>/dev/null || true
    rm tmp/flow.pid
  fi
  
  if [ -f tmp/schema-registry.pid ]; then
    kill $(cat tmp/schema-registry.pid) 2>/dev/null || true
    rm tmp/schema-registry.pid
  fi
  
  if [ -f tmp/graphql-api.pid ]; then
    kill $(cat tmp/graphql-api.pid) 2>/dev/null || true
    rm tmp/graphql-api.pid
  fi
  
  echo "All services stopped"
  exit 0
}

# Handle termination
trap cleanup SIGINT SIGTERM

echo "All services started. Press Ctrl+C to stop."
echo "GraphQL API available at: http://localhost:$GRAPHQL_API_PORT/graphql"
echo "Schema Registry available at: http://localhost:$SCHEMA_REGISTRY_PORT/schema"

# Wait for all processes
wait 
```

# scripts/run_original.sh

```sh
#!/bin/bash
# run_original.sh - Script to run the original Flow binary

# Default values
PLUGINS_DIR="./plugins"
PIPELINE_CONFIG="pipeline_example.yaml"
INSTANCE_ID="local-dev"
TENANT_ID="local"
API_KEY="local-dev-key"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --pipeline)
      PIPELINE_CONFIG="$2"
      shift 2
      ;;
    --plugins)
      PLUGINS_DIR="$2"
      shift 2
      ;;
    --instance-id)
      INSTANCE_ID="$2"
      shift 2
      ;;
    --tenant-id)
      TENANT_ID="$2"
      shift 2
      ;;
    --api-key)
      API_KEY="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Run the original Flow binary
echo "Running original Flow binary with pipeline config: $PIPELINE_CONFIG..."
./Flow \
  --instance-id "$INSTANCE_ID" \
  --tenant-id "$TENANT_ID" \
  --api-key "$API_KEY" \
  --plugins "$PLUGINS_DIR" \
  --pipeline "$PIPELINE_CONFIG" 
```

# scripts/test_gcs.go

```go
// test_gcs.go
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	// Get bucket name from command line
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test_gcs.go <bucket-name>")
		os.Exit(1)
	}
	bucketName := os.Args[1]

	// Print environment variables
	fmt.Println("GOOGLE_APPLICATION_CREDENTIALS:", os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))

	// Parse bucket name and prefix
	parts := strings.SplitN(bucketName, "/", 2)
	bucket := parts[0]
	prefix := ""
	if len(parts) > 1 {
		prefix = parts[1]
	}

	fmt.Printf("Bucket: %s\n", bucket)
	fmt.Printf("Prefix: %s\n", prefix)

	// Instead of using the GCS client directly, use gsutil command
	fmt.Printf("\nRunning: gsutil ls gs://%s/%s\n", bucket, prefix)
	cmd := exec.Command("gsutil", "ls", fmt.Sprintf("gs://%s/%s", bucket, prefix))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error running gsutil: %v", err)
	}
}

```

# scripts/test_wasm_plugin.sh

```sh
#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
EXAMPLES_DIR="$PROJECT_ROOT/examples"
WASM_SAMPLE_DIR="$EXAMPLES_DIR/wasm-plugin-sample"
PLUGINS_DIR="$PROJECT_ROOT/plugins"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Testing WASM Plugin Support ===${NC}"

# Make sure TinyGo is installed
if ! command -v tinygo &> /dev/null; then
    echo -e "${RED}Error: TinyGo is not installed. Please install TinyGo first.${NC}"
    echo "You can add TinyGo to your environment using Nix:"
    echo "  nix develop"
    exit 1
fi

# Build the WASM sample plugin
echo -e "${YELLOW}Building WASM sample plugin...${NC}"
cd "$WASM_SAMPLE_DIR"
if ! make build; then
    echo -e "${RED}Failed to build WASM sample plugin${NC}"
    exit 1
fi
echo -e "${GREEN}WASM sample plugin built successfully${NC}"

# Install the WASM plugin to the plugins directory
echo -e "${YELLOW}Installing WASM plugin to plugins directory...${NC}"
mkdir -p "$PLUGINS_DIR"
cp "$WASM_SAMPLE_DIR/wasm-sample.wasm" "$PLUGINS_DIR/"
echo -e "${GREEN}WASM plugin installed successfully${NC}"

# Run Flow with the WASM sample pipeline
echo -e "${YELLOW}Running Flow with WASM sample pipeline...${NC}"
cd "$PROJECT_ROOT"
./flow run --config examples/pipelines/pipeline_wasm_sample.yaml

echo -e "${GREEN}Test completed successfully!${NC}" 
```

