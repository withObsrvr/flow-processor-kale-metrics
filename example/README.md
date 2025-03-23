# Kale Metrics Processor Example

This directory contains example files for using the Kale Metrics Processor.

## Sample Files

- `sample_event.json`: A sample contract event message
- `sample_invocation.json`: A sample contract invocation message

## Usage

To use the Kale Metrics Processor in your code:

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// Define a consumer that implements the Consumer interface
type ExampleConsumer struct{}

// Implement the Consume method
func (c *ExampleConsumer) Consume(ctx context.Context, metric interface{}) error {
	// Convert metric to JSON for display
	metricJSON, err := json.MarshalIndent(metric, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling metric to JSON: %w", err)
	}

	fmt.Printf("Received metric:\n%s\n", string(metricJSON))
	return nil
}

func main() {
	// Create a new processor
	processor := NewKaleMetricsProcessor()

	// Create a consumer
	consumer := &ExampleConsumer{}

	// Subscribe the consumer
	processor.Subscribe(consumer)

	// Create a context
	ctx := context.Background()

	// Read sample event data from file
	eventData, err := os.ReadFile("sample_event.json")
	if err != nil {
		log.Fatalf("Error reading sample event data: %v", err)
	}

	// Parse event data
	var event map[string]interface{}
	if err := json.Unmarshal(eventData, &event); err != nil {
		log.Fatalf("Error parsing sample event data: %v", err)
	}

	// Process the event
	if err := processor.ProcessEventMessage(ctx, event); err != nil {
		log.Fatalf("Error processing event: %v", err)
	}

	// Read sample invocation data from file
	invocationData, err := os.ReadFile("sample_invocation.json")
	if err != nil {
		log.Fatalf("Error reading sample invocation data: %v", err)
	}

	// Parse invocation data
	var invocation map[string]interface{}
	if err := json.Unmarshal(invocationData, &invocation); err != nil {
		log.Fatalf("Error parsing sample invocation data: %v", err)
	}

	// Process the invocation
	if err := processor.ProcessInvocationMessage(ctx, invocation); err != nil {
		log.Fatalf("Error processing invocation: %v", err)
	}
} 