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

	"github.com/stellar/go/ingest"
	"github.com/stellar/go/strkey"
	"github.com/stellar/go/toid"
	"github.com/stellar/go/xdr"
	"github.com/withObsrvr/pluginapi"
)

// ErrorType defines the category of an error
type ErrorType string

const (
	ErrorTypeConfig     ErrorType = "config"
	ErrorTypeNetwork    ErrorType = "network"
	ErrorTypeParsing    ErrorType = "parsing"
	ErrorTypeProcessing ErrorType = "processing"
	ErrorTypeConsumer   ErrorType = "consumer"
)

// ErrorSeverity defines how critical an error is
type ErrorSeverity string

const (
	ErrorSeverityFatal   ErrorSeverity = "fatal"
	ErrorSeverityWarning ErrorSeverity = "warning"
	ErrorSeverityInfo    ErrorSeverity = "info"
)

// ProcessorError represents a structured error with context
type ProcessorError struct {
	Err             error
	Type            ErrorType
	Severity        ErrorSeverity
	TransactionHash string
	LedgerSequence  uint32
	ContractID      string
	Context         map[string]interface{}
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

// ContractEvent represents an event emitted by a contract
type ContractEvent struct {
	// Transaction context
	TransactionHash   string    `json:"transaction_hash"`
	TransactionID     int64     `json:"transaction_id"`
	Successful        bool      `json:"successful"`
	LedgerSequence    uint32    `json:"ledger_sequence"`
	ClosedAt          time.Time `json:"closed_at"`
	NetworkPassphrase string    `json:"network_passphrase"`

	// Event context
	ContractID     string `json:"contract_id"`
	EventIndex     int    `json:"event_index"`
	OperationIndex int    `json:"operation_index"`

	// Event type information
	Type     string `json:"type"`
	TypeCode int32  `json:"type_code"`

	// Event data - both raw and decoded
	Topics        []TopicData `json:"topics"`
	TopicsDecoded []TopicData `json:"topics_decoded"`
	Data          EventData   `json:"data"`
	DataDecoded   EventData   `json:"data_decoded"`
	EventXDR      string      `json:"event_xdr"`

	// Kale-specific information
	FunctionName string            `json:"function_name,omitempty"`
	KaleMetrics  map[string]string `json:"kale_metrics,omitempty"`

	// Metadata for querying and filtering
	Tags map[string]string `json:"tags,omitempty"`
}

// ContractInvocation represents a contract function invocation
type ContractInvocation struct {
	// Transaction context
	TransactionHash   string    `json:"transaction_hash"`
	TransactionID     int64     `json:"transaction_id"`
	Successful        bool      `json:"successful"`
	LedgerSequence    uint32    `json:"ledger_sequence"`
	ClosedAt          time.Time `json:"closed_at"`
	NetworkPassphrase string    `json:"network_passphrase"`

	// Contract context
	ContractID     string `json:"contract_id"`
	OperationIndex int    `json:"operation_index"`

	// Function information
	FunctionName string `json:"function_name"`
	Parameters   []struct {
		Name  string    `json:"name,omitempty"`
		Value EventData `json:"value"`
	} `json:"parameters"`

	// Result information
	Result EventData `json:"result"`

	// Kale-specific metrics
	KaleMetrics map[string]string `json:"kale_metrics,omitempty"`
}

// KaleContractProcessor processes events and invocations from the Kale contract
type KaleContractProcessor struct {
	networkPassphrase string
	kaleContractID    string
	consumers         []pluginapi.Consumer
	mu                sync.RWMutex
	stats             struct {
		ProcessedLedgers      uint32
		EventsFound           uint64
		InvocationsFound      uint64
		SuccessfulEvents      uint64
		SuccessfulInvocations uint64
		LastLedger            uint32
		LastProcessedTime     time.Time
	}
}

// Initialize configures the processor with necessary parameters
func (p *KaleContractProcessor) Initialize(config map[string]interface{}) error {
	// Get network passphrase from config
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

	// Get Kale contract ID from config
	kaleContractID, ok := config["kale_contract_id"].(string)
	if !ok {
		return NewProcessorError(
			errors.New("missing kale_contract_id in configuration"),
			ErrorTypeConfig,
			ErrorSeverityFatal,
		)
	}

	if kaleContractID == "" {
		return NewProcessorError(
			errors.New("kale_contract_id cannot be empty"),
			ErrorTypeConfig,
			ErrorSeverityFatal,
		)
	}

	p.networkPassphrase = networkPassphrase
	p.kaleContractID = kaleContractID
	return nil
}

// RegisterConsumer adds a consumer to the processor
func (p *KaleContractProcessor) RegisterConsumer(consumer pluginapi.Consumer) {
	log.Printf("KaleContractProcessor: Registering consumer %s", consumer.Name())
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consumers = append(p.consumers, consumer)
}

// Process handles the main processing logic for events and invocations
func (p *KaleContractProcessor) Process(ctx context.Context, msg pluginapi.Message) error {
	// Check for canceled context
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
	log.Printf("Processing ledger %d for Kale contract events and invocations", sequence)

	txReader, err := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(p.networkPassphrase, ledgerCloseMeta)
	if err != nil {
		return NewProcessorError(
			fmt.Errorf("error creating transaction reader: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityFatal,
		).WithLedger(sequence)
	}
	defer txReader.Close()

	// Process each transaction
	for {
		// Check for context cancellation
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
			// Continue despite transaction read errors
			log.Printf("Warning: %s", NewProcessorError(
				fmt.Errorf("error reading transaction: %w", err),
				ErrorTypeProcessing,
				ErrorSeverityWarning,
			).WithLedger(sequence).Error())
			continue
		}

		txHash := tx.Result.TransactionHash.HexString()

		// Process Kale contract invocations and events
		err = p.processTransaction(ctx, tx, txHash, ledgerCloseMeta)
		if err != nil {
			log.Printf("Error processing transaction: %s", err.Error())
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

// processTransaction examines a transaction for Kale contract invocations and events
func (p *KaleContractProcessor) processTransaction(
	ctx context.Context,
	tx ingest.LedgerTransaction,
	txHash string,
	meta xdr.LedgerCloseMeta,
) error {
	// Process invocations first, as they may generate events
	invocations, err := p.processKaleInvocations(ctx, tx, txHash, meta)
	if err != nil {
		log.Printf("Warning: Error processing Kale invocations: %s", err.Error())
	}

	// Process any invocations found
	for _, invocation := range invocations {
		err := p.forwardInvocationToConsumers(ctx, invocation)
		if err != nil {
			log.Printf("Warning: Error forwarding invocation: %s", err.Error())
		}
	}

	// Process events
	events, err := p.processKaleEvents(ctx, tx, txHash, meta)
	if err != nil {
		log.Printf("Warning: Error processing Kale events: %s", err.Error())
	}

	// Process any events found
	for _, event := range events {
		err := p.forwardEventToConsumers(ctx, event)
		if err != nil {
			log.Printf("Warning: Error forwarding event: %s", err.Error())
		}
	}

	return nil
}

// processKaleInvocations extracts and processes Kale contract invocations
func (p *KaleContractProcessor) processKaleInvocations(
	ctx context.Context,
	tx ingest.LedgerTransaction,
	txHash string,
	meta xdr.LedgerCloseMeta,
) ([]*ContractInvocation, error) {
	var invocations []*ContractInvocation

	for opIdx, op := range tx.Envelope.Operations() {
		// Skip operations that aren't InvokeHostFunction
		if op.Body.Type != xdr.OperationTypeInvokeHostFunction {
			continue
		}

		// Get the host function
		hostFuncOp, ok := op.Body.GetInvokeHostFunctionOp()
		if !ok {
			continue
		}
		hostFunc := hostFuncOp.HostFunction

		// Only interested in InvokeContract functions
		if hostFunc.Type != xdr.HostFunctionTypeHostFunctionTypeInvokeContract {
			continue
		}

		// Get the contract invocation details
		contractInvoke := hostFunc.MustInvokeContract()

		// Convert contract address to string
		var contractID string
		contractIdByte, err := contractInvoke.ContractAddress.MarshalBinary()
		if err != nil {
			log.Printf("Warning: Error marshaling contract ID: %v", err)
			continue
		}

		contractID, err = strkey.Encode(strkey.VersionByteContract, contractIdByte)
		if err != nil {
			log.Printf("Warning: Error encoding contract ID: %v", err)
			continue
		}

		// Skip if not Kale contract
		if contractID != p.kaleContractID {
			continue
		}

		// Create ContractInvocation object
		functionNameStr := string(contractInvoke.FunctionName)
		invocation := &ContractInvocation{
			TransactionHash:   txHash,
			TransactionID:     toid.New(int32(meta.LedgerSequence()), int32(tx.Index), 0).ToInt64(),
			Successful:        tx.Result.Successful(),
			LedgerSequence:    meta.LedgerSequence(),
			ClosedAt:          time.Unix(int64(meta.LedgerHeaderHistoryEntry().Header.ScpValue.CloseTime), 0),
			NetworkPassphrase: p.networkPassphrase,
			ContractID:        contractID,
			OperationIndex:    opIdx,
			FunctionName:      functionNameStr,
			KaleMetrics:       make(map[string]string),
		}

		// Process function parameters
		for i, param := range contractInvoke.Args {
			rawParam, decodedParam := serializeScVal(param)

			invocation.Parameters = append(invocation.Parameters, struct {
				Name  string    `json:"name,omitempty"`
				Value EventData `json:"value"`
			}{
				Name:  fmt.Sprintf("param_%d", i), // We don't have parameter names from the XDR
				Value: rawParam,
			})

			// Store decoded value in the KaleMetrics for specific parameters
			switch i {
			case 0:
				invocation.KaleMetrics[fmt.Sprintf("decoded_param_%d", i)] = decodedParam.Value
			}
		}

		// Add Kale-specific metrics based on function name
		switch functionNameStr {
		case "plant":
			// Plant metrics: amount, farmer
			if len(contractInvoke.Args) >= 2 {
				amountScVal := contractInvoke.Args[0]
				farmerScVal := contractInvoke.Args[1]

				if amountScVal.Type == xdr.ScValTypeScvI128 {
					invocation.KaleMetrics["amount"] = amountScVal.String()
				}

				if farmerScVal.Type == xdr.ScValTypeScvAddress {
					invocation.KaleMetrics["farmer"] = farmerScVal.String()
				}
			}
		case "work":
			// Work metrics: farmer, nonce, hash
			if len(contractInvoke.Args) >= 3 {
				farmerScVal := contractInvoke.Args[0]
				nonceScVal := contractInvoke.Args[1]
				hashScVal := contractInvoke.Args[2]

				if farmerScVal.Type == xdr.ScValTypeScvAddress {
					invocation.KaleMetrics["farmer"] = farmerScVal.String()
				}

				if nonceScVal.Type == xdr.ScValTypeScvU64 {
					invocation.KaleMetrics["nonce"] = nonceScVal.String()
				}

				if hashScVal.Type == xdr.ScValTypeScvBytes {
					invocation.KaleMetrics["hash"] = hashScVal.String()
				}
			}
		case "harvest":
			// Harvest metrics: index, farmer
			if len(contractInvoke.Args) >= 2 {
				indexScVal := contractInvoke.Args[0]
				farmerScVal := contractInvoke.Args[1]

				if indexScVal.Type == xdr.ScValTypeScvU32 {
					invocation.KaleMetrics["index"] = indexScVal.String()
				}

				if farmerScVal.Type == xdr.ScValTypeScvAddress {
					invocation.KaleMetrics["farmer"] = farmerScVal.String()
				}
			}
		}

		invocations = append(invocations, invocation)

		// Update stats
		p.mu.Lock()
		p.stats.InvocationsFound++
		if invocation.Successful {
			p.stats.SuccessfulInvocations++
		}
		p.mu.Unlock()
	}

	return invocations, nil
}

// processKaleEvents extracts and processes Kale contract events
func (p *KaleContractProcessor) processKaleEvents(
	ctx context.Context,
	tx ingest.LedgerTransaction,
	txHash string,
	meta xdr.LedgerCloseMeta,
) ([]*ContractEvent, error) {
	var events []*ContractEvent

	// Get diagnostic events from transaction
	diagnosticEvents, err := tx.GetDiagnosticEvents()
	if err != nil {
		return nil, NewProcessorError(
			fmt.Errorf("error getting diagnostic events: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		).WithTransaction(txHash)
	}

	// Process events by operation index
	for opIdx, opEvents := range filterContractEvents(diagnosticEvents) {
		for eventIdx, event := range opEvents {
			// Check for the Kale contract ID
			var contractID string
			if event.ContractId != nil {
				contractIdByte, err := event.ContractId.MarshalBinary()
				if err != nil {
					continue
				}
				contractID, err = strkey.Encode(strkey.VersionByteContract, contractIdByte)
				if err != nil {
					continue
				}
			}

			// Skip if not the Kale contract
			if contractID != p.kaleContractID {
				continue
			}

			// Get event topics and data
			var topics []xdr.ScVal
			var eventData xdr.ScVal

			if event.Body.V == 0 {
				v0 := event.Body.MustV0()
				topics = v0.Topics
				eventData = v0.Data
			} else {
				continue // Skip unsupported event body versions
			}

			// Convert event XDR to base64
			eventXDR, err := xdr.MarshalBase64(event)
			if err != nil {
				continue
			}

			// Serialize topics and data
			rawTopics, decodedTopics := serializeScValArray(topics)
			rawData, decodedData := serializeScVal(eventData)

			// Create contract event
			contractEvent := &ContractEvent{
				TransactionHash:   txHash,
				TransactionID:     toid.New(int32(meta.LedgerSequence()), int32(tx.Index), 0).ToInt64(),
				Successful:        tx.Result.Successful(),
				LedgerSequence:    meta.LedgerSequence(),
				ClosedAt:          time.Unix(int64(meta.LedgerHeaderHistoryEntry().Header.ScpValue.CloseTime), 0),
				NetworkPassphrase: p.networkPassphrase,
				ContractID:        contractID,
				EventIndex:        eventIdx,
				OperationIndex:    opIdx,
				Type:              event.Type.String(),
				TypeCode:          int32(event.Type),
				Topics:            rawTopics,
				TopicsDecoded:     decodedTopics,
				Data:              rawData,
				DataDecoded:       decodedData,
				EventXDR:          eventXDR,
				KaleMetrics:       make(map[string]string),
				Tags:              make(map[string]string),
			}

			// Add basic tags for filtering
			contractEvent.Tags["contract_id"] = contractID
			contractEvent.Tags["event_type"] = event.Type.String()
			contractEvent.Tags["successful"] = fmt.Sprintf("%t", tx.Result.Successful())

			// Analyze topics to extract Kale-specific information
			// For example, if the first topic contains a function name
			if len(decodedTopics) > 0 {
				functionName := decodedTopics[0].Value
				contractEvent.FunctionName = functionName
				contractEvent.Tags["function"] = functionName

				// Add Kale-specific metrics based on function
				switch functionName {
				case "plant":
					if len(decodedTopics) > 1 {
						contractEvent.KaleMetrics["farmer"] = decodedTopics[1].Value
					}
					if len(decodedTopics) > 2 {
						contractEvent.KaleMetrics["amount"] = decodedTopics[2].Value
					}
				case "work":
					if len(decodedTopics) > 1 {
						contractEvent.KaleMetrics["farmer"] = decodedTopics[1].Value
					}
					if len(decodedTopics) > 2 {
						contractEvent.KaleMetrics["hash"] = decodedTopics[2].Value
					}
				case "harvest":
					if len(decodedTopics) > 1 {
						contractEvent.KaleMetrics["farmer"] = decodedTopics[1].Value
					}
					if len(decodedTopics) > 2 {
						contractEvent.KaleMetrics["amount"] = decodedTopics[2].Value
					}
				}
			}

			events = append(events, contractEvent)

			// Update stats
			p.mu.Lock()
			p.stats.EventsFound++
			if contractEvent.Successful {
				p.stats.SuccessfulEvents++
			}
			p.mu.Unlock()
		}
	}

	return events, nil
}

// forwardInvocationToConsumers sends an invocation to all registered consumers
func (p *KaleContractProcessor) forwardInvocationToConsumers(ctx context.Context, invocation *ContractInvocation) error {
	jsonBytes, err := json.Marshal(invocation)
	if err != nil {
		return NewProcessorError(
			fmt.Errorf("error marshaling invocation: %w", err),
			ErrorTypeProcessing,
			ErrorSeverityWarning,
		)
	}

	msg := pluginapi.Message{
		Payload:   jsonBytes,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"ledger_sequence": invocation.LedgerSequence,
			"contract_id":     invocation.ContractID,
			"transaction_id":  invocation.TransactionID,
			"function_name":   invocation.FunctionName,
			"type":            "kale_invocation",
		},
	}

	return p.forwardToConsumers(ctx, msg)
}

// forwardEventToConsumers sends an event to all registered consumers
func (p *KaleContractProcessor) forwardEventToConsumers(ctx context.Context, event *ContractEvent) error {
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
			"type":            "kale_event",
			"event_type":      event.Type,
		},
	}

	return p.forwardToConsumers(ctx, msg)
}

// forwardToConsumers sends a message to all registered consumers
func (p *KaleContractProcessor) forwardToConsumers(ctx context.Context, msg pluginapi.Message) error {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return NewProcessorError(
			fmt.Errorf("context canceled before forwarding: %w", err),
			ErrorTypeConsumer,
			ErrorSeverityWarning,
		)
	}

	// Get a copy of consumers slice to avoid race conditions
	p.mu.RLock()
	consumers := make([]pluginapi.Consumer, len(p.consumers))
	copy(consumers, p.consumers)
	p.mu.RUnlock()

	for _, consumer := range consumers {
		// Check context before each consumer
		if err := ctx.Err(); err != nil {
			return NewProcessorError(
				fmt.Errorf("context canceled during forwarding: %w", err),
				ErrorTypeConsumer,
				ErrorSeverityWarning,
			)
		}

		// Use a timeout for each consumer
		consumerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := consumer.Process(consumerCtx, msg)
		cancel() // Always cancel to prevent context leak

		if err != nil {
			log.Printf("Error in consumer %s: %v", consumer.Name(), err)
		}
	}

	return nil
}

// filterContractEvents groups contract events by operation index
func filterContractEvents(diagnosticEvents []xdr.DiagnosticEvent) map[int][]xdr.ContractEvent {
	events := make(map[int][]xdr.ContractEvent)

	for _, diagEvent := range diagnosticEvents {
		if !diagEvent.InSuccessfulContractCall || diagEvent.Event.Type != xdr.ContractEventTypeContract {
			continue
		}

		// Use the operation index as the key (default to 0 if not available)
		opIndex := 0
		events[opIndex] = append(events[opIndex], diagEvent.Event)
	}
	return events
}

// serializeScVal converts an ScVal to structured data format
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

// Name returns the plugin name
func (p *KaleContractProcessor) Name() string {
	return "flow/processor/kale-metrics"
}

// Version returns the plugin version
func (p *KaleContractProcessor) Version() string {
	return "1.0.0"
}

// Type returns the plugin type
func (p *KaleContractProcessor) Type() pluginapi.PluginType {
	return pluginapi.ProcessorPlugin
}

// New creates a new instance of the processor
func New() pluginapi.Plugin {
	return &KaleContractProcessor{}
}
