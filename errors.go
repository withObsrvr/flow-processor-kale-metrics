package main

import (
	"fmt"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	// ErrorTypeConfig represents configuration-related errors
	ErrorTypeConfig ErrorType = "config"
	// ErrorTypeProcessing represents errors that occur during message processing
	ErrorTypeProcessing ErrorType = "processing"
	// ErrorTypeParsing represents errors related to parsing messages or data
	ErrorTypeParsing ErrorType = "parsing"
	// ErrorTypeInternal represents internal errors in the processor
	ErrorTypeInternal ErrorType = "internal"
	// ErrorTypeNetwork represents network-related errors
	ErrorTypeNetwork ErrorType = "network"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	// ErrorSeverityFatal represents errors that prevent further processing
	ErrorSeverityFatal ErrorSeverity = "fatal"
	// ErrorSeverityError represents errors that affect a single message
	ErrorSeverityError ErrorSeverity = "error"
	// ErrorSeverityWarning represents non-critical errors
	ErrorSeverityWarning ErrorSeverity = "warning"
)

// ProcessorError encapsulates errors with additional context
type ProcessorError struct {
	Err             error                  // Original error
	Type            ErrorType              // Category of error
	Severity        ErrorSeverity          // Error severity
	TransactionHash string                 // Transaction context
	LedgerSequence  uint32                 // Ledger context
	BlockIndex      uint32                 // Block index context
	ContractID      string                 // Contract context
	Context         map[string]interface{} // Additional metadata
}

// Error implements the error interface
func (e *ProcessorError) Error() string {
	base := fmt.Sprintf("[%s/%s] %v", e.Type, e.Severity, e.Err)

	if e.ContractID != "" {
		base += fmt.Sprintf(" (contract: %s)", e.ContractID)
	}

	if e.BlockIndex > 0 {
		base += fmt.Sprintf(" (block: %d)", e.BlockIndex)
	}

	if e.TransactionHash != "" {
		base += fmt.Sprintf(" (tx: %s)", e.TransactionHash)
	}

	if e.LedgerSequence > 0 {
		base += fmt.Sprintf(" (ledger: %d)", e.LedgerSequence)
	}

	return base
}

// Unwrap returns the wrapped error
func (e *ProcessorError) Unwrap() error {
	return e.Err
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

// WithBlock adds block index information to the error
func (e *ProcessorError) WithBlock(blockIndex uint32) *ProcessorError {
	e.BlockIndex = blockIndex
	return e
}

// WithContract adds contract information to the error
func (e *ProcessorError) WithContract(contractID string) *ProcessorError {
	e.ContractID = contractID
	return e
}

// WithContext adds additional context to the error
func (e *ProcessorError) WithContext(key string, value interface{}) *ProcessorError {
	e.Context[key] = value
	return e
}
