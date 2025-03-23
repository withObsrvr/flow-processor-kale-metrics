package main

import (
	"github.com/withObsrvr/pluginapi"
)

// New creates a new KaleMetricsPlugin
// This is the entry point for the plugin framework
func New() pluginapi.Plugin {
	return NewPlugin()
}

// main is a placeholder - the plugin is loaded dynamically by the framework
func main() {
	// This function is not executed when loaded as a plugin
}
