package main

import (
	"log"

	"github.com/spf13/viper"
)

func loadDefaultConfiguration() {
	// Set default values for configuration parameters
	viper.SetDefault("radius.secret", "testing123")
	viper.SetDefault("radius.address", "127.0.0.1:1812")
	viper.SetDefault("app.basedir", "capture")
	viper.SetDefault("app.port", "0.0.0.0:18443")
	viper.SetDefault("app.sslcert", "cert/certificate.crt")
	viper.SetDefault("app.sslkey", "cert/private.key")
	viper.SetDefault("app.testhttps", false)
}

// loadConfiguration loads configuration from a file using Viper or your preferred configuration library.
func loadConfigurationFromFile() {
	viper.SetConfigName("config") // Name of your configuration file (without extension)
	viper.SetConfigType("yaml")   // Choose the appropriate configuration file type (e.g., JSON, YAML)

	// Add paths where Viper will look for the configuration file
	viper.AddConfigPath("/etc/synctcpdump/") // Path to global configuration
	viper.AddConfigPath(".")                 // Path to the directory of the executable

	// Automatically search for config file in the specified paths
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}
}
