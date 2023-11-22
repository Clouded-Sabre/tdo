/*
 * Copyright 2023 Rodger Wang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
	viper.SetDefault("app.ginintesting", true)
}

// loadConfiguration loads configuration from a file using Viper
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

	ginInTesting = viper.GetBool("app.ginintesting")
}
