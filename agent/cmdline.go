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
	"flag"
	"fmt"
	"log"

	"github.com/spf13/viper"
)

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("Since tcpdump needs root privilege, you have to run this program as root or sudoer")
	fmt.Println("  --help\t\tShow help message")
	fmt.Println("  -basedir string\tBase directory for pcap files (default \"/home/rodger/capture\")")
	fmt.Println("  -port string\tListening address for the API (default \"0.0.0.0:18443\")")
	fmt.Println("  -sslcert string\tPath to SSL certificate file (default \"/path/to/your/certificate.crt\")")
	fmt.Println("  -sslkey string\tPath to SSL private key file (default \"/path/to/your/private.key\")")
	fmt.Println("  -testhttps\t\tEnable/disable the test HTTPS endpoint (default false which means disabled)")
}

func parseCommandLineArguments() *bool {
	// Define command-line flags

	helpFlag := flag.Bool("help", false, "Show help message")
	flag.StringVar(&baseDirFlag, "basedir", "", "Base directory for pcap files")
	flag.StringVar(&listenAddressFlag, "port", "", "Listening address for the API")
	flag.StringVar(&sslCertPathFlag, "sslcert", "", "Path to SSL certificate file")
	flag.StringVar(&sslKeyPathFlag, "sslkey", "", "Path to SSL private key file")
	var testHttpsFlagString string
	flag.StringVar(&testHttpsFlagString, "testhttps", "", "Enable/disable the test HTTPS endpoint")
	flag.Parse()

	if baseDirFlag == "" {
		baseDirFlag = viper.GetString("app.basedir")
	}
	if listenAddressFlag == "" {
		listenAddressFlag = viper.GetString("app.port")
	}
	if sslCertPathFlag == "" {
		sslCertPathFlag = viper.GetString("app.sslcert")
	}
	if sslKeyPathFlag == "" {
		sslKeyPathFlag = viper.GetString("app.sslkey")
	}

	// Check if the testHttpsFlag is explicitly set in the command line
	if testHttpsFlagString == "" {
		// Flag is not explicitly set in the command line, use the default or config file value
		fmt.Println("Flag not set in the command line. Using default or config file value.")
		testHttpsFlag = viper.GetBool("app.testhttps")
	} else {
		// Flag is explicitly set in the command line
		if testHttpsFlagString == "true" || testHttpsFlagString == "false" {
			fmt.Println("Flag is set in the command line. We use it.")
			if testHttpsFlagString == "true" {
				testHttpsFlag = true
			} else {
				testHttpsFlag = true
			}
		} else {
			log.Fatal("Command line argument testHttps should be either 'true' or 'false'!")
		}
	}

	return helpFlag
}
