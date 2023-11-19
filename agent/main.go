package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

var (
	mutex        sync.Mutex
	isTcpdumpOn  bool
	tcpdumpCmd   *exec.Cmd
	pcapFilename string

	baseDirFlag        string
	listenAddressFlag  string
	tcpdumpOptionsFlag string
	sslCertPathFlag    string
	sslKeyPathFlag     string
	radius_secret      string
	radius_address     string

	testHttpsFlag bool // Add a flag to enable/disable the test HTTPS endpoint
)

func main() {
	// Load default configuration
	loadDefaultConfiguration()

	// Load configuration from file
	loadConfigurationFromFile()

	// Parse command line arguments. Command line argument take the precedence if present
	helpFlag := parseCommandLineArguments()

	// Check if the program is running as root, except for the --help option
	if !*helpFlag && !isRootUser() {
		fmt.Println("WARNING: This program should be run as root to capture network traffic.")
		os.Exit(1)
	}

	if *helpFlag {
		printUsage()
		os.Exit(0)
	}

	radius_secret = viper.GetString("radius.secret")
	radius_address = viper.GetString("radius.address")

	// Create a Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Routes
	r.POST("/start_tcpdump", startTcpdump)
	r.POST("/stop_tcpdump", stopTcpdump)
	r.GET("/download_pcap", downloadPcap)
	r.POST("/delete_pcap", deletePcap)
	if testHttpsFlag {
		r.GET("/test_https", testHttps)   // Add the new route for testing HTTPS
		r.GET("/test_radius", testRadius) // Add the new route for testing RADIUS+HTTPS
	}

	// Create a new HTTPS server
	server := &http.Server{
		Addr:    listenAddressFlag,
		Handler: r,
	}

	// Start the server in a goroutine
	go func() {
		if err := server.ListenAndServeTLS(sslCertPathFlag, sslKeyPathFlag); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServeTLS: %v", err)
		}
	}()

	// Wait for a control-c signal to exit
	select {}
}

func startTcpdump(c *gin.Context) {
	// Acquire the mutex to prevent concurrent start requests
	mutex.Lock()
	defer mutex.Unlock()

	// Authenticate the user using basic authentication
	if !authenticateUser(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	if isTcpdumpOn {
		c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "tcpdump is already running"})
		return
	}

	var requestData map[string]string
	if err := c.ShouldBindJSON(&requestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid JSON data"})
		return
	}

	pcapFilename = baseDirFlag + "/" + requestData["pcap_filename"]
	if pcapFilename == baseDirFlag+"/" {
		pcapFilename = baseDirFlag + "/capture.pcap"
	}

	// Check if the request includes tcpdump options
	tcpdumpOptions := requestData["tcpdump_options"]
	if tcpdumpOptions == "" {
		// If not specified, use the default options
		tcpdumpOptions = tcpdumpOptionsFlag
	}

	tcpdumpCmd = exec.Command("/usr/bin/tcpdump", strings.Fields(tcpdumpOptions)...)
	tcpdumpCmd.Args = append(tcpdumpCmd.Args, "-w", pcapFilename)

	if err := tcpdumpCmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}

	isTcpdumpOn = true

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "tcpdump started", "pcap_filename": pcapFilename})
}

func stopTcpdump(c *gin.Context) {
	// Acquire the mutex to prevent concurrent stop requests
	mutex.Lock()
	defer mutex.Unlock()

	// Authenticate the user using basic authentication
	if !authenticateUser(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	if !isTcpdumpOn {
		c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "tcpdump is not running"})
		return
	}

	if err := tcpdumpCmd.Process.Kill(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}

	isTcpdumpOn = false

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "tcpdump stopped"})
}

func downloadPcap(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	// Authenticate the user using RADIUS
	if !authenticateUser(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	// Check if the pcap file exists
	if _, err := os.Stat(pcapFilename); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Pcap file not found"})
		return
	}

	// Set the appropriate headers for downloading the file
	c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", pcapFilename))
	c.Writer.Header().Add("Content-Type", "application/octet-stream")

	// Send the file as the response
	c.File(pcapFilename)
}

func deletePcap(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	// Authenticate the user using RADIUS
	if !authenticateUser(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	// Check if the pcap file exists
	if _, err := os.Stat(pcapFilename); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Pcap file not found"})
		return
	}

	// Delete the pcap file
	if err := os.Remove(pcapFilename); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Pcap file deleted"})
}

func authenticateUser(c *gin.Context) bool {
	username, password, hasAuth := c.Request.BasicAuth()

	if !hasAuth {
		return false
	}

	// Use RADIUS for authentication
	packet := radius.New(radius.CodeAccessRequest, []byte(radius_secret))
	rfc2865.UserName_SetString(packet, username)
	rfc2865.UserPassword_SetString(packet, password)
	response, err := radius.Exchange(context.Background(), packet, radius_address)

	if err != nil {
		log.Printf("RADIUS exchange error: %v", err)
		return false
	}

	if response.Code != radius.CodeAccessAccept {
		log.Printf("RADIUS authentication failed. Response Code: %d", response.Code)
		return false
	}

	return true
}

func isRootUser() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0" || u.Gid == "0"
}

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

func testHttps(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Test HTTPS communication successful"})
}

func testRadius(c *gin.Context) {
	// Authenticate the user using basic authentication
	if !authenticateUser(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Test RADIUS communication successful"})
}

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
