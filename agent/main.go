package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

var (
	mutex             sync.Mutex
	tcpdumpSessions   map[string]tcpdumpSession
	baseDirFlag       string
	listenAddressFlag string
	sslCertPathFlag   string
	sslKeyPathFlag    string
	radius_secret     string
	radius_address    string
	testHttpsFlag     bool // enable/disable the test HTTPS endpoint
)

type tcpdumpSession struct {
	isRunning           bool
	tcpdumpCmd          *exec.Cmd
	tcpdumpOptionsFlag  string
	pcapFilename        string
	StartTime, stopTime time.Time
}

func NewTcpdumpSession(name, baseDirFlag, pcapFilename, tcpdumpOptionsFlag string) *tcpdumpSession {
	session := &tcpdumpSession{
		isRunning:          false,
		tcpdumpCmd:         nil,
		tcpdumpOptionsFlag: tcpdumpOptionsFlag,
		pcapFilename:       pcapFilename,
		StartTime:          time.Time{}, // Zero value for time.Time indicates an uninitialized time
	}

	return session
}

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
	r.GET("/list_sessions", listSessions)
	r.GET("/get_filesize", getFilesize) // Add new route for file size
	r.GET("/get_duration", getDuration) // Add new route for capture session duration
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

	var requestData map[string]string
	if err := c.ShouldBindJSON(&requestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid JSON data"})
		return
	}

	sessionName := getUsernameSessionName(c)

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		// Session exists, check if it is running
		if session.isRunning {
			c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "tcpdump session is already running"})
			return
		}

		// Session exists and is not running, repopulate and restart
		session.tcpdumpOptionsFlag = requestData["tcpdump_options"]
		session.pcapFilename = baseDirFlag + "/" + requestData["pcap_filename"]
		if session.pcapFilename == baseDirFlag+"/" {
			session.pcapFilename = baseDirFlag + "/capture.pcap"
		}

		err := session.startTcpdump()

		if err == nil {
			c.JSON(http.StatusOK, gin.H{"status": "success", "message": "tcpdump session restarted", "pcap_filename": session.pcapFilename})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		}
		return
	}

	// Session does not exist, create a new session and start it
	newSession := NewTcpdumpSession(sessionName, baseDirFlag, requestData["pcap_filename"], requestData["tcpdump_options"])

	// Add the new session to the map
	tcpdumpSessions[sessionName] = *newSession

	// Start tcpdump command
	err := newSession.startTcpdump()
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "tcpdump session started", "pcap_filename": newSession.pcapFilename})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
	}
}

func getUsernameSessionName(c *gin.Context) string {
	username, _, hasAuth := c.Request.BasicAuth()
	sessionName, exists := c.GetPostForm("session_name")

	if !hasAuth || !exists {
		return "" // Return an empty string or handle as needed based on your requirements
	}

	return username + "." + sessionName
}

func (s *tcpdumpSession) startTcpdump() error {
	s.tcpdumpCmd = exec.Command("/usr/bin/tcpdump", strings.Fields(s.tcpdumpOptionsFlag)...)
	s.tcpdumpCmd.Args = append(s.tcpdumpCmd.Args, "-w", s.pcapFilename)

	if err := s.tcpdumpCmd.Start(); err != nil {
		log.Printf("Failed to start tcpdump for session %v: %v", s.pcapFilename, err)
		return err
	}

	s.isRunning = true
	s.StartTime = time.Now()
	s.stopTime = time.Time{}

	log.Printf("tcpdump started for session %v", s.pcapFilename)
	return nil
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

	sessionName := getUsernameSessionName(c)

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		// Session exists, check if it is running
		if session.isRunning {
			// Stop the tcpdump session
			err := session.stopTcpdump()

			if err == nil {
				c.JSON(http.StatusOK, gin.H{"status": "success", "message": "tcpdump session stopped"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			}
		} else {
			// Session exists but is not running
			c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "tcpdump session is not running"})
		}
		return
	}

	// Session does not exist
	c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "tcpdump session not found"})
}

func (s *tcpdumpSession) stopTcpdump() error {
	// Stop the tcpdump process
	if err := s.tcpdumpCmd.Process.Kill(); err != nil {
		log.Printf("Failed to stop tcpdump for session %v: %v", s.pcapFilename, err)
		return err
	}

	s.isRunning = false
	s.stopTime = time.Now()

	log.Printf("tcpdump stopped for session %v", s.pcapFilename)
	return nil
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

	sessionName := getUsernameSessionName(c)

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		// Session exists, check if it is running
		if session.isRunning {
			// Session is running, cannot download while running
			c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "tcpdump session is still running"})
			return
		}

		// Session exists and is not running, check if the pcap file exists
		if _, err := os.Stat(session.pcapFilename); os.IsNotExist(err) {
			// Pcap file not found
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Pcap file not found"})
			return
		}

		// Set the appropriate headers for downloading the file
		c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", session.pcapFilename))
		c.Writer.Header().Add("Content-Type", "application/octet-stream")

		// Send the file as the response
		c.File(session.pcapFilename)
		return
	}

	// Session does not exist
	c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "tcpdump session not found"})
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

	sessionName := getUsernameSessionName(c)

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		// Session exists, check if it is running
		if session.isRunning {
			// Session is running, cannot delete pcap file while running
			c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "tcpdump session is still running"})
			return
		}

		// Session exists and is not running, check if the pcap file exists
		if _, err := os.Stat(session.pcapFilename); os.IsNotExist(err) {
			// Pcap file not found
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Pcap file not found"})
			return
		}

		// Delete the pcap file
		if err := os.Remove(session.pcapFilename); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}

		delete(tcpdumpSessions, sessionName) // clear the session entry from session map

		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Pcap file deleted"})
		return
	}

	// Session does not exist
	c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "tcpdump session not found"})
}

func getFilesize(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	// Authenticate the user using RADIUS
	if !authenticateUser(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	sessionName := getUsernameSessionName(c)

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		// Session exists, check if the pcap file exists
		if _, err := os.Stat(session.pcapFilename); os.IsNotExist(err) {
			// Pcap file not found
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Pcap file not found"})
			return
		}

		// Get the size of the pcap file
		fileInfo, err := os.Stat(session.pcapFilename)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}

		fileSize := fileInfo.Size()

		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Pcap file size", "file_size": fileSize})
		return
	}

	// Session does not exist
	c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "tcpdump session not found"})
}

func getDuration(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	// Authenticate the user using RADIUS
	if !authenticateUser(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	// Get the sessionName from the request
	sessionName := getUsernameSessionName(c)

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		if session.isRunning {
			// Session is running, report session duration since startTime
			sessionDuration := time.Since(session.StartTime).String()
			c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Session is running", "session_duration": sessionDuration})
		} else {
			// Session is not running, check if stopTime is assigned
			if !session.stopTime.IsZero() {
				// stopTime is assigned, report session duration as stopTime - startTime
				sessionDuration := session.stopTime.Sub(session.StartTime).String()
				c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Session is not running", "session_duration": sessionDuration})
			} else {
				// stopTime is not assigned, report error as the session is not started yet
				c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Session has not started yet"})
			}
		}
	} else {
		// Session does not exist, report error to client
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Session not found"})
	}
}

func listSessions(c *gin.Context) {
	// Acquire the mutex to prevent concurrent access to tcpdumpSessions
	mutex.Lock()
	defer mutex.Unlock()

	// Authenticate the user using basic authentication
	if !authenticateUser(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	username, _, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Unauthorized"})
		return
	}

	// Create a list to store session details
	var sessionsList []gin.H

	// Iterate over tcpdumpSessions to find sessions started by the user
	for sessionName, session := range tcpdumpSessions {
		// Check if the sessionName starts with the RADIUS username
		if strings.HasPrefix(sessionName, username+".") {
			// Build a map with session details
			sessionDetails := gin.H{
				"session_name":    sessionName,
				"pcap_filename":   session.pcapFilename,
				"tcpdump_options": session.tcpdumpOptionsFlag,
				"is_running":      session.isRunning,
				"start_time":      session.StartTime,
				"stop_time":       session.stopTime,
			}

			// Append the session details to the list
			sessionsList = append(sessionsList, sessionDetails)
		}
	}

	// Return the list of sessions
	c.JSON(http.StatusOK, gin.H{"status": "success", "sessions": sessionsList})
}

func isRootUser() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0" || u.Gid == "0"
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
