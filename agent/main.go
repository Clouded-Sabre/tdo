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
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

var (
	mutex             sync.Mutex
	tcpdumpSessions   = make(map[string]*tcpdumpSession)
	baseDirFlag       string
	listenAddressFlag string
	sslCertPathFlag   string
	sslKeyPathFlag    string
	radius_secret     string
	radius_address    string
	testHttpsFlag     bool // enable/disable the test HTTPS endpoint
	ginInTesting      = true

	version string
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

	theRadiusClient = &radiusClient{}

	radius_secret = viper.GetString("radius.secret")
	radius_address = viper.GetString("radius.address")

	log.Println("Checking if RADIUS server is reachable......")
	if !isRadiusServerReachable() {
		log.Println("RADIUS server is not reachable. Please check!")
		os.Exit(0)
	}

	cmdShell = LocalShell{}

	// Create a Gin router
	if !ginInTesting {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	// Apply the BasicAuthMiddleware to all relevant routes in the group
	authGroup := r.Group("/", BasicAuthMiddleware)

	// Routes
	authGroup.POST("/v1/start_tcpdump", startTcpdump)
	authGroup.POST("/v1/stop_tcpdump", stopTcpdump)
	authGroup.GET("/v1/download_pcap", downloadPcap)
	authGroup.POST("/v1/delete_pcap", deletePcap)
	authGroup.GET("/v1/list_sessions", listSessions)
	authGroup.GET("/v1/get_filesize", getFilesize)          // report pcap file size
	authGroup.GET("/v1/get_duration", getDuration)          // report capture session duration
	authGroup.GET("/v1/get_storage_space", getStorageSpace) // report available storage space
	if testHttpsFlag {
		r.GET("/test_https", testHttps)           // for testing HTTPS
		authGroup.GET("/test_radius", testRadius) // for testing RADIUS+HTTPS
	}

	log.Println("Starting Gin Server......")

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

// BasicAuthMiddleware is a middleware function for basic authentication
func BasicAuthMiddleware(c *gin.Context) {
	_, _, ok := c.Request.BasicAuth()

	// Authenticate the user using your existing logic
	if !ok || !authenticateUser(c) {
		c.Header("WWW-Authenticate", "Basic realm=Restricted")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.Next()
}

func startTcpdump(c *gin.Context) {
	// Acquire the mutex to prevent concurrent start requests
	mutex.Lock()
	defer mutex.Unlock()

	var requestData map[string]string
	if err := c.ShouldBindJSON(&requestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid JSON data"})
		return
	}

	sessionName, err := getUsernameSessionName(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}

	pcapFilename := baseDirFlag + "/" + requestData["pcap_filename"]
	if pcapFilename == baseDirFlag+"/" {
		pcapFilename = baseDirFlag + "/capture.pcap"
	}

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		// Session exists, check if it is running
		if session.isRunning {
			c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "tcpdump session is already running"})
			return
		}

		// Session exists and is not running, repopulate and restart
		session.tcpdumpOptionsFlag = requestData["tcpdump_options"]
		session.pcapFilename = pcapFilename

		err := session.startTcpdump(sessionName)

		if err == nil {
			c.JSON(http.StatusOK, gin.H{"status": "success", "message": "tcpdump session restarted", "pcap_filename": session.pcapFilename})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		}
		return
	}

	// Session does not exist, create a new session and start it
	newSession := NewTcpdumpSession(sessionName, baseDirFlag, pcapFilename, requestData["tcpdump_options"])

	// Add the new session to the map
	tcpdumpSessions[sessionName] = newSession

	// Start tcpdump command
	err = newSession.startTcpdump(sessionName)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "tcpdump session started", "pcap_filename": newSession.pcapFilename})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
	}
}

func getUsernameSessionName(c *gin.Context) (string, error) {
	username, _, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		return "", errors.New("basic authentication is required")
	}

	// Try to get session_name from URL query parameters
	sessionName := c.Query("session_name")
	if sessionName == "" {
		return "", errors.New("session_name is required")
	}

	return username + "." + sessionName, nil
}

func (s *tcpdumpSession) startTcpdump(sessionName string) error {
	// start the tcpdump command
	tcpdumpCmd, err := cmdShell.Execute(s.tcpdumpOptionsFlag, s.pcapFilename, sessionName)
	if err != nil {
		log.Printf("Failed to start tcpdump for session %v: %v", sessionName, err)
		return err
	}

	// Sleep for a short duration to see if the process can sustain
	time.Sleep(100 * time.Millisecond)

	// check if tcpdump is actually running or not.
	isTcpdumpRunning, err := cmdShell.isProcessRunning(tcpdumpCmd)
	if err != nil {
		log.Println("Failed to check if tcpdump process is running.")
		log.Println("Error:", err.Error())
		return err
	} else {
		if isTcpdumpRunning {
			s.tcpdumpCmd = tcpdumpCmd
			s.isRunning = true
			s.StartTime = time.Now()
			s.stopTime = time.Time{}

			log.Printf("tcpdump started for session %v", sessionName)
			return nil
		} else {
			err = fmt.Errorf("tcpdump failed to start")
			return err
		}
	}
}

func stopTcpdump(c *gin.Context) {
	// Acquire the mutex to prevent concurrent stop requests
	mutex.Lock()
	defer mutex.Unlock()

	sessionName, err := getUsernameSessionName(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		// Session exists, check if it is running
		if session.isRunning {
			// Stop the tcpdump session
			err := session.stopTcpdump(sessionName)

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
	c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "tcpdump session not found"})
}

func (s *tcpdumpSession) stopTcpdump(sessionName string) error {
	// Stop the tcpdump process
	if err := cmdShell.ProcessKill(s.tcpdumpCmd, sessionName); err != nil {
		log.Printf("Failed to stop tcpdump for session %v: %v", sessionName, err)
		return err
	}

	s.isRunning = false
	s.stopTime = time.Now()

	log.Printf("tcpdump stopped for session %v", sessionName)
	return nil
}

func downloadPcap(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	sessionName, err := getUsernameSessionName(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}

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
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Pcap file not found"})
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
	c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "tcpdump session not found"})
}

func deletePcap(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	sessionName, err := getUsernameSessionName(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}

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
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Pcap file not found"})
			return
		}

		// Delete the pcap file
		if err := os.Remove(session.pcapFilename); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Error while deleting the pcapfile: " + err.Error()})
			return
		}

		delete(tcpdumpSessions, sessionName) // clear the session entry from session map

		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Pcap file deleted"})
		return
	}

	// Session does not exist
	c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "tcpdump session not found"})
}

func getFilesize(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	sessionName, err := getUsernameSessionName(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}

	// Check if the session exists
	if session, exists := tcpdumpSessions[sessionName]; exists {
		// Session exists, check if the pcap file exists
		if _, err := os.Stat(session.pcapFilename); os.IsNotExist(err) {
			// Pcap file not found
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Pcap file not found"})
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
	c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "tcpdump session not found"})
}

func getDuration(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	// Get the sessionName from the request
	sessionName, err := getUsernameSessionName(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}

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
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Session not found"})
	}
}

func listSessions(c *gin.Context) {
	// Acquire the mutex to prevent concurrent access to tcpdumpSessions
	mutex.Lock()
	defer mutex.Unlock()

	username, _, _ := c.Request.BasicAuth()

	// Create a list to store session details
	var sessionsList []*gin.H

	//fmt.Println("The number of sessions in the map is", len(tcpdumpSessions))
	// Iterate over tcpdumpSessions to find sessions started by the user
	for sessionName, session := range tcpdumpSessions {
		//fmt.Printf("sessionName = %q, session = %+v\n", sessionName, session)
		// Check if the sessionName starts with the RADIUS username
		if strings.HasPrefix(sessionName, username+".") {
			// Build a map with session details
			//fmt.Println("Got", sessionName)
			sessionDetails := &gin.H{
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

// Function to report available storage space on the volume where baseDir is located
func getStorageSpace(c *gin.Context) {
	// Acquire the mutex to prevent concurrent requests
	mutex.Lock()
	defer mutex.Unlock()

	// Get the baseDir path
	baseDir := baseDirFlag

	// Get the volume path for baseDir
	volumePath := getVolumePath(baseDir)

	// Get the available space on the volume
	availableSpaceMB, err := getAvailableSpaceMB(volumePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Available storage space in MB", "available_space_mb": availableSpaceMB})
}

// Function to get the volume path for a given directory
func getVolumePath(dir string) string {
	volumePath := dir
	if filepath.IsAbs(dir) {
		volumePath = filepath.VolumeName(dir)
	}
	return volumePath
}

// Function to get the available space in MB on a volume
func getAvailableSpaceMB(volumePath string) (float64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(volumePath, &stat)
	if err != nil {
		return 0, err
	}

	// Calculate available space in MB
	availableSpaceMB := float64(stat.Bavail*uint64(stat.Bsize)) / (1024 * 1024)
	return availableSpaceMB, nil
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
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Test RADIUS communication successful"})
}
