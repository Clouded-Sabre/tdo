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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestTestHttps(t *testing.T) {
	// Create a test context
	context, _ := gin.CreateTestContext(httptest.NewRecorder())

	// Create a test request
	req, err := http.NewRequest("GET", "/test_https", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set any headers or other properties on the request if needed

	// Assign the request to the context
	context.Request = req

	// Call the testHttps function
	testHttps(context)

	// Now you can assert on the response or other expectations
	if context.Writer.Status() != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, context.Writer.Status())
	}

	// Add more assertions as needed
}

func TestBasicAuthMiddleware_Success(t *testing.T) {
	// Create a test context
	context, _ := gin.CreateTestContext(httptest.NewRecorder())

	// Set up a test request with valid basic authentication headers
	username := "testuser"
	password := "testpassword"
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	req, _ := http.NewRequest("GET", "/test_radius", nil)
	req.Header.Set("Authorization", authHeader)

	// Assign the request to the context
	context.Request = req

	// Call the middleware
	BasicAuthMiddleware(context)

	// Assert that the status code is http.StatusOK
	assert.Equal(t, http.StatusOK, context.Writer.Status())
}

func TestBasicAuthMiddleware_Failure(t *testing.T) {
	// Create a test context
	context, _ := gin.CreateTestContext(httptest.NewRecorder())

	// Set up a test request without valid basic authentication headers
	req, _ := http.NewRequest("GET", "/test_radius", nil)

	// Assign the request to the context
	context.Request = req

	// Call the middleware
	BasicAuthMiddleware(context)

	// Assert that the status code is http.StatusUnauthorized
	assert.Equal(t, http.StatusUnauthorized, context.Writer.Status())
}

func TestBasicAuthMiddleware_InvalidCredentials(t *testing.T) {
	// Create a test context
	context, _ := gin.CreateTestContext(httptest.NewRecorder())

	// Set up a test request with invalid basic authentication headers
	username := "invaliduser"
	password := "invalidpassword"
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	req, _ := http.NewRequest("GET", "/test_radius", nil)
	req.Header.Set("Authorization", authHeader)

	// Assign the request to the context
	context.Request = req

	// Call the middleware
	BasicAuthMiddleware(context)

	// Assert that the status code is http.StatusUnauthorized
	assert.Equal(t, http.StatusUnauthorized, context.Writer.Status())
}

func TestStartTcpdump_NewSessionSuccess(t *testing.T) {
	// Mock the exec.Command function
	mockCommand := &MockShell{
		isPidRunning: true,
		Err:          nil,
	}
	cmdShell = mockCommand

	sessionName := "mySession"
	fullSessionName := radiusUsername + "." + sessionName
	delete(tcpdumpSessions, fullSessionName) // Ensure the session is not in the map

	// Request data
	requestData := map[string]interface{}{
		"pcap_filename":   "capture.pcap",
		"tcpdump_options": "-i eth0",
	}

	requestBody, err := json.Marshal(requestData)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	// Create a dummy gin context
	w := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(w)

	// Set up a dummy request
	req := httptest.NewRequest("POST", "/start_tcpdump?session_name="+sessionName, bytes.NewBuffer(requestBody))
	req.SetBasicAuth(radiusUsername, radiusPassword)
	req.Header.Set("Content-Type", "application/json")

	// Set the request in the gin context
	context.Request = req

	// Call the function that starts tcpdump
	startTcpdump(context)

	// Check the status code in the test response recorder
	statusCode := w.Code
	assert.Equal(t, http.StatusOK, statusCode)

	// Parse the response body
	var responseBody map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &responseBody)
	if err != nil {
		t.Fatal("Error unmarshaling JSON response:", err)
	}

	// Check that the "status" key is set to "success"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "success", actualStatus)
}

func TestStartTcpdump_NewSessionFailure(t *testing.T) {
	// Mock the exec.Command function
	mockCommand := &MockShell{
		isPidRunning: false,
		Err:          fmt.Errorf("Cannot find the command"),
	}
	cmdShell = mockCommand

	sessionName := "mySession1"
	fullSessionName := radiusUsername + "." + sessionName
	delete(tcpdumpSessions, fullSessionName) // Ensure the session is not in the map

	// Request data
	requestData := map[string]interface{}{
		"pcap_filename":   "capture.pcap",
		"tcpdump_options": "-i eth0",
	}

	requestBody, err := json.Marshal(requestData)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	// Create a dummy gin context
	w := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(w)

	// Set up a dummy request
	req := httptest.NewRequest("POST", "/start_tcpdump?session_name="+sessionName, bytes.NewBuffer(requestBody))
	req.SetBasicAuth(radiusUsername, radiusPassword)
	req.Header.Set("Content-Type", "application/json")

	// Set the request in the gin context
	context.Request = req

	// Call the function that starts tcpdump
	startTcpdump(context)

	// Check the status code in the test response recorder
	statusCode := w.Code
	assert.Equal(t, http.StatusInternalServerError, statusCode)
}

func TestStartTcpdump_SessionAlreadyRunning(t *testing.T) {
	// Create a dummy session that is already running
	sessionName := "runningSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning: true,
	}

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/start_tcpdump?session_name="+sessionName, strings.NewReader(`{"pcap_filename": "capture.pcap", "tcpdump_options": "-i eth0"}`))
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the startTcpdump function
	startTcpdump(context)

	// Check if it responds with a conflict status
	assert.Equal(t, http.StatusConflict, context.Writer.Status())
	// Add more assertions if needed
}

func TestStartTcpdump_SessionStopped(t *testing.T) {
	// Mock the exec.Command function
	mockCommand := &MockShell{
		isPidRunning: true,
		Err:          nil,
	}
	cmdShell = mockCommand

	// Create a dummy session that is not running
	sessionName := "notRunningSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning: false,
	}

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/start_tcpdump?session_name="+sessionName, strings.NewReader(`{"pcap_filename": "capture.pcap", "tcpdump_options": "-i eth0"}`))
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the startTcpdump function
	startTcpdump(context)

	// Check if it responds with a success status
	assert.Equal(t, http.StatusOK, context.Writer.Status())
	// Add more assertions if needed
}

func TestStartTcpdump_InvalidJSON(t *testing.T) {
	// Create a test context with invalid JSON data
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/start_tcpdump?session_name=test1", strings.NewReader("invalidJSONData"))
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the startTcpdump function
	startTcpdump(context)

	// Check if it responds with a bad request status
	assert.Equal(t, http.StatusBadRequest, context.Writer.Status())
	// Add more assertions if needed
}

func TestStartTcpdump_TcpdumpFailure(t *testing.T) {
	sessionName := "mySession"
	fullSessionName := radiusUsername + "." + sessionName
	delete(tcpdumpSessions, fullSessionName) // Ensure the session is not in the map

	// Mock the exec.Command function
	mockCommand := &MockShell{
		isPidRunning: false,
		Err:          fmt.Errorf("Tcpdump failed to start"),
	}
	cmdShell = mockCommand

	// Create a test context with valid JSON data
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/start_tcpdump?session_name="+sessionName, strings.NewReader(`{"pcap_filename": "capture.pcap", "tcpdump_options": "-i eth0"}`))
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the startTcpdump function
	startTcpdump(context)

	// Check if it responds with an internal server error
	assert.Equal(t, http.StatusInternalServerError, context.Writer.Status())
	// Add more assertions if needed
}

func TestStopTcpdump_Success(t *testing.T) {
	cmdShell = &MockShell{
		isPidRunning: true,
		// an output and error to be returned when command is executed
		//Output []byte
		Err: nil,
	}

	// Create a dummy session that is running
	sessionName := "runningSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning: true,
	}

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/stop_tcpdump?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the stopTcpdump function
	stopTcpdump(context)

	// Check if it responds with a success status
	assert.Equal(t, http.StatusOK, context.Writer.Status())
	// Add more assertions if needed
}

func TestStopTcpdump_SessionNotRunning(t *testing.T) {
	// Create a dummy session that is not running
	sessionName := "notRunningSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning: false,
	}

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/stop_tcpdump?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the stopTcpdump function
	stopTcpdump(context)

	// Check if it responds with a conflict status
	assert.Equal(t, http.StatusConflict, context.Writer.Status())
	// Add more assertions if needed
}

func TestStopTcpdump_SessionNotFound(t *testing.T) {
	// Create a test context with an invalid session name
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/stop_tcpdump?session_name=nonexistentSession", nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the stopTcpdump function
	stopTcpdump(context)

	// Check if it responds with an internal server error
	assert.Equal(t, http.StatusInternalServerError, context.Writer.Status())
	// Add more assertions if needed
}

func TestDownloadPcap_Success(t *testing.T) {
	// Ensure that the pcap file exists or create it
	pcapFilename := "test_session.pcap"
	if _, err := os.Stat(pcapFilename); os.IsNotExist(err) {
		// Create an empty pcap file
		file, err := os.Create(pcapFilename)
		if err != nil {
			t.Fatalf("Error creating pcap file: %v", err)
		}
		defer file.Close()
	}

	// Initialize the tcpdumpSessions map with a dummy session
	sessionName := "testSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		pcapFilename: pcapFilename,
		isRunning:    false,
	}

	// Create a dummy gin context
	w := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(w)

	// Set up a dummy request
	req := httptest.NewRequest("GET", "/download_pcap?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	// Set the request in the gin context
	context.Request = req

	// Call the function that downloads the pcap file
	downloadPcap(context)

	// Check the status code in the test response recorder
	statusCode := w.Code
	assert.Equal(t, http.StatusOK, statusCode)

	// Add more assertions as needed
}

func TestDownloadPcap_SessionNotFound(t *testing.T) {
	// Create a test context
	w := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(w)

	// Set up a test request with a non-existent session name
	sessionName := "nonExistentSession"
	req, _ := http.NewRequest("GET", "/download_pcap?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	// Set the session name in the query parameter
	q := req.URL.Query()
	q.Add("session_name", sessionName)
	req.URL.RawQuery = q.Encode()

	// Assign the request to the context
	context.Request = req

	// Call the downloadPcap function
	downloadPcap(context)

	// Assert that the status code is http.StatusNotFound
	assert.Equal(t, http.StatusInternalServerError, context.Writer.Status())

	// Check the response body for the error message
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	if err != nil {
		t.Fatal("Error unmarshaling JSON response:", err)
	}

	expectedMessage := "tcpdump session not found"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, expectedMessage, actualMessage)
}

func TestDownloadPcap_FileNotFound(t *testing.T) {
	// Set up the test environment
	sessionName := "testSession"
	pcapFilename := "nonexistent.pcap"
	fullSessionName := radiusUsername + "." + sessionName

	// Remove the file if it exists
	_ = os.Remove(pcapFilename)

	// Add the session entry in tcpdumpSessions
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		pcapFilename: pcapFilename,
		isRunning:    false,
	}

	// Create a dummy gin context
	w := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(w)

	// Set up a dummy request
	req := httptest.NewRequest("GET", "/download_pcap?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	// Set the request in the gin context
	context.Request = req

	// Call the downloadPcap function
	downloadPcap(context)

	// Check the status code in the test response recorder
	statusCode := w.Code
	assert.Equal(t, http.StatusInternalServerError, statusCode)

	// Parse the response body
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	assert.NoError(t, err, "Error unmarshaling JSON response")

	// Check that the "status" key is set to "error"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "error", actualStatus)

	// Check the expected error message
	expectedMessage := "Pcap file not found"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, expectedMessage, actualMessage)
}

func TestDownloadPcap_SessionRunning(t *testing.T) {
	// Set up the test environment
	sessionName := "testSession"
	pcapFilename := "testSession.pcap"
	fullSessionName := radiusUsername + "." + sessionName

	// Add the session entry in tcpdumpSessions
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		pcapFilename: pcapFilename,
		isRunning:    true,
	}

	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with valid authentication
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/download_pcap?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	// Assign the request to the context
	context.Request = req

	// Call the downloadPcap function
	downloadPcap(context)

	// Assert that the status code is http.StatusConflict
	assert.Equal(t, http.StatusConflict, w.Code)

	// Parse the response body
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	assert.NoError(t, err, "Error unmarshaling JSON response")

	// Check that the "status" key is set to "error"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "error", actualStatus)

	// Check that the "message" key contains the expected error message
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Contains(t, actualMessage, "tcpdump session is still running")

	// Remove the mock session from tcpdumpSessions
	delete(tcpdumpSessions, fullSessionName)
	// Add more assertions if needed
}

func TestDeletePcap_Success(t *testing.T) {
	// Ensure that the pcap file exists or create it
	pcapFilename := "validSession.pcap"
	if _, err := os.Stat(pcapFilename); os.IsNotExist(err) {
		// Create an empty pcap file
		file, err := os.Create(pcapFilename)
		if err != nil {
			t.Fatalf("Error creating pcap file: %v", err)
		}
		defer file.Close()
	}

	// Set up a dummy session
	sessionName := "validSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning:    false,
		pcapFilename: pcapFilename,
	}

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/delete_pcap?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the deletePcap function
	deletePcap(context)

	// Check if it responds with a success status
	assert.Equal(t, http.StatusOK, context.Writer.Status())
	// Add more assertions if needed
}

func TestDeletePcap_SessionNotFound(t *testing.T) {
	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with an invalid session name
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("DELETE", "/delete_pcap?session_name=nonexistentSession", nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)
	context.Request = req

	// Call the deletePcap function
	deletePcap(context)

	// Check if it responds with a "session not found" error
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the error message
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	if err != nil {
		t.Fatal("Error unmarshaling JSON response:", err)
	}

	expectedMessage := "tcpdump session not found"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, expectedMessage, actualMessage)

	// Add more assertions if needed
}

func TestDeletePcap_PcapFileNotFound(t *testing.T) {
	// Set up a dummy session without creating a pcap file
	sessionName := "noPcapSession"
	pcapFilename := "nonexistent.pcap"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning:    false,
		pcapFilename: pcapFilename,
	}

	// Remove the file if it exists
	_ = os.Remove(pcapFilename)

	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("POST", "/delete_pcap?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the deletePcap function
	deletePcap(context)

	// Check if it responds with a "pcap file not found" error
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the error message
	var responseBody map[string]interface{}
	fmt.Println(w.Body.String())
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	if err != nil {
		t.Fatal("Error unmarshaling JSON response:", err)
	}

	expectedMessage := "Pcap file not found"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, expectedMessage, actualMessage)

	// Add more assertions if needed
}

func TestDeletePcap_SessionRunning(t *testing.T) {
	// Set up a dummy session with isRunning=true
	sessionName := "runningSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning:    true,
		pcapFilename: "runningSession.pcap",
	}

	// Create a test context with a valid session name
	w := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("POST", "/delete_pcap?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the deletePcap function
	deletePcap(context)

	// Check if it responds with a "session is still running" error
	assert.Equal(t, http.StatusConflict, context.Writer.Status())
	// Add more assertions if needed
}

func TestGetFilesize_Success(t *testing.T) {
	// Create a larger pcap file for testing
	pcapFilename := "test_session.pcap"
	content := []byte("Sample pcap content...") // You can add more content here
	err := os.WriteFile(pcapFilename, content, 0644)
	if err != nil {
		t.Fatalf("Error creating pcap file: %v", err)
	}
	defer os.Remove(pcapFilename)

	// Initialize the tcpdumpSessions map with a dummy session
	sessionName := "testSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		pcapFilename: pcapFilename,
		isRunning:    false,
	}

	// Create a dummy gin context
	w := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(w)

	// Set up a dummy request
	req := httptest.NewRequest("GET", "/get_filesize?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	// Set the request in the gin context
	context.Request = req

	// Call the function that retrieves the file size
	getFilesize(context)

	// Check the status code in the test response recorder
	statusCode := w.Code
	assert.Equal(t, http.StatusOK, statusCode)

	// Parse the response body
	var responseBody map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &responseBody)
	if err != nil {
		t.Fatal("Error unmarshaling JSON response:", err)
	}

	// Check that the "status" key is set to "success"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "success", actualStatus)

	// Check the reported file size
	fileSize, ok := responseBody["file_size"].(float64)
	assert.True(t, ok, "Failed to get file_size key from response")
	assert.Greater(t, fileSize, float64(0), "File size should be greater than 0")
}

func TestGetFilesize_SessionNotFound(t *testing.T) {
	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with an invalid session name
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/get_filesize?session_name=nonexistentSession", nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)
	context.Request = req

	// Call the getFilesize function
	getFilesize(context)

	// Check if it responds with a "session not found" error
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the error message
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	if err != nil {
		t.Fatal("Error unmarshaling JSON response:", err)
	}

	expectedMessage := "tcpdump session not found"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, expectedMessage, actualMessage)

	// Add more assertions if needed
}

func TestGetFilesize_PcapFileNotFound(t *testing.T) {
	// Set up a dummy session without creating a pcap file
	sessionName := "noPcapSession"
	pcapFilename := "nonexistent.pcap"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning:    false,
		pcapFilename: pcapFilename,
	}

	// Remove the file if it exists
	_ = os.Remove(pcapFilename)

	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/get_filesize?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the getFilesize function
	getFilesize(context)

	// Check if it responds with a "pcap file not found" error
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the error message
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	if err != nil {
		t.Fatal("Error unmarshaling JSON response:", err)
	}

	expectedMessage := "Pcap file not found"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, expectedMessage, actualMessage)

	// Add more assertions if needed
}

func TestGetDuration_SessionRunning(t *testing.T) {
	// Set up a dummy session that is currently running
	sessionName := "runningSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning: true,
		StartTime: time.Now().Add(-time.Hour), // Set a start time in the past
		stopTime:  time.Time{},                // Stop time not set
	}

	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/get_duration?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the getDuration function
	getDuration(context)

	// Check if it responds with success status
	assert.Equal(t, http.StatusOK, w.Code)

	// Check the response body for the session duration
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	assert.NoError(t, err, "Error unmarshaling JSON response")

	// Ensure that the "status" key is set to "success"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "success", actualStatus)

	// Ensure that the "message" key is set to "Session is running"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, "Session is running", actualMessage)

	// Ensure that the "session_duration" key is present
	_, ok = responseBody["session_duration"]
	assert.True(t, ok, "Failed to get session_duration key from response")
	// Add more assertions if needed
}

func TestGetDuration_SessionNotRunningWithDuration(t *testing.T) {
	// Set up a dummy session that is not currently running but has a duration
	sessionName := "notRunningSessionWithDuration"
	fullSessionName := radiusUsername + "." + sessionName
	startTime := time.Now().Add(-time.Hour)
	stopTime := startTime.Add(time.Minute * 30) // Set a stop time in the past
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		isRunning: false,
		StartTime: startTime,
		stopTime:  stopTime,
	}

	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with a valid session name
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/get_duration?session_name="+sessionName, nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	context.Request = req

	// Call the getDuration function
	getDuration(context)

	// Check if it responds with success status
	assert.Equal(t, http.StatusOK, w.Code)

	// Check the response body for the session duration
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	assert.NoError(t, err, "Error unmarshaling JSON response")

	// Ensure that the "status" key is set to "success"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "success", actualStatus)

	// Ensure that the "message" key is set to "Session is not running"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, "Session is not running", actualMessage)

	// Ensure that the "session_duration" key is present
	_, ok = responseBody["session_duration"]
	assert.True(t, ok, "Failed to get session_duration key from response")
	// Add more assertions if needed
}

func TestGetDuration_SessionNotFound(t *testing.T) {
	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with an invalid session name
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/get_duration?session_name=nonexistentSession", nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	// Set the session name in the query parameter
	q := req.URL.Query()
	q.Add("session_name", "nonexistentSession")
	req.URL.RawQuery = q.Encode()

	// Assign the request to the context
	context.Request = req

	// Call the getDuration function
	getDuration(context)

	// Assert that the status code is http.StatusInternalServerError
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Check the response body for the error message
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	assert.NoError(t, err, "Error unmarshaling JSON response")

	expectedMessage := "Session not found"
	actualMessage, ok := responseBody["message"].(string)
	assert.True(t, ok, "Failed to get message key from response")
	assert.Equal(t, expectedMessage, actualMessage)

	// Add more assertions if needed
}

func TestListSessions_Success(t *testing.T) {
	// Set up a dummy session
	sessionName := "testSession"
	fullSessionName := radiusUsername + "." + sessionName
	tcpdumpSessions[fullSessionName] = &tcpdumpSession{
		pcapFilename:       "testSession.pcap",
		tcpdumpOptionsFlag: "-i eth0",
		isRunning:          true,
		StartTime:          time.Now().Add(-time.Minute),
		stopTime:           time.Now(),
	}

	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with valid authentication
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/list_sessions", nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	// Assign the request to the context
	context.Request = req

	// Call the listSessions function
	listSessions(context)

	// Assert that the status code is http.StatusOK
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	assert.NoError(t, err, "Error unmarshaling JSON response")

	// Check that the "status" key is set to "success"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "success", actualStatus)

	// Check the response body for the list of sessions
	sessionsList, ok := responseBody["sessions"].([]interface{})
	assert.True(t, ok, "Failed to get sessions key from response")

	// Assert that there is at least one session in the list
	assert.NotEmpty(t, sessionsList)

	// Add more assertions if needed
}

func TestListSessions_NoSessions(t *testing.T) {
	// set tcpdumpSession to empty
	tcpdumpSessions = make(map[string]*tcpdumpSession)

	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context with valid authentication
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/list_sessions", nil)
	req.SetBasicAuth(radiusUsername, radiusPassword)

	// Assign the request to the context
	context.Request = req

	// Call the listSessions function
	listSessions(context)

	// Assert that the status code is http.StatusOK
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	assert.NoError(t, err, "Error unmarshaling JSON response")

	// Check that the "status" key is set to "success"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "success", actualStatus)

	// Check if the "sessions" key is present in the response
	sessionsList, ok := responseBody["sessions"]
	// Check if the "sessions" key is absent in the response
	assert.True(t, ok, "Failed to get sessions key from response")

	// If "sessions" key is present, assert that it is null
	assert.Nil(t, sessionsList)
	// Add more assertions if needed
}

func TestGetStorageSpace_Success(t *testing.T) {
	// Create a recorder to capture the HTTP response
	w := httptest.NewRecorder()

	// Create a test context
	context, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest("GET", "/get_storage_space", nil)

	// Assign the request to the context
	context.Request = req

	// Call the getStorageSpace function
	getStorageSpace(context)

	// Assert that the status code is http.StatusOK
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	assert.NoError(t, err, "Error unmarshaling JSON response")

	fmt.Println("Response is:", responseBody)
	// Check that the "status" key is set to "success"
	actualStatus, ok := responseBody["status"].(string)
	assert.True(t, ok, "Failed to get status key from response")
	assert.Equal(t, "success", actualStatus)

	// Check if the "available_space_mb" key is present in the response
	availableSpaceMB, ok := responseBody["available_space_mb"]
	assert.True(t, ok, "Failed to get available_space_mb key from response")

	// Assert that the available space is a non-negative integer (this depends on your actual expected behavior)
	assert.GreaterOrEqual(t, availableSpaceMB, 0.0)
}

func TestGetVolumePath_Linux(t *testing.T) {
	// Test with an absolute path
	absPath := "/home/user/documents"
	volumePath := getVolumePath(absPath)
	assert.Equal(t, "", volumePath, "Linux systems don't have drive letters, so volume path should be empty for absolute paths")

	// Test with a relative path
	relPath := "relative/path"
	volumePath = getVolumePath(relPath)
	assert.Equal(t, relPath, volumePath, "Volume path for a relative path should be the same as the input path")
}

func TestGetAvailableSpaceMB(t *testing.T) {
	// Replace "/path/to/volume" with the actual path to the volume you want to test
	volumePath := "/"

	// Call the function to get available space
	availableSpaceMB, err := getAvailableSpaceMB(volumePath)

	// Check if there is any error
	assert.NoError(t, err, "Unexpected error while getting available space")

	// Check if available space is greater than or equal to 0
	assert.GreaterOrEqual(t, availableSpaceMB, float64(0), "Available space should be greater than or equal to 0")
}

func TestGetAvailableSpaceMB_Error(t *testing.T) {
	// Call the function to get available space with a non-existent path
	nonExistentPath := "/nonexistentpath"
	availableSpaceMB, err := getAvailableSpaceMB(nonExistentPath)

	// Check if an error is returned
	assert.Error(t, err, "Expected an error")
	assert.Equal(t, float64(0), availableSpaceMB, "Expected available space to be 0")
}

func TestGetUsernameSessionName_Success(t *testing.T) {
	// Create a test context with valid authentication and session_name in query parameters
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("GET", "/some_endpoint?session_name=mySession", nil)
	req.SetBasicAuth("testuser", "testpassword")
	context.Request = req

	// Call the function
	result, err := getUsernameSessionName(context)

	// Check the result and error
	assert.NoError(t, err, "Unexpected error")
	assert.Equal(t, "testuser.mySession", result, "Unexpected result")
}

func TestGetUsernameSessionName_MissingAuthentication(t *testing.T) {
	// Create a test context without authentication
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("GET", "/some_endpoint?session_name=mySession", nil)
	context.Request = req

	// Call the function
	_, err := getUsernameSessionName(context)

	// Check for the expected error
	assert.Error(t, err, "Expected an error")
	assert.Equal(t, "basic authentication is required", err.Error(), "Unexpected error message")
}

func TestGetUsernameSessionName_MissingSessionName(t *testing.T) {
	// Create a test context with valid authentication but missing session_name in query parameters
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("GET", "/some_endpoint", nil)
	req.SetBasicAuth("testuser", "testpassword")
	context.Request = req

	// Call the function
	_, err := getUsernameSessionName(context)

	// Check for the expected error
	assert.Error(t, err, "Expected an error")
	assert.Equal(t, "session_name is required", err.Error(), "Unexpected error message")
}

func TestMain(m *testing.M) {
	fmt.Println("Setting up test env")
	// Set up default mock configurations
	mockRadiusClient := &MockRadiusClient{
		Err: nil,
	}

	theRadiusClient = mockRadiusClient

	radius_address = "127.0.0.1:1812"
	radius_secret = "testing123"

	radiusUsername = "testuser"
	radiusPassword = "testpassword"

	baseDirFlag = "."
	// Run the tests
	fmt.Println("Start testing now")
	exitCode := m.Run()

	// Clean up or perform any additional actions if needed

	// Exit with the test result code
	os.Exit(exitCode)
}
