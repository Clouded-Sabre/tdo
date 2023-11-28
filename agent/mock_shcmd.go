package main

import (
	"os/exec"
)

// MockShell A shell implementation for testing.
// It always returns determinitistic results.
type MockShell struct {
	isPidRunning bool
	// an output and error to be returned when command is executed
	//Output []byte
	Err error
}

func (t *MockShell) Execute(tcpdumpOptionsFlag, pcapFilename, sessionName string) (tcpdumpCmd *exec.Cmd, err error) {
	return nil, t.Err
}

func (t *MockShell) ProcessKill(tcpdumpCmd *exec.Cmd, sessionName string) error {
	return t.Err
}

func (t *MockShell) isProcessRunning(tcpdumpCmd *exec.Cmd) (isRunning bool, err error) {
	return t.isPidRunning, t.Err
}
