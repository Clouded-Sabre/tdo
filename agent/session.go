package main

import (
	"log"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// define Shell interface so tha we can easily mock shell command execution
type Shell interface {
	Execute(tcpdumpOptionsFlag, pcapFilename, sessionName string) (tcpdumpCmd *exec.Cmd, err error)
	ProcessKill(tcpdumpCmd *exec.Cmd, sessionName string) (err error)
	isProcessRunning(tcpdumpCmd *exec.Cmd) (isRunning bool, err error)
}

type LocalShell struct{}

func (LocalShell) Execute(tcpdumpOptionsFlag, pcapFilename, sessionName string) (tcpdumpCmd *exec.Cmd, err error) {
	tcpdumpCmd = exec.Command("/usr/bin/tcpdump", strings.Fields(tcpdumpOptionsFlag)...)
	tcpdumpCmd.Args = append(tcpdumpCmd.Args, "-w", pcapFilename)

	if err := tcpdumpCmd.Start(); err != nil {
		log.Printf("Failed to start tcpdump for session %v: %v", sessionName, err)
		return nil, err
	}

	return tcpdumpCmd, err
}

func (LocalShell) ProcessKill(tcpdumpCmd *exec.Cmd, sessionName string) (err error) {
	// Stop the tcpdump process
	pid := tcpdumpCmd.Process.Pid
	if err := tcpdumpCmd.Process.Kill(); err != nil {
		log.Printf("Failed to stop tcpdump for session %v: %v", sessionName, err)
		return err
	}

	// Wait for the process to exit
	_, err = tcpdumpCmd.Process.Wait()
	if err != nil {
		return err
	}

	// Sleep for a short duration to allow the operating system
	// to properly reap the process and avoid zombie status
	time.Sleep(100 * time.Millisecond)

	log.Printf("Successfully killed PID %d\n", pid)

	return nil
}

func (LocalShell) isProcessRunning(tcpdumpCmd *exec.Cmd) (bool, error) {
	process := tcpdumpCmd.Process

	err := process.Signal(syscall.Signal(0))
	if err != nil {
		log.Println("Process with PID", process.Pid, "is not running")
		return false, nil
	}

	log.Println("Process with PID", process.Pid, "is still running")
	return true, nil
}

var cmdShell Shell

type tcpdumpSession struct {
	tcpdumpCmd          *exec.Cmd
	isRunning           bool
	tcpdumpOptionsFlag  string
	pcapFilename        string
	StartTime, stopTime time.Time
}

func NewTcpdumpSession(name, baseDirFlag, pcapFilename, tcpdumpOptionsFlag string) *tcpdumpSession {
	session := &tcpdumpSession{
		isRunning:          false,
		tcpdumpOptionsFlag: tcpdumpOptionsFlag,
		pcapFilename:       pcapFilename,
		StartTime:          time.Time{}, // Zero value for time.Time indicates an uninitialized time
	}

	return session
}
