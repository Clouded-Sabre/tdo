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
