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
	"context"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

var (
	radiusUsername, radiusPassword string
)

// MockRadiuClient mock real radius client
// It always returns determinitistic results.
type MockRadiusClient struct {
	Err error
}

func (r *MockRadiusClient) Exchange(ctx context.Context, packet *radius.Packet, radiusAddress string) (response *radius.Packet, err error) {
	// Extract username and password attributes from the packet
	username := rfc2865.UserName_GetString(packet)
	password := rfc2865.UserPassword_GetString(packet)

	// Check if the received username and password match the predefined values
	if username == radiusUsername && password == radiusPassword {
		// If the credentials match, return an "accept" response
		return &radius.Packet{Code: radius.CodeAccessAccept}, r.Err
	}

	// If the credentials don't match, return a "reject" response
	return &radius.Packet{Code: radius.CodeAccessReject}, r.Err
}
