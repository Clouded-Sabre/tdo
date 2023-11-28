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
