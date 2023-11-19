package main

import (
	"context"
	"log"

	"github.com/gin-gonic/gin"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

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
