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
