// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"time"
)

type LoginStatus int

const (
	LOGIN_BEGIN LoginStatus = iota // default is set to before login state
	LOGIN_USER_NOT_FOUND
	LOGIN_ACCOUNT_NOT_ACTIVE
	LOGIN_NO_PASSWORD
	LOGIN_FAILED
	LOGIN_TFA_REQUIRED
	LOGIN_TFA_REGISTER
	LOGIN_CHANGE_PASSWORD
	LOGIN_SUCCESS
)

// struct holding TFA credentials and details about last successful and failed login attempts
type AuthData struct {
	TotpSecret  string
	TotpCodes   map[string]bool
	LastSLogin  time.Time
	LastFLogin  time.Time
	FLoginCount int
	Skeys       map[string]*SecurityKey
	WebauthnId  string // a special unique identifier that links user on the authenticator
}

type SecurityKey struct {
	DeviceId       string              `json:"deviceId"`     // AAGUID
	CredentialId   string              `json:"credentialId"` // the unique ID of this credential
	Fmt            string              `json:"fmt"`
	SignCount      uint32              `json:"-"`
	PubKeyCOSE     map[int]interface{} `json:"-"`
	RegisteredDate int64               `json:"registeredDate"`
	LastUsedDate   int64               `json:"lastUsedDate"`
}

type LoginResult struct {
	User   *Resource // user is non-nil only if the authentication is successful
	Id     string    // user resource's ID will always be present unless the user is not found
	Status LoginStatus
}
