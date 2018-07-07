// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package base

import ()

type AuditEvent struct {
	Id         string // CSN of the event
	Uri        string // URI of the endpoint
	ActorId    string // user's ID, can be null
	Operation  string // operation
	StatusCode int    // http status code
	Desc       string // description of the error
	IpAddress  string // ip address from where the related request was sent
	Payload    string // payload used for performing operation
}
