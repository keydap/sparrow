// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import "crypto/x509"

type ConfigEvent struct {
	Csn  string
	Data []byte
}

type JoinEvent struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	ServerId int    `json:"serverId"`
}

type PendingJoinRequest struct {
	Host      string
	Port      int
	ServerId  int
	CertChain []*x509.Certificate
}
