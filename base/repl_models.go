// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import "crypto/x509"

type ConfigEvent struct {
	Csn  string
	Data []byte
}

type JoinEvent struct {
	Host     string `json:"host" valid:"ascii,required"`
	Port     int    `json:"port" valid:"range(1|65535),required"`
	ServerId int    `json:"serverId" valid:"range(0|65535),required"`
}

type PendingJoinRequest struct {
	Host        string
	Port        int
	ServerId    int
	RequestTime int64
	CertChain   []*x509.Certificate
}
