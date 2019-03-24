// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

type ConfigEvent struct {
	Csn  string
	Data []byte
}

type JoinRequest struct {
	Host         string `json:"host" valid:"ascii,required"`
	Port         int    `json:"port" valid:"range(1|65535),required"`
	ServerId     uint16 `json:"serverId" valid:"range(0|65535),required"`
	WebHookToken string `json:"webHookToken" valid:"required"`
	SentBy       string `json:"sentBy" valid:"required"`
	Domain       string `json:"domain" valid:"required"`
	CreatedTime  int64  `json:"createdTime"`
}

type ReplicationPeer struct {
	ServerId        uint16
	Url             string
	WebHookToken    string
	SentBy          string
	Domain          string
	CreatedTime     int64
	LastReqSentTime int64
}

type JoinResponse struct {
	ApprovedBy       string
	PeerWebHookToken string
	PeerView         []ReplicationPeer
}
