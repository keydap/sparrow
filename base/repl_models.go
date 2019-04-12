// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import "net/url"

type DataType uint8

const (
	SERVER_CONFIG DataType = iota
	PROVIDER_CONFIG
	TEMPLATES
	RESOURCE_CREATE
	RESOURCE_PATCH
	RESOURCE_DELETE
)

type ReplicationEvent struct {
	Csn        string
	DomainCode string
	Type       DataType
	Data       []byte
	Res        *Resource
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
	Url             *url.URL
	WebHookToken    string
	SentBy          string
	Domain          string
	CreatedTime     int64
	LastCsn         string
	LastReqSentTime int64
}

type JoinResponse struct {
	PeerServerId     uint16            `json:"peerServerId" valid:"range(0|65535),required"`
	ApprovedBy       string            `json:"approvedBy" valid:"required"`
	PeerWebHookToken string            `json:"peerWebHookToken" valid:"required"`
	PeerView         []ReplicationPeer `json:"peerView"`
}
