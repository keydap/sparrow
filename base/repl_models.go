// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import "net/url"

type DataType uint8

const HEADER_X_FROM_PEER_ID = "X-From-Peer-Id"
const HEADER_X_WEBHOOK_TOKEN = "X-Webhook-Token"

const (
	SERVER_CONFIG DataType = iota
	PROVIDER_CONFIG
	TEMPLATES
	RESOURCE_CREATE
	RESOURCE_PATCH
	RESOURCE_REPLACE
	RESOURCE_DELETE
)

type ReplicationEvent struct {
	Version      string
	DomainCode   string
	Type         DataType
	Data         []byte
	CreatedRes   *Resource
	PatchIfMatch string
	PatchRid     string
	RtName       string
	DelRid       string
	ResToReplace *Resource
}

type JoinRequest struct {
	Host         string `json:"host" valid:"ascii,required"`
	Port         int    `json:"port" valid:"range(1|65535),required"`
	ServerId     uint16 `json:"serverId" valid:"range(0|65535),required"`
	WebHookToken string `json:"webHookToken" valid:"required"`
	SentBy       string `json:"sentBy" valid:"required"`
	Domain       string `json:"domain" valid:"required"`
	CreatedTime  int64  `json:"createdTime"`
	RequestId    string `json:"requestId" valid:"required"` // this is for correlation during approval phase
	PeerHost     string // no need to send to the peer
	PeerPort     int    // no need to send to the peer
}

type ReplicationPeer struct {
	ServerId        uint16
	Url             *url.URL
	WebHookToken    string
	ApprovedBy      string
	Domain          string
	CreatedTime     int64
	LastVersion     string
	LastReqSentTime int64
}

type JoinResponse struct {
	PeerServerId     uint16            `json:"peerServerId" valid:"range(0|65535),required"`
	ApprovedBy       string            `json:"approvedBy" valid:"required"`
	PeerWebHookToken string            `json:"peerWebHookToken" valid:"required"`
	RequestId        string            `json:"requestId" valid:"required"` // this is for correlation during approval phase
	PeerView         []ReplicationPeer `json:"peerView"`
}
