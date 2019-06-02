// Copyright 2019 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package repl

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sparrow/base"
	"sparrow/utils"
	"strings"
	"sync"
	"time"
)

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
	NEW_SESSION
	REVOKE_SESSION
	DELETE_SESSION
	NEW_DOMAIN
	DELETE_DOMAIN
)

type ReplicationEvent struct {
	Version          string
	DomainCode       string
	Type             DataType
	Data             []byte
	CreatedRes       *base.Resource
	PatchIfMatch     string
	PatchRid         string
	RtName           string
	Rid              string
	ResToReplace     *base.Resource
	NewSession       *base.RbacSession
	SsoSession       bool
	RevokedSessionId string
	DeletedSessionId string
	NewPassword      string
	HashAlgo         string
	NewDomainName    string
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

type JoinResponse struct {
	PeerServerId     uint16            `json:"peerServerId" valid:"range(0|65535),required"`
	ApprovedBy       string            `json:"approvedBy" valid:"required"`
	PeerWebHookToken string            `json:"peerWebHookToken" valid:"required"`
	RequestId        string            `json:"requestId" valid:"required"` // this is for correlation during approval phase
	PeerView         []ReplicationPeer `json:"peerView"`
}

type ReplicationPeer struct {
	ServerId           uint16
	BaseUrl            string
	EventsUrl          *url.URL
	WebHookToken       string
	ApprovedBy         string
	Domain             string
	CreatedTime        int64
	LastVersions       map[string]string // a map of domain code and the associated event version
	PendingVersions    map[string]string // a map of domain code and the associated LATEST event version that was NOT sent yet due to backlog processing
	LastReqSentTime    int64
	LastReqFailureTime int64
	lock               sync.Mutex
	pendingVersionLock sync.Mutex
	catchingUpBacklog  bool
}

func (peer *ReplicationPeer) SendEvent(eventData []byte, transport *http.Transport, serverId uint16, webhookToken string, domainCode string, version string, replSilo *ReplProviderSilo) {
	if peer.catchingUpBacklog {
		peer.pendingVersionLock.Lock()
		pversion, ok := peer.PendingVersions[domainCode]
		if ok {
			if strings.Compare(version, pversion) > 0 { // only update the given version number is higher than the pending version
				peer.PendingVersions[domainCode] = version
			}
		} else {
			peer.PendingVersions[domainCode] = version
		}
		log.Debugf("still processing backlog, not sending event %s", version)
		peer.pendingVersionLock.Unlock()
		return
	}

	peer.lock.Lock()
	defer peer.lock.Unlock()

	_, ok := peer.PendingVersions[domainCode]
	if ok {
		peer.catchingUpBacklog = true
		startV := peer.LastVersions[domainCode]
		lastSentVersion, err := replSilo._sendEventsWithoutLockAfter(startV, peer, transport, serverId, webhookToken, domainCode)
		peer.catchingUpBacklog = false
		// there was some issue in delivering the events, DO NOT update the PendingVersions
		if err != nil {
			return
		}
		updated := false
		if lastSentVersion != "" {
			updated = peer.updatePendingVersionMap(domainCode, lastSentVersion)
		}

		if !updated {
			return
		}
	}

	peer._sendEvent(eventData, transport, serverId, webhookToken, domainCode, version)
}

func (peer *ReplicationPeer) updatePendingVersionMap(domainCode string, lastSentVersion string) bool {
	peer.pendingVersionLock.Lock()
	pversion, ok := peer.PendingVersions[domainCode]
	updated := false
	if ok {
		if strings.Compare(lastSentVersion, pversion) >= 0 {
			delete(peer.PendingVersions, domainCode)
			updated = true
			log.Debugf("removed the pending version map for %s", peer.ServerId)
		}
	} else {
		updated = true // for the case when there is no pending version
	}

	peer.pendingVersionLock.Unlock()

	return updated
}

func (peer *ReplicationPeer) _sendEvent(eventData []byte, transport *http.Transport, serverId uint16, webhookToken string, domainCode string, version string) error {
	// no locking here
	req := &http.Request{}
	req.Method = http.MethodPost
	req.Header = http.Header{}
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add(HEADER_X_FROM_PEER_ID, fmt.Sprintf("%d", serverId))
	req.Header.Add(HEADER_X_WEBHOOK_TOKEN, webhookToken)

	req.Body = ioutil.NopCloser(bytes.NewBuffer(eventData))
	req.URL = peer.EventsUrl
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Debugf("%#v", err)
		peer.LastReqFailureTime = utils.DateTimeMillis()
	} else if resp.StatusCode == 200 {
		log.Debugf("successfully sent event with version %s to peer %d %s", version, serverId, peer.EventsUrl)
		peer.LastVersions[domainCode] = version
		peer.LastReqSentTime = utils.DateTimeMillis()
	}

	return err
}
