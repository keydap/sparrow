// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"fmt"
	"sparrow/base"
	"sync"
	"time"
)

const gtime_format = "20060102150405.000000Z" //"yyyyMMddHHmmss.000000Z" , the last 6 digits after . are microseconds

type csnGenerator struct {
	lastTime    int64 // millis
	changeCount uint32
	replicaId   uint16
	modCount    uint32
	mutex       sync.Mutex
}

type csnImpl struct {
	timeMillis  int64
	now         time.Time
	changeCount uint32
	replicaId   uint16
	modCount    uint32
}

func (ci csnImpl) TimeMillis() int64 {
	return ci.timeMillis
}

func (ci csnImpl) ChangeCount() uint32 {
	return ci.changeCount
}

func (ci csnImpl) ReplicaId() uint16 {
	return ci.replicaId
}

func (ci csnImpl) ModificationCount() uint32 {
	return ci.modCount
}

func (ci csnImpl) String() string {
	t := ci.now.Format(gtime_format)

	return fmt.Sprintf("%s#%06x#%03x#%06x", t, ci.changeCount, ci.replicaId, ci.modCount)
}

func NewCsnGenerator(replicaId uint16) *csnGenerator {
	cg := &csnGenerator{}
	cg.replicaId = replicaId
	return cg
}

func (cg *csnGenerator) NewCsn() base.Csn {
	cg.mutex.Lock()

	now := time.Now().UTC()
	millis := now.UnixNano() / 1000000

	if cg.lastTime == millis {
		cg.changeCount++
	} else {
		cg.lastTime = millis
		cg.changeCount = 0
	}

	ci := csnImpl{}
	ci.timeMillis = cg.lastTime
	ci.changeCount = cg.changeCount
	ci.replicaId = cg.replicaId
	ci.modCount = cg.modCount
	ci.now = now

	cg.mutex.Unlock()

	return ci
}
