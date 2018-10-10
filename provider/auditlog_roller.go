// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"sparrow/utils"
	"time"
)

func (al *AuditLogger) rollLog(dbFilePath string) {
	oldSl, err := openAuditLog(dbFilePath, al.prv)
	if err != nil {
		log.Warningf("could not open the audit database file %s for dumping", dbFilePath)
		return
	}

	auditArchiveDir := filepath.Join(al.prv.layout.DataDir, "archived-auditlogs")
	err = os.Mkdir(auditArchiveDir, utils.DIR_PERM)
	if !os.IsExist(err) {
		log.Warningf("could not create archive directory for audit logs %s %v", auditArchiveDir, err)
		return
	}

	// read each entry and store as JSON in a new file
	_, bkFilePath := filepath.Split(dbFilePath)
	bkFilePath = bkFilePath + ".json"
	bkFilePath = filepath.Join(auditArchiveDir, bkFilePath)
	err = oldSl.DumpJSON(bkFilePath, true, al.rt)
	if err != nil {
		log.Warningf("failed to dump the audit database %s %#v", dbFilePath, err)
		return
	}

	oldSl.Close()
	oldSl = nil

	os.Remove(dbFilePath)
}

func startRoller(roller chan time.Time) {
	// everything should be in local TZ, NOT in UTC
	for {
		now, ok := <-roller
		if !ok {
			break
		}
		sleepUntil := timeUntilMidnight(now)
		time.Sleep(sleepUntil)
		log.Debugf("sleeping for %v until the next rollup", sleepUntil)

		roller <- time.Now()
		log.Debugf("sent an event for rolling up the audit log")
	}
}

func timeUntilMidnight(now time.Time) (sleepUntil time.Duration) {
	zoneOffset := now.Format(time.RFC3339)[19:]
	zoneOffset = "%d-%02d-%02dT00:00:00" + zoneOffset

	nextDay := now.Add(24 * time.Hour)
	y, m, d := nextDay.Date()
	startOfNextDay := fmt.Sprintf(zoneOffset, y, m, d)

	nextDay, _ = time.Parse(time.RFC3339, startOfNextDay)
	sleepUntil = nextDay.Sub(now)
	// testing purpose
	//sleepUntil = 2 * time.Minute
	return sleepUntil
}
