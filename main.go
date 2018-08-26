// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package main

import (
	logger "github.com/juju/loggo"
	"os"
	"os/signal"
	"sparrow/net"
	"syscall"
)

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.main")
}

func main() {
	logger.ConfigureLoggers("<root>=debug")
	//logger.ConfigureLoggers("<root>=debug; sparrow.base=warning; sparrow.net=info; sparrow.schema=warning; sparrow.provider=warning; sparrow.silo=warning")
	go net.Start("/tmp/sparrow")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Debugf("Waiting for signals...")
	<-sigs
	log.Infof("Shutting down...")
	net.Stop()
}
