// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package main

import (
	"flag"
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

//var profile = flag.String("profile", "", "write cpu profile to file")
var address = flag.String("a", "0.0.0.0", "IP address or DNS name of the server (can optionally have the listening port as well prefixed with the : char)")
var enableTls = flag.Bool("tls", true, "Flag to enable or disable TLS")

func main() {
	logger.ConfigureLoggers("<root>=debug")
	//logger.ConfigureLoggers("<root>=debug; sparrow.base=warning; sparrow.net=info; sparrow.schema=warning; sparrow.provider=warning; sparrow.silo=warning")
	sp := net.NewSparrowServer("/tmp/sparrow")
	go sp.Start()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Debugf("Waiting for signals...")
	<-sigs
	log.Infof("Shutting down...")
	sp.Stop()
}
