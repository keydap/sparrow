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
var host = flag.String("h", "localhost", "IP address or DNS name of the server (can optionally have the listening port as well prefixed with the : char)")
var enableTls = flag.Bool("tls", true, "Flag to enable or disable TLS")
var dir = flag.String("d", "/tmp/sparrow", "the directory to be used for storing data")
var port = flag.Int("hp", 7090, "the port at which the server accepts new connections over HTTP")
var ldapPort = flag.Int("lp", 7092, "the port at which the server accepts new connections over LDAP")

func main() {
	flag.Parse()
	logger.ConfigureLoggers("<root>=debug")
	//logger.ConfigureLoggers("<root>=debug; sparrow.base=warning; sparrow.net=info; sparrow.schema=warning; sparrow.provider=warning; sparrow.silo=warning")
	sp := net.NewSparrowServer(*dir, "")
	go sp.Start()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Debugf("Waiting for signals...")
	<-sigs
	log.Infof("Shutting down...")
	sp.Stop()
}
