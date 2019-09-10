package main

import (
	"flag"
)

var (
	bunkrSocketAddr = flag.String("bunkrSocketAddr", "/tmp/bunkr_daemon.sock", "The address where the client will run")
	agentSocketAddr = flag.String("agentSocketAddr", "/tmp/agent.sock", "The address where the ssh-agent will run")
	storageAddr     = flag.String("storageAddr", "~/.bunkr/agent_storage.json", "The address where the client will run")
	version         = flag.Bool("version", false, "Show version information")
	addKey          = flag.String("addBunkrKey", "", "Enables importing and ssh key fomr Bunkr")
)

type options struct {
	BunkrAddr   string
	AgentAddr   string
	StorageAddr string
	AddKey      string
	Version     bool
}

func getOpts() *options {

	flag.Parse()
	opts := &options{
		BunkrAddr:   *bunkrSocketAddr,
		AgentAddr:   *agentSocketAddr,
		StorageAddr: *storageAddr,
		AddKey:      *addKey,
		Version:     *version,
	}
	return opts
}
