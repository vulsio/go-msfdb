package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/takuzoo3868/go-msfdb/commands"
	"github.com/takuzoo3868/go-msfdb/config"
)

func main() {
	var v = flag.Bool("v", false, "Show version")

	if envArgs := os.Getenv("GO_MSFDB_ARGS"); 0 < len(envArgs) {
		commands.RootCmd.SetArgs(strings.Fields(envArgs))
	} else {
		flag.Parse()
	}

	if *v {
		fmt.Printf("go-msfdb-%s-%s\n", config.Version, config.Revision)
		os.Exit(0)
	}

	if err := commands.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
