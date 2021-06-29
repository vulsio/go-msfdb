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
		if err := flag.CommandLine.Parse(strings.Fields(envArgs)); err != nil {
			fmt.Printf("Failed to parse ENV_VARs: %s", err)
			os.Exit(1)
		}
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
