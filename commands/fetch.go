package commands

import (
	"github.com/spf13/cobra"
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the data of msfdb-list",
	Long:  `Fetch the data of msfdb-list`,
}

func init() {
	RootCmd.AddCommand(fetchCmd)
}
