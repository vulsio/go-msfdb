package commands

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the data of msfdb-list",
	Long:  `Fetch the data of msfdb-list`,
}

func init() {
	RootCmd.AddCommand(fetchCmd)

	fetchCmd.PersistentFlags().Uint("expire", 0, "timeout to set for Redis keys in seconds. If set to 0, the key is persistent.")
	_ = viper.BindPFlag("expire", fetchCmd.PersistentFlags().Lookup("expire"))
}
