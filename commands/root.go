package commands

import (
	"fmt"
	"os"

	"github.com/inconshreveable/log15"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vulsio/go-msfdb/commands/convert"
	"github.com/vulsio/go-msfdb/commands/fetch"
	"github.com/vulsio/go-msfdb/utils"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:           "go-msfdb",
	Short:         "Go Metasploit DB",
	Long:          `Go Metasploit DB`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	cobra.OnInitialize(initConfig)

	// subcommands
	RootCmd.AddCommand(fetch.FetchCmd)
	RootCmd.AddCommand(convert.ConvertCmd)
	RootCmd.AddCommand(searchCmd)
	RootCmd.AddCommand(serverCmd)
	RootCmd.AddCommand(versionCmd)

	// flags
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.go-msfdb.yaml)")

	RootCmd.PersistentFlags().Bool("log-to-file", false, "output log to file")
	if err := viper.BindPFlag("log-to-file", RootCmd.PersistentFlags().Lookup("log-to-file")); err != nil {
		panic(err)
	}

	RootCmd.PersistentFlags().String("log-dir", utils.GetDefaultLogDir(), "/path/to/log")
	if err := viper.BindPFlag("log-dir", RootCmd.PersistentFlags().Lookup("log-dir")); err != nil {
		panic(err)
	}

	RootCmd.PersistentFlags().Bool("log-json", false, "output log as JSON")
	if err := viper.BindPFlag("log-json", RootCmd.PersistentFlags().Lookup("log-json")); err != nil {
		panic(err)
	}

	RootCmd.PersistentFlags().Bool("debug", false, "debug mode")
	if err := viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("debug")); err != nil {
		panic(err)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			log15.Error("Failed to find home directory.", "err", err)
			os.Exit(1)
		}

		// Search config in home directory with name ".go-msfdb" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".go-msfdb")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
