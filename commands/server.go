package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/takuzoo3868/go-msfdb/db"
	server "github.com/takuzoo3868/go-msfdb/server"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start go-msfdb HTTP server",
	Long:  `Start go-msfdb HTTP server`,
	RunE:  executeServer,
}

func init() {
	RootCmd.AddCommand(serverCmd)

	serverCmd.PersistentFlags().String("bind", "", "HTTP server bind to IP address (default: loop back interface")
	if err := viper.BindPFlag("bind", serverCmd.PersistentFlags().Lookup("bind")); err != nil {
		panic(err)
	}
	viper.SetDefault("bind", "127.0.0.1")

	serverCmd.PersistentFlags().String("port", "", "HTTP server port number (default: 1327")
	if err := viper.BindPFlag("port", serverCmd.PersistentFlags().Lookup("port")); err != nil {
		panic(err)
	}
	viper.SetDefault("port", "1327")

}

func executeServer(cmd *cobra.Command, args []string) (err error) {
	var isFetch = false

	logDir := viper.GetString("log-dir")
	driver, locked, err := db.NewDB(
		viper.GetString("dbtype"),
		viper.GetString("dbpath"),
		viper.GetBool("debug-sql"),
		isFetch,
	)
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}

	log15.Info("Starting HTTP Server...")
	if err = server.Start(logDir, driver); err != nil {
		log15.Error("Failed to start server.", "err", err)
		return err
	}

	return nil
}
