package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-msfdb/db"
	server "github.com/vulsio/go-msfdb/server"
	"github.com/vulsio/go-msfdb/utils"
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

	serverCmd.PersistentFlags().String("bind", "127.0.0.1", "HTTP server bind to IP address")
	if err := viper.BindPFlag("bind", serverCmd.PersistentFlags().Lookup("bind")); err != nil {
		panic(err)
	}

	serverCmd.PersistentFlags().String("port", "1327", "HTTP server port number")
	if err := viper.BindPFlag("port", serverCmd.PersistentFlags().Lookup("port")); err != nil {
		panic(err)
	}
}

func executeServer(_ *cobra.Command, _ []string) (err error) {
	if err := utils.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

	driver, locked, err := db.NewDB(
		viper.GetString("dbtype"),
		viper.GetString("dbpath"),
		viper.GetBool("debug-sql"),
		db.Option{},
	)
	if err != nil {
		if locked {
			return xerrors.Errorf("Failed to initialize DB. Close DB connection before fetching. err: %w", err)
		}
		return err
	}

	log15.Info("Starting HTTP Server...")
	if err = server.Start(viper.GetBool("log-to-file"), viper.GetString("log-dir"), driver); err != nil {
		return xerrors.Errorf("Failed to start server. err: %w", err)
	}

	return nil
}
