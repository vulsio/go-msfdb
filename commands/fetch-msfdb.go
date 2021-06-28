package commands

import (
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/takuzoo3868/go-msfdb/db"
	"github.com/takuzoo3868/go-msfdb/fetcher"
	"github.com/takuzoo3868/go-msfdb/git"
	"github.com/takuzoo3868/go-msfdb/models"
)

var fetchMetasploitDBCmd = &cobra.Command{
	Use:   "msfdb",
	Short: "Fetch the data of metasploit-framework cve's list",
	Long:  `Fetch the data of metasploit-framework cve's list`,
	RunE:  fetchMetasploitDB,
}

func init() {
	fetchCmd.AddCommand(fetchMetasploitDBCmd)
}

func fetchMetasploitDB(cmd *cobra.Command, args []string) (err error) {
	driver, locked, err := db.NewDB(
		viper.GetString("dbtype"),
		viper.GetString("dbpath"),
		viper.GetBool("debug-sql"),
	)
	if err != nil {
		if locked {
			log15.Error("Failed to initialize DB. Close DB connection before fetching", "err", err)
		}
		return err
	}
	defer func() {
		_ = driver.CloseDB()
	}()

	log15.Info("Fetching vulsio/msfdb-list")
	gc := &git.Config{}
	fc := fetcher.Config{
		GitClient: gc,
	}
	var records []models.Metasploit
	if records, err = fc.FetchMetasploitDB(); err != nil {
		log15.Error("Failed to fetch vulsio/msfdb-list", "err", err)
		return err
	}
	log15.Info("Metasploit-Framework modules", "count", len(records))

	log15.Info("Insert info into go-msfdbdb.", "db", driver.Name())
	if err := driver.InsertMetasploit(records); err != nil {
		log15.Error("Failed to insert.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	return nil
}
