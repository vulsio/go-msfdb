package commands

import (
	"github.com/takuzoo3868/go-msfdb/db"
	"github.com/takuzoo3868/go-msfdb/fetcher"
	"github.com/takuzoo3868/go-msfdb/models"
	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	log15.Info("Fetching vulsio/msfdb-list")
	var exploits []*models.Metasploit
	if exploits, err = fetcher.FetchMetasploitDB(); err != nil {
		log15.Error("Failed to fetch Exploit", "err", err)
		return err
	}
	log15.Info("Offensive Security Exploit", "count", len(exploits))

	log15.Info("Insert Exploit into go-exploitdb.", "db", driver.Name())
	if err := driver.InsertMetasploit(exploits); err != nil {
		log15.Error("Failed to insert.", "dbpath", viper.GetString("dbpath"), "err", err)
		return err
	}

	return nil
}