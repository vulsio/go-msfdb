package commands

import (
	"time"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-msfdb/db"
	"github.com/vulsio/go-msfdb/fetcher"
	"github.com/vulsio/go-msfdb/git"
	"github.com/vulsio/go-msfdb/models"
	"github.com/vulsio/go-msfdb/utils"
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
		return xerrors.Errorf("Failed to open DB. err: %w", err)
	}
	defer func() {
		_ = driver.CloseDB()
	}()

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to Insert CVEs into DB. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}
	// If the fetch fails the first time (without SchemaVersion), the DB needs to be cleaned every time, so insert SchemaVersion.
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. err: %w", err)
	}

	log15.Info("Fetching vulsio/msfdb-list")
	gc := &git.Config{}
	fc := fetcher.Config{
		GitClient: gc,
	}
	var records []models.Metasploit
	if records, err = fc.FetchMetasploitDB(); err != nil {
		return xerrors.Errorf("Failed to fetch vulsio/msfdb-list. err: %w", err)
	}
	log15.Info("Metasploit-Framework modules", "count", len(records))

	log15.Info("Insert info into go-msfdb.", "db", driver.Name())
	if err := driver.InsertMetasploit(records); err != nil {
		return xerrors.Errorf("Failed to insert. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	fetchMeta.LastFetchedAt = time.Now()
	if err := driver.UpsertFetchMeta(fetchMeta); err != nil {
		return xerrors.Errorf("Failed to upsert FetchMeta to DB. dbpath: %s, err: %w", viper.GetString("dbpath"), err)
	}

	return nil
}
