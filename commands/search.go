package commands

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-msfdb/db"
	"github.com/vulsio/go-msfdb/models"
	"github.com/vulsio/go-msfdb/utils"
)

var (
	cveIDRegexp = regexp.MustCompile(`^CVE-\d{1,}-\d{1,}$`)
	edbIDRegexp = regexp.MustCompile(`^EDB-\d{1,}$`)
)

// searchCmd represents the search command
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search the data of exploit",
	Long:  `Search the data of exploit`,
	RunE:  searchMetasploit,
}

func init() {
	RootCmd.AddCommand(searchCmd)

	searchCmd.PersistentFlags().String("type", "CVE", "All Metasploit Framework modules by CVE: CVE  |  by EDB: EDB")
	if err := viper.BindPFlag("type", searchCmd.PersistentFlags().Lookup("type")); err != nil {
		panic(err)
	}

	searchCmd.PersistentFlags().String("param", "", "All Metasploit Framework modules: None  |  by CVE: [CVE-xxxx]  | by EDB: [EDB-xxxx]")
	if err := viper.BindPFlag("param", searchCmd.PersistentFlags().Lookup("param")); err != nil {
		panic(err)
	}
}

func searchMetasploit(_ *cobra.Command, _ []string) (err error) {
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

	fetchMeta, err := driver.GetFetchMeta()
	if err != nil {
		return xerrors.Errorf("Failed to get FetchMeta from DB. err: %w", err)
	}
	if fetchMeta.OutDated() {
		return xerrors.Errorf("Failed to search command. err: SchemaVersion is old. SchemaVersion: %+v", map[string]uint{"latest": models.LatestSchemaVersion, "DB": fetchMeta.SchemaVersion})
	}

	searchType := viper.GetString("type")
	param := viper.GetString("param")

	switch searchType {
	case "CVE":
		if !cveIDRegexp.MatchString(param) {
			return xerrors.Errorf("Specify the search type [CVE] parameters like `--param CVE-xxxx-xxxx`")
		}
		results, err := driver.GetModuleByCveID(param)
		if err != nil {
			return err
		}
		printResults(results)
	case "EDB":
		if !edbIDRegexp.MatchString(param) {
			return xerrors.Errorf("Specify the search type [EDB] parameters like `--param EDB-xxxx`")
		}
		results, err := driver.GetModuleByEdbID(param)
		if err != nil {
			return err
		}
		printResults(results)
	default:
		return xerrors.Errorf("Specify the search type [CVE / EDB].")
	}
	return nil
}

func printResults(results []models.Metasploit) {
	fmt.Println("")
	fmt.Println("Results: CVE-Metasploit Record")
	fmt.Println("---------------------------------------")
	for _, r := range results {
		fmt.Printf("\n[*] CVE: %s\n", r.CveID)
		fmt.Printf("  Name: %s\n", r.Name)
		fmt.Printf("  Title: %s\n", r.Title)
		fmt.Printf("  Description: %s\n", r.Description)
		if 0 < len(r.Edbs) {
			fmt.Println("\n[-] Edbs")
			for _, e := range r.Edbs {
				fmt.Printf("  EDB-ID: %s\n", e.ExploitUniqueID)
			}
		}
		if 0 < len(r.References) {
			fmt.Println("\n[-] References")
			for _, u := range r.References {
				fmt.Printf("  URL: %s\n", u.Link)
			}
		}
	}
	fmt.Println("\n---------------------------------------")
}
