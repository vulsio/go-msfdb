package commands

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/takuzoo3868/go-msfdb/db"
	"github.com/takuzoo3868/go-msfdb/models"
	"github.com/takuzoo3868/go-msfdb/utils"
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

func searchMetasploit(cmd *cobra.Command, args []string) (err error) {
	if err := utils.SetLogger(viper.GetBool("log-to-file"), viper.GetString("log-dir"), viper.GetBool("debug"), viper.GetBool("log-json")); err != nil {
		return xerrors.Errorf("Failed to SetLogger. err: %w", err)
	}

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

	searchType := viper.GetString("type")
	param := viper.GetString("param")

	switch searchType {
	case "CVE":
		if !cveIDRegexp.MatchString(param) {
			log15.Error("Specify the search type [CVE] parameters like `--param CVE-xxxx-xxxx`")
			return errors.New("Invalid CVE Param")
		}
		results := driver.GetModuleByCveID(param)
		if err := printResults(results); err != nil {
			return err
		}
	case "EDB":
		if !edbIDRegexp.MatchString(param) {
			log15.Error("Specify the search type [EDB] parameters like `--param EDB-xxxx`")
			return errors.New("Invalid EDB Param")
		}
		results := driver.GetModuleByEdbID(param)
		if err := printResults(results); err != nil {
			return err
		}
	default:
		log15.Error("Specify the search type [CVE / EDB].")
		return errors.New("Invalid Type")
	}
	return nil
}

func printResults(results []models.Metasploit) error {
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

	return nil
}
