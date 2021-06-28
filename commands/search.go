package commands

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/inconshreveable/log15"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/takuzoo3868/go-msfdb/db"
	"github.com/takuzoo3868/go-msfdb/models"
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

	searchCmd.PersistentFlags().String("type", "", "All Metasploit Framework modules by CVE: CVE  |  by EDB: EDB (default: CVE)")
	if err := viper.BindPFlag("type", searchCmd.PersistentFlags().Lookup("type")); err != nil {
		panic(err)
	}
	viper.SetDefault("type", "CVE")

	searchCmd.PersistentFlags().String("param", "", "All Metasploit Framework modules: None  |  by CVE: [CVE-xxxx]  | by EDB: [EDB-xxxx]  (default: None)")
	if err := viper.BindPFlag("param", searchCmd.PersistentFlags().Lookup("param")); err != nil {
		panic(err)
	}
	viper.SetDefault("param", "")
}

func searchMetasploit(cmd *cobra.Command, args []string) (err error) {
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
		if !cveIDRegexp.Match([]byte(param)) {
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
