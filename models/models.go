package models

// ExploitType :
type ExploitType string

var (
	// Rapid7DatabaseType :
	Rapid7DatabaseType ExploitType = "Rapid7"
)

// Metasploit : https://www.rapid7.com/db/modules
type Metasploit struct {
	ID int64 `json:",omitempty"`
}
