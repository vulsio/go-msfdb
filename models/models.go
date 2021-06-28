package models

// Metasploit : https://www.rapid7.com/db/modules
type Metasploit struct {
	ID          int64 `json:"-"`
	Name        string
	Title       string
	Description string
	CveID       string
	Edbs        []Edb
	References  []Reference
}

// Edb has Exploit-ID
type Edb struct {
	ID              int64 `json:"-"`
	MetasploitID    int64
	ExploitUniqueID string
}

// Reference is Child model of Metasploit
// It holds reference information about the CVE
type Reference struct {
	ID           int64 `json:"-"`
	MetasploitID int64
	Link         string `sql:"type:text"`
}
