package models

// Metasploit : https://www.rapid7.com/db/modules
type Metasploit struct {
	ID          int64 `json:"-"`
	Name        string
	Title       string
	Description string `gorm:"type:text"`
	CveID       string
	Edbs        []Edb
	References  []Reference
}

// Edb has Exploit-ID
type Edb struct {
	ID              int64 `json:"-"`
	MetasploitID    int64 `json:"-"`
	ExploitUniqueID string
}

// Reference is Child model of Metasploit
// It holds reference information about the CVE
type Reference struct {
	ID           int64  `json:"-"`
	MetasploitID int64  `json:"-"`
	Link         string `gorm:"type:text"`
}
