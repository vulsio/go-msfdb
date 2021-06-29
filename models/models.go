package models

// Metasploit : https://www.rapid7.com/db/modules
type Metasploit struct {
	ID          int64 `json:"-"`
	Name        string
	Title       string
	Description string `gorm:"type:text"`
	CveID       string `gorm:"index:idx_metasploit_cve_id"`
	Edbs        []Edb
	References  []Reference
}

// Edb has Exploit-ID
type Edb struct {
	ID              int64  `json:"-"`
	MetasploitID    int64  `json:"-" gorm:"index:idx_edbs_metasploit_id"`
	ExploitUniqueID string `gorm:"index:idx_edbs_exploit_unique_id"`
}

// Reference is Child model of Metasploit
// It holds reference information about the CVE
type Reference struct {
	ID           int64  `json:"-"`
	MetasploitID int64  `json:"-" gorm:"index:idx_references_metasploit_id"`
	Link         string `gorm:"type:text"`
}
