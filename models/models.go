package models

import "gorm.io/gorm"

// LatestSchemaVersion manages the Schema version used in the latest go-msfdb.
const LatestSchemaVersion = 2

// FetchMeta has meta infomation about fetched security tracker
type FetchMeta struct {
	gorm.Model      `json:"-"`
	GoMsfdbRevision string
	SchemaVersion   uint
}

// OutDated checks whether last fetched feed is out dated
func (f FetchMeta) OutDated() bool {
	return f.SchemaVersion != LatestSchemaVersion
}

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
