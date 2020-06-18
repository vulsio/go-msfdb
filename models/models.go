package models

import (
	"time"

	"github.com/jinzhu/gorm"
)

// LastUpdated :
type LastUpdated struct {
	Date time.Time
}

// Metasploit : https://www.rapid7.com/db/modules
type Metasploit struct {
	gorm.Model  `json:"-" xml:"-"`
	Name        string
	Title       string
	Description string
	CveID       string
	EdbIDs      []Edb       `json:",omitempty" gorm:"many2many:msf_edbs;"`
	References  []Reference `json:",omitempty" gorm:"many2many:msf_refs;"`
}

// Edb has EdbID
type Edb struct {
	ID    uint `json:",omitempty"`
	EdbID string
}

// Reference is Child model of Metasploit
// It holds reference information about the CVE
type Reference struct {
	ID   uint   `json:",omitempty"`
	Link string `sql:"type:text"`
}
