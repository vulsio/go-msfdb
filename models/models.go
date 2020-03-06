package models

import (
	"time"
)

// ExploitType :
type ExploitType string

var (
	// Rapid7DatabaseType :
	Rapid7DatabaseType ExploitType = "Rapid7"
)

// Rapid7Database : https://www.rapid7.com/db/modules
type Rapid7Database struct {
	Name          string
	URL           string
	Title         string
	Publish       string
	Describe      string
	Author        string
	Cve           string
	References    string
	Targets       string
	Platforms     string
	Architectures string
	Related       string
	CollectAt     time.Time
}

