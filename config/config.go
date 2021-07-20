package config

import (
	valid "github.com/asaskevich/govalidator"
	"github.com/inconshreveable/log15"
)

// Version of go-msfdb
var Version = "`make build` or `make install` will show the version"

// Revision of Git
var Revision string

// CommonConfig :
type CommonConfig struct {
	Debug     bool
	DebugSQL  bool
	Quiet     bool
	DBPath    string
	DBType    string
	HTTPProxy string
}

// CommonConf :
var CommonConf CommonConfig

// Validate :
func (p *CommonConfig) Validate() bool {
	if p.DBType == "sqlite3" {
		if ok, _ := valid.IsFilePath(p.DBPath); !ok {
			log15.Error("SQLite3 DB path must be a *Absolute* file path.", "dbpath", p.DBPath)
			return false
		}
	}

	_, err := valid.ValidateStruct(p)
	if err != nil {
		log15.Error("Invalid Struct", "err", err)
		return false
	}
	return true
}
