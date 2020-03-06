package db

import(
	"fmt"

	"github.com/jinzhu/gorm"
	sqlite3 "github.com/mattn/go-sqlite3"
	// Required MySQL.  See http://jinzhu.me/gorm/database.html#connecting-to-a-database
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	// Required SQLite3.
	_ "github.com/jinzhu/gorm/dialects/sqlite"

	"github.com/takuzoo3868/go-msfdb/models"
)

const (
	dialectSqlite3    = "sqlite3"
	dialectMysql      = "mysql"
	dialectPostgreSQL = "postgres"
)

// RDBDriver :
type RDBDriver struct {
	name string
	conn *gorm.DB
}

// Name return db name
func (r *RDBDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool) (locked bool, err error) {
	r.conn, err = gorm.Open(dbType, dbPath)
	if err != nil {
		msg := fmt.Sprintf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
		if r.name == dialectSqlite3 {
			switch err.(sqlite3.Error).Code {
			case sqlite3.ErrLocked, sqlite3.ErrBusy:
				return true, fmt.Errorf(msg)
			}
		}
		return false, fmt.Errorf(msg)
	}
	r.conn.LogMode(debugSQL)
	if r.name == dialectSqlite3 {
		r.conn.Exec("PRAGMA foreign_keys = ON")
	}
	return false, nil
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	//TODO Add FetchMeta
	if err := r.conn.AutoMigrate(
		&models.Rapid7Database{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}
	return nil
}