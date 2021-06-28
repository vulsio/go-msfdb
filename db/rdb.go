package db

import (
	"fmt"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/jinzhu/gorm"
	sqlite3 "github.com/mattn/go-sqlite3"
	"golang.org/x/xerrors"

	"github.com/takuzoo3868/go-msfdb/models"
	"github.com/takuzoo3868/go-msfdb/utils"

	// Required MySQL.  See http://jinzhu.me/gorm/database.html#connecting-to-a-database
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"

	// Required SQLite3.
	_ "github.com/jinzhu/gorm/dialects/sqlite"
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

// CloseDB close Database
func (r *RDBDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}
	if err = r.conn.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	if err := r.conn.AutoMigrate(
		&models.Metasploit{},
		&models.Edb{},
		&models.Reference{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	var errs gorm.Errors
	// Metasploits
	errs = errs.Add(r.conn.Model(&models.Metasploit{}).AddIndex("idx_metasploit_cve_id", "cve_id").Error)

	for _, e := range errs {
		if e != nil {
			return fmt.Errorf("Failed to create index. err: %s", e)
		}
	}
	return nil
}

// InsertMetasploit :
func (r *RDBDriver) InsertMetasploit(records []models.Metasploit) (err error) {
	log15.Info("Inserting Modules having CVEs...")
	return r.deleteAndInsertMetasploit(r.conn, records)
}

func (r *RDBDriver) deleteAndInsertMetasploit(conn *gorm.DB, records []models.Metasploit) (err error) {
	bar := pb.StartNew(len(records))
	tx := conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// select old record
	old := models.Metasploit{}
	result := tx.Where(&models.Metasploit{}).First(&old)
	if !result.RecordNotFound() {
		// Delete all old records
		var errs gorm.Errors
		errs = errs.Add(tx.Unscoped().Delete(models.Metasploit{}).Error)
		errs = errs.Add(tx.Unscoped().Delete(models.Edb{}).Error)
		errs = errs.Add(tx.Unscoped().Delete(models.Reference{}).Error)
		errs = utils.DeleteNil(errs)
		if len(errs.GetErrors()) > 0 {
			return fmt.Errorf("Failed to delete old records. err: %s", errs.Error())
		}
	}

	for _, record := range records {
		if err = tx.Create(&record).Error; err != nil {
			return fmt.Errorf("Failed to insert. err: %s", err)
		}
		bar.Increment()
	}
	bar.Finish()
	log15.Info("CveID Metasploit Count", "count", len(records))
	return nil
}

// GetModuleByCveID :
func (r *RDBDriver) GetModuleByCveID(cveID string) []models.Metasploit {
	ms := []models.Metasploit{}
	var errs gorm.Errors

	errs = errs.Add(r.conn.Where(&models.Metasploit{CveID: cveID}).Find(&ms).Error)
	for _, m := range ms {
		errs = errs.Add(r.conn.Model(&m).Related(&m.References, "references").Error)
	}

	for _, e := range errs.GetErrors() {
		if !gorm.IsRecordNotFoundError(e) {
			log15.Error("Failed to get module info by CVE", "err", e)
		}
	}
	return ms
}

// GetModuleByEdbID :
func (r *RDBDriver) GetModuleByEdbID(edbID string) []models.Metasploit {
	ms := []models.Metasploit{}
	var errs gorm.Errors

	errs = errs.Add(r.conn.Raw("SELECT * FROM metasploits LEFT JOIN msf_edbs ON metasploits.id = msf_edbs.metasploit_id LEFT JOIN edbs ON msf_edbs.edb_id = edbs.id WHERE edbs.exploit_unique_id = ?", edbID).Scan(&ms).Error)
	for _, m := range ms {
		errs = errs.Add(r.conn.Model(&m).Related(&m.References, "references").Error)
	}

	for _, e := range errs.GetErrors() {
		if !gorm.IsRecordNotFoundError(e) {
			log15.Error("Failed to get module info by EDB-ID", "err", e)
		}
	}
	return ms
}
