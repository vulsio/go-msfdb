package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vulsio/go-msfdb/config"
	"github.com/vulsio/go-msfdb/models"
	"github.com/vulsio/go-msfdb/utils"
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
	gormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger: logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				LogLevel: logger.Silent,
			},
		),
	}

	if debugSQL {
		gormConfig.Logger = logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold: time.Second,
				LogLevel:      logger.Info,
				Colorful:      true,
			},
		)
	}

	switch r.name {
	case dialectSqlite3:
		r.conn, err = gorm.Open(sqlite.Open(dbPath), &gormConfig)
	case dialectMysql:
		r.conn, err = gorm.Open(mysql.Open(dbPath), &gormConfig)
	case dialectPostgreSQL:
		r.conn, err = gorm.Open(postgres.Open(dbPath), &gormConfig)
	default:
		err = xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
	}

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

	var sqlDB *sql.DB
	if sqlDB, err = r.conn.DB(); err != nil {
		return xerrors.Errorf("Failed to get DB Object. err : %w", err)
	}
	if err = sqlDB.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// MigrateDB migrates Database
func (r *RDBDriver) MigrateDB() error {
	if err := r.conn.AutoMigrate(
		&models.FetchMeta{},

		&models.Metasploit{},
		&models.Edb{},
		&models.Reference{},
	); err != nil {
		return xerrors.Errorf("Failed to migrate. err: %w", err)
	}

	return nil
}

// InsertMetasploit :
func (r *RDBDriver) InsertMetasploit(records []models.Metasploit) (err error) {
	log15.Info("Inserting Modules having CVEs...")
	return r.deleteAndInsertMetasploit(records)
}

func (r *RDBDriver) deleteAndInsertMetasploit(records []models.Metasploit) (err error) {
	bar := pb.StartNew(len(records))
	tx := r.conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	var errs utils.Errors
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(models.Metasploit{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(models.Edb{}).Error)
	errs = errs.Add(tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(models.Reference{}).Error)
	errs = utils.DeleteNil(errs)
	if len(errs.GetErrors()) > 0 {
		return fmt.Errorf("Failed to delete old records. err: %s", errs.Error())
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for idx := range chunkSlice(len(records), batchSize) {
		if err = tx.Create(records[idx.From:idx.To]).Error; err != nil {
			return fmt.Errorf("Failed to insert. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()
	log15.Info("CveID Metasploit Count", "count", len(records))
	return nil
}

// GetModuleByCveID :
func (r *RDBDriver) GetModuleByCveID(cveID string) ([]models.Metasploit, error) {
	ms := []models.Metasploit{}
	err := r.conn.Preload("References").Preload("Edbs").Where(&models.Metasploit{CveID: cveID}).Find(&ms).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log15.Error("Failed to get module info by CVE", "err", err)
		return nil, err
	}
	return ms, nil
}

// GetModuleMultiByCveID :
func (r *RDBDriver) GetModuleMultiByCveID(cveIDs []string) (map[string][]models.Metasploit, error) {
	ms := map[string][]models.Metasploit{}
	for _, cveID := range cveIDs {
		module, err := r.GetModuleByCveID(cveID)
		if err != nil {
			return nil, err
		}
		ms[cveID] = module
	}
	return ms, nil
}

// GetModuleByEdbID :
func (r *RDBDriver) GetModuleByEdbID(edbID string) ([]models.Metasploit, error) {
	ms := []models.Metasploit{}
	err := r.conn.Preload("References").Preload("Edbs").Joins("JOIN edbs ON edbs.metasploit_id = metasploits.id").Where("exploit_unique_id = ?", edbID).Find(&ms).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log15.Error("Failed to get module info by EDB-ID", "err", err)
		return nil, err
	}
	return ms, nil
}

// GetModuleMultiByEdbID :
func (r *RDBDriver) GetModuleMultiByEdbID(edbIDs []string) (map[string][]models.Metasploit, error) {
	ms := map[string][]models.Metasploit{}
	for _, edbID := range edbIDs {
		module, err := r.GetModuleByEdbID(edbID)
		if err != nil {
			return nil, err
		}
		ms[edbID] = module
	}
	return ms, nil
}

// IsGoMsfdbModelV1 determines if the DB was created at the time of go-msfdb Model v1
func (r *RDBDriver) IsGoMsfdbModelV1() (bool, error) {
	if r.conn.Migrator().HasTable(&models.FetchMeta{}) {
		return false, nil
	}

	var (
		count int64
		err   error
	)
	switch r.name {
	case dialectSqlite3:
		err = r.conn.Table("sqlite_master").Where("type = ?", "table").Count(&count).Error
	case dialectMysql:
		err = r.conn.Table("information_schema.tables").Where("table_schema = ?", r.conn.Migrator().CurrentDatabase()).Count(&count).Error
	case dialectPostgreSQL:
		err = r.conn.Table("pg_tables").Where("schemaname = ?", "public").Count(&count).Error
	}

	if count > 0 {
		return true, nil
	}
	return false, err
}

// GetFetchMeta get FetchMeta from Database
func (r *RDBDriver) GetFetchMeta() (fetchMeta *models.FetchMeta, err error) {
	if err = r.conn.Take(&fetchMeta).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return &models.FetchMeta{GoMsfdbRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	return fetchMeta, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RDBDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	fetchMeta.GoMsfdbRevision = config.Revision
	fetchMeta.SchemaVersion = models.LatestSchemaVersion
	return r.conn.Save(fetchMeta).Error
}
