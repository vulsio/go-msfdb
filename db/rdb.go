package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vulsio/go-msfdb/config"
	"github.com/vulsio/go-msfdb/models"
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

// https://github.com/mattn/go-sqlite3/blob/edc3bb69551dcfff02651f083b21f3366ea2f5ab/error.go#L18-L66
type errNo int

type sqliteError struct {
	Code errNo /* The error code returned by SQLite */
}

// result codes from http://www.sqlite.org/c3ref/c_abort.html
var (
	errBusy   = errNo(5) /* The database file is locked */
	errLocked = errNo(6) /* A table in the database is locked */
)

// ErrDBLocked :
var ErrDBLocked = xerrors.New("database is locked")

// Name return db name
func (r *RDBDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RDBDriver) OpenDB(dbType, dbPath string, debugSQL bool, _ Option) (err error) {
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
		if err != nil {
			parsedErr, marshalErr := json.Marshal(err)
			if marshalErr != nil {
				return xerrors.Errorf("Failed to marshal err. err: %w", marshalErr)
			}

			var errMsg sqliteError
			if unmarshalErr := json.Unmarshal(parsedErr, &errMsg); unmarshalErr != nil {
				return xerrors.Errorf("Failed to unmarshal. err: %w", unmarshalErr)
			}

			switch errMsg.Code {
			case errBusy, errLocked:
				return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, ErrDBLocked)
			default:
				return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
			}
		}

		r.conn.Exec("PRAGMA foreign_keys = ON")
	case dialectMysql:
		r.conn, err = gorm.Open(mysql.Open(dbPath), &gormConfig)
		if err != nil {
			return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
		}
	case dialectPostgreSQL:
		r.conn, err = gorm.Open(postgres.Open(dbPath), &gormConfig)
		if err != nil {
			return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dbType, dbPath, err)
		}
	default:
		return xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
	}
	return nil
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
		switch r.name {
		case dialectSqlite3:
			if r.name == dialectSqlite3 {
				parsedErr, marshalErr := json.Marshal(err)
				if marshalErr != nil {
					return xerrors.Errorf("Failed to marshal err. err: %w", marshalErr)
				}

				var errMsg sqliteError
				if unmarshalErr := json.Unmarshal(parsedErr, &errMsg); unmarshalErr != nil {
					return xerrors.Errorf("Failed to unmarshal. err: %w", unmarshalErr)
				}

				switch errMsg.Code {
				case errBusy, errLocked:
					return xerrors.Errorf("Failed to migrate. err: %w", ErrDBLocked)
				default:
					return xerrors.Errorf("Failed to migrate. err: %w", err)
				}
			}
		case dialectMysql, dialectPostgreSQL:
			return xerrors.Errorf("Failed to migrate. err: %w", err)
		default:
			return xerrors.Errorf("Not Supported DB dialects. r.name: %s", r.name)
		}
	}

	return nil
}

// InsertMetasploit :
func (r *RDBDriver) InsertMetasploit(records []models.Metasploit) (err error) {
	log15.Info("Inserting Modules having CVEs...")
	return r.deleteAndInsertMetasploit(records)
}

func (r *RDBDriver) deleteAndInsertMetasploit(records []models.Metasploit) (err error) {
	bar := pb.StartNew(len(records)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	tx := r.conn.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()

	// Delete all old records
	for _, table := range []interface{}{models.Metasploit{}, models.Edb{}, models.Reference{}} {
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(table).Error; err != nil {
			return xerrors.Errorf("Failed to delete old records. err: %w", err)
		}
	}

	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	for idx := range chunkSlice(len(records), batchSize) {
		if err = tx.Create(records[idx.From:idx.To]).Error; err != nil {
			return xerrors.Errorf("Failed to insert. err: %w", err)
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
	if err := r.conn.Preload("References").Preload("Edbs").Where(&models.Metasploit{CveID: cveID}).Find(&ms).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get module info by CVE. err: %w", err)
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
	if err := r.conn.Preload("References").Preload("Edbs").Joins("JOIN edbs ON edbs.metasploit_id = metasploits.id").Where("exploit_unique_id = ?", edbID).Find(&ms).Error; err != nil {
		return nil, xerrors.Errorf("Failed to get module info by EDB-ID. err: %w", err)
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
		return &models.FetchMeta{GoMsfdbRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion, LastFetchedAt: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)}, nil
	}

	return fetchMeta, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RDBDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	fetchMeta.GoMsfdbRevision = config.Revision
	fetchMeta.SchemaVersion = models.LatestSchemaVersion
	return r.conn.Save(fetchMeta).Error
}
