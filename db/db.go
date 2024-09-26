package db

import (
	"time"

	"github.com/vulsio/go-msfdb/models"
	"golang.org/x/xerrors"
)

// DB :
type DB interface {
	Name() string
	OpenDB(dbType, dbPath string, debugSQL bool, option Option) error
	MigrateDB() error
	CloseDB() error

	IsGoMsfdbModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	InsertMetasploit([]models.Metasploit) error
	GetModuleByCveID(string) ([]models.Metasploit, error)
	GetModuleMultiByCveID([]string) (map[string][]models.Metasploit, error)
	GetModuleByEdbID(string) ([]models.Metasploit, error)
	GetModuleMultiByEdbID([]string) (map[string][]models.Metasploit, error)
}

// Option :
type Option struct {
	RedisTimeout time.Duration
}

// NewDB :
func NewDB(dbType string, dbPath string, debugSQL bool, option Option) (driver DB, err error) {
	if driver, err = newDB(dbType); err != nil {
		return driver, xerrors.Errorf("Failed to new db: %w", err)
	}

	if err := driver.OpenDB(dbType, dbPath, debugSQL, option); err != nil {
		return nil, xerrors.Errorf("Failed to open db. err: %w", err)
	}

	isV1, err := driver.IsGoMsfdbModelV1()
	if err != nil {
		return nil, xerrors.Errorf("Failed to IsGoMsfdbModelV1. err: %w", err)
	}
	if isV1 {
		return nil, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err := driver.MigrateDB(); err != nil {
		return driver, xerrors.Errorf("Failed to migrate db: %w", err)
	}
	return driver, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, xerrors.Errorf("Invalid database dialect, %s", dbType)
}
