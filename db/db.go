package db

import (
	"fmt"

	"github.com/inconshreveable/log15"
	"github.com/vulsio/go-msfdb/models"
	"golang.org/x/xerrors"
)

// DB :
type DB interface {
	Name() string
	OpenDB(dbType, dbPath string, debugSQL bool) (bool, error)
	MigrateDB() error
	CloseDB() error

	IsGoMsfdbModelV1() (bool, error)
	GetFetchMeta() (*models.FetchMeta, error)
	UpsertFetchMeta(*models.FetchMeta) error

	InsertMetasploit([]models.Metasploit) error
	GetModuleByCveID(string) []models.Metasploit
	GetModuleByEdbID(string) []models.Metasploit
	GetModuleMultiByCveID(cveIDs []string) map[string][]models.Metasploit
	GetModuleMultiByEdbID(edbIDs []string) map[string][]models.Metasploit
}

// NewDB :
func NewDB(dbType string, dbPath string, debugSQL bool) (driver DB, locked bool, err error) {
	if driver, err = newDB(dbType); err != nil {
		return driver, false, fmt.Errorf("Failed to new db: %w", err)
	}

	if locked, err := driver.OpenDB(dbType, dbPath, debugSQL); err != nil {
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}

	isV1, err := driver.IsGoMsfdbModelV1()
	if err != nil {
		log15.Error("Failed to IsGoMsfdbModelV1.", "err", err)
		return nil, false, err
	}
	if isV1 {
		log15.Error("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again")
		return nil, false, xerrors.New("Failed to NewDB. Since SchemaVersion is incompatible, delete Database and fetch again.")
	}

	if err := driver.MigrateDB(); err != nil {
		return driver, false, fmt.Errorf("Failed to migrate db: %w", err)
	}
	return driver, false, nil
}

func newDB(dbType string) (DB, error) {
	switch dbType {
	case dialectSqlite3, dialectMysql, dialectPostgreSQL:
		return &RDBDriver{name: dbType}, nil
	case dialectRedis:
		return &RedisDriver{name: dbType}, nil
	}
	return nil, fmt.Errorf("Invalid database dialect, %s", dbType)
}

// IndexChunk has a starting point and an ending point for Chunk
type IndexChunk struct {
	From, To int
}

func chunkSlice(length int, chunkSize int) <-chan IndexChunk {
	ch := make(chan IndexChunk)

	go func() {
		defer close(ch)

		for i := 0; i < length; i += chunkSize {
			idx := IndexChunk{i, i + chunkSize}
			if length < idx.To {
				idx.To = length
			}
			ch <- idx
		}
	}()

	return ch
}
