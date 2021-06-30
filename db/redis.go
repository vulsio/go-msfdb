package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/takuzoo3868/go-msfdb/models"
)

/**
# Redis Data Structure
- SET
  ┌───┬───────────────────────┬────────────────┬────────────────────────────────┐
  │NO │          KEY          │     MEMBER     │            PURPOSE             │
  └───┴───────────────────────┴────────────────┴────────────────────────────────┘

  ┌───┬───────────────────────┬────────────────┬────────────────────────────────┐
  │ 1 │METASPLOIT#C#$CVEID    │ $MODULE JSON   │ TO GET MODULE FROM CVEID       │
  └───┴───────────────────────┴────────────────┴────────────────────────────────┘
**/

const (
	dialectRedis = "redis"
	cveIDPrefix  = "METASPLOIT#C#"
)

// RedisDriver is Driver for Redis
type RedisDriver struct {
	name string
	conn *redis.Client
}

// Name return db name
func (r *RedisDriver) Name() string {
	return r.name
}

// OpenDB opens Database
func (r *RedisDriver) OpenDB(dbType, dbPath string, debugSQL bool) (locked bool, err error) {
	if err = r.connectRedis(dbPath); err != nil {
		err = fmt.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %s", dbType, dbPath, err)
	}
	return
}

func (r *RedisDriver) connectRedis(dbPath string) error {
	ctx := context.Background()
	var err error
	var option *redis.Options
	if option, err = redis.ParseURL(dbPath); err != nil {
		log15.Error("Failed to parse url.", "err", err)
		return err
	}
	r.conn = redis.NewClient(option)
	err = r.conn.Ping(ctx).Err()
	return err
}

// CloseDB close Database
func (r *RedisDriver) CloseDB() (err error) {
	if r.conn == nil {
		return
	}
	if err = r.conn.Close(); err != nil {
		return xerrors.Errorf("Failed to close DB. Type: %s. err: %w", r.name, err)
	}
	return
}

// DropDB drop tables
func (r *RedisDriver) DropDB() error {
	return nil
}

// MigrateDB migrates Database
func (r *RedisDriver) MigrateDB() error {
	return nil
}

// InsertMetasploit :
func (r *RedisDriver) InsertMetasploit(records []*models.Metasploit) (err error) {
	ctx := context.Background()
	log15.Info("Inserting Modules having CVEs...")
	bar := pb.StartNew(len(records))

	var count int
	for _, record := range records {
		pipe := r.conn.Pipeline()
		bar.Increment()

		j, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("Failed to marshal json. err: %s", err)
		}

		if result := pipe.SAdd(ctx, cveIDPrefix+record.CveID, string(j)); result.Err() != nil {
			return fmt.Errorf("Failed to HSet CVE. err: %s", result.Err())
		}
		count++

		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
	}
	log15.Info("CveID Metasploit Count", "count", count)
	bar.Finish()
	return nil
}

// GetModuleByCveID :
func (r *RedisDriver) GetModuleByCveID(cveID string) []*models.Metasploit {
	ctx := context.Background()
	modules := []*models.Metasploit{}
	results := r.conn.SMembers(ctx, cveIDPrefix+cveID)
	if results.Err() != nil {
		log15.Error("Failed to get cve.", "err", results.Err())
		return nil
	}
	for _, j := range results.Val() {
		var module models.Metasploit
		if err := json.Unmarshal([]byte(j), &module); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil
		}
		modules = append(modules, &module)
	}
	return modules
}

// GetModuleByEdbID :
func (r *RedisDriver) GetModuleByEdbID(edbID string) []*models.Metasploit {
	log15.Error("redis does not correspond to edbid query")
	return nil
}
