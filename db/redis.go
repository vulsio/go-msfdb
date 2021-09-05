package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/takuzoo3868/go-msfdb/config"
	"github.com/takuzoo3868/go-msfdb/models"
)

/**
# Redis Data Structure
- SET
  ┌───┬───────────────────────┬────────────────┬────────────────────────────────┐
  │NO │          KEY          │     MEMBER     │            PURPOSE             │
  └───┴───────────────────────┴────────────────┴────────────────────────────────┘
  ┌───┬───────────────────────┬────────────────┬────────────────────────────────┐
  │ 1 │ METASPLOIT#C#$CVEID   │ $MODULE JSON   │ TO GET MODULE FROM CVEID       │
  ├───┼───────────────────────┼────────────────┼────────────────────────────────┤
  | 2 | METASPLOIT#E#$EDBID   | $MODULE JSON   | TO GET MODULE FROM EDBID       |
  └───┴───────────────────────┴────────────────┴────────────────────────────────┘

- Hash
  ┌───┬──────────────────────┬───────────────┬────────┬──────────────────────────────┐
  │NO │         KEY          │   FIELD       │  VALUE │           PURPOSE            │
  └───┴──────────────────────┴───────────────┴────────┴──────────────────────────────┘
  ┌──────────────────────────┬───────────────┬────────┬──────────────────────────────┐
  │ 1 │ METASPLOIT#FETCHMETA │   Revision    │ string │ GET Go-Msfdb Binary Revision │
  ├───┼──────────────────────┼───────────────┼────────┼──────────────────────────────┤
  │ 2 │ METASPLOIT#FETCHMETA │ SchemaVersion │  uint  │ GET Go-Msfdb Schema Version  │
  └───┴──────────────────────┴───────────────┴────────┴──────────────────────────────┘
**/

const (
	dialectRedis = "redis"
	cveIDPrefix  = "METASPLOIT#C#"
	edbIDPrefix  = "METASPLOIT#E#"
	fetchMetaKey = "METASPLOIT#FETCHMETA"
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
	return r.conn.Ping(ctx).Err()
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

// MigrateDB migrates Database
func (r *RedisDriver) MigrateDB() error {
	return nil
}

// IsGoMsfdbModelV1 determines if the DB was created at the time of go-msfdb Model v1
func (r *RedisDriver) IsGoMsfdbModelV1() (bool, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return false, fmt.Errorf("Failed to Exists. err: %s", err)
	}
	if exists == 0 {
		keys, _, err := r.conn.Scan(ctx, 0, "METASPLOIT#*", 1).Result()
		if err != nil {
			return false, fmt.Errorf("Failed to Scan. err: %s", err)
		}
		if len(keys) == 0 {
			return false, nil
		}
		return true, nil
	}

	return false, nil
}

// GetFetchMeta get FetchMeta from Database
func (r *RedisDriver) GetFetchMeta() (*models.FetchMeta, error) {
	ctx := context.Background()

	exists, err := r.conn.Exists(ctx, fetchMetaKey).Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to Exists. err: %s", err)
	}
	if exists == 0 {
		return &models.FetchMeta{GoMsfdbRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	revision, err := r.conn.HGet(ctx, fetchMetaKey, "Revision").Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HGet Revision. err: %s", err)
	}

	verstr, err := r.conn.HGet(ctx, fetchMetaKey, "SchemaVersion").Result()
	if err != nil {
		return nil, fmt.Errorf("Failed to HGet SchemaVersion. err: %s", err)
	}
	version, err := strconv.ParseUint(verstr, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("Failed to ParseUint. err: %s", err)
	}

	return &models.FetchMeta{GoMsfdbRevision: revision, SchemaVersion: uint(version)}, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RedisDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	return r.conn.HSet(context.Background(), fetchMetaKey, map[string]interface{}{"Revision": fetchMeta.GoMsfdbRevision, "SchemaVersion": fetchMeta.SchemaVersion}).Err()
}

// InsertMetasploit :
func (r *RedisDriver) InsertMetasploit(records []models.Metasploit) (err error) {
	expire := viper.GetUint("expire")
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	ctx := context.Background()
	log15.Info("Inserting Modules having CVEs...")
	bar := pb.StartNew(len(records))
	for idx := range chunkSlice(len(records), batchSize) {
		pipe := r.conn.Pipeline()
		for _, record := range records[idx.From:idx.To] {

			j, err := json.Marshal(record)
			if err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}

			key := cveIDPrefix + record.CveID
			if err := pipe.SAdd(ctx, key, string(j)).Err(); err != nil {
				return fmt.Errorf("Failed to SAdd CVE. err: %s", err)
			}
			if expire > 0 {
				if err := pipe.Expire(ctx, key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
					return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
				}
			} else {
				if err := pipe.Persist(ctx, key).Err(); err != nil {
					return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
				}
			}

			for _, edb := range record.Edbs {
				key := edbIDPrefix + edb.ExploitUniqueID
				if err := pipe.SAdd(ctx, key, string(j)).Err(); err != nil {
					return fmt.Errorf("Failed to SAdd CVE. err: %s", err)
				}
				if expire > 0 {
					if err := pipe.Expire(ctx, key, time.Duration(expire*uint(time.Second))).Err(); err != nil {
						return fmt.Errorf("Failed to set Expire to Key. err: %s", err)
					}
				} else {
					if err := pipe.Persist(ctx, key).Err(); err != nil {
						return fmt.Errorf("Failed to remove the existing timeout on Key. err: %s", err)
					}
				}
			}
		}
		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	log15.Info("CveID Metasploit Count", "count", len(records))
	return nil
}

// GetModuleByCveID :
func (r *RedisDriver) GetModuleByCveID(cveID string) []models.Metasploit {
	ctx := context.Background()
	modules := []models.Metasploit{}
	metasploits, err := r.conn.SMembers(ctx, cveIDPrefix+cveID).Result()
	if err != nil {
		log15.Error("Failed to get metasploit.", "err", err)
		return nil
	}
	for _, metasploit := range metasploits {
		var module models.Metasploit
		if err := json.Unmarshal([]byte(metasploit), &module); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil
		}
		modules = append(modules, module)
	}
	return modules
}

// GetModuleByEdbID :
func (r *RedisDriver) GetModuleByEdbID(edbID string) []models.Metasploit {
	ctx := context.Background()
	modules := []models.Metasploit{}
	metasploits, err := r.conn.SMembers(ctx, edbIDPrefix+edbID).Result()
	if err != nil {
		log15.Error("Failed to get metasploit.", "err", err)
		return nil
	}

	for _, metasploit := range metasploits {
		var module models.Metasploit
		if err := json.Unmarshal([]byte(metasploit), &module); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil
		}
		modules = append(modules, module)
	}
	return modules
}
