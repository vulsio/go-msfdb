package db

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/go-redis/redis/v8"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-msfdb/config"
	"github.com/vulsio/go-msfdb/models"
)

/**
# Redis Data Structure
- Strings
  ┌───┬─────────┬────────┬──────────────────────────────────────────────────┐
  │NO │  KEY    │ MEMBER │                    PURPOSE                       │
  └───┴─────────┴────────┴──────────────────────────────────────────────────┘
  ┌───┬─────────┬────────┬──────────────────────────────────────────────────┐
  │ 1 │ MSF#DEP │  JSON  │ TO DELETE OUTDATED AND UNNEEDED FIELD AND MEMBER │
  └───┴─────────┴────────┴──────────────────────────────────────────────────┘

- SET
  ┌───┬────────────────┬───────────────┬────────────────────────────────┐
  │NO │      KEY       │    MEMBER     │            PURPOSE             │
  └───┴────────────────┴───────────────┴────────────────────────────────┘
  ┌───┬────────────────┬───────────────┬────────────────────────────────┐
  | 1 | MSF#EDB#$EDBID | $CVEID#MD5SUM | TO GET MODULE FROM EDBID       |
  └───┴────────────────┴───────────────┴────────────────────────────────┘

- Hash
  ┌───┬────────────────┬───────────────┬──────────────┬────────────────────────────────┐
  │NO │     KEY        │   FIELD       │     VALUE    │           PURPOSE              │
  └───┴────────────────┴───────────────┴──────────────┴────────────────────────────────┘
  ┌───┬────────────────┬───────────────┬──────────────┬────────────────────────────────┐
  │ 1 │ MSF#CVE#$CVEID │    MD5SUM     │ $MODULE JSON │ TO GET MODULE FROM CVEID       │
  ├───┼────────────────┼───────────────┼──────────────┼────────────────────────────────┤
  │ 2 │ MSF#FETCHMETA  │   Revision    │    string    │ GET Go-Msfdb Binary Revision   │
  ├───┼────────────────┼───────────────┼──────────────┼────────────────────────────────┤
  │ 3 │ MSF#FETCHMETA  │ SchemaVersion │     uint     │ GET Go-Msfdb Schema Version    │
  ├───┼────────────────┼───────────────┼──────────────┼────────────────────────────────┤
  │ 4 │ MSF#FETCHMETA  │ LastFetchedAt │  time.Time   │ GET Go-Msfdb Last Fetched Time │
  └───┴────────────────┴───────────────┴──────────────┴────────────────────────────────┘
**/

const (
	dialectRedis         = "redis"
	cveIDKeyFormat       = "MSF#CVE#%s"
	edbIDKeyFormat       = "MSF#EDB#%s"
	edbIDKeyMemberFormat = "%s#%s"
	depKey               = "MSF#DEP"
	fetchMetaKey         = "MSF#FETCHMETA"
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
func (r *RedisDriver) OpenDB(_, dbPath string, _ bool, option Option) error {
	if err := r.connectRedis(dbPath, option); err != nil {
		return xerrors.Errorf("Failed to open DB. dbtype: %s, dbpath: %s, err: %w", dialectRedis, dbPath, err)
	}
	return nil
}

func (r *RedisDriver) connectRedis(dbPath string, option Option) error {
	ctx := context.Background()
	var err error
	var opt *redis.Options
	if opt, err = redis.ParseURL(dbPath); err != nil {
		return xerrors.Errorf("Failed to parse url. err: %w", err)
	}
	if 0 < option.RedisTimeout.Seconds() {
		opt.ReadTimeout = option.RedisTimeout
	}
	r.conn = redis.NewClient(opt)
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
		return false, xerrors.Errorf("Failed to Exists. err: %w", err)
	}
	if exists == 0 {
		keys, _, err := r.conn.Scan(ctx, 0, "MSF#*", 1).Result()
		if err != nil {
			return false, xerrors.Errorf("Failed to Scan. err: %w", err)
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
		return nil, xerrors.Errorf("Failed to Exists. err: %w", err)
	}
	if exists == 0 {
		return &models.FetchMeta{GoMsfdbRevision: config.Revision, SchemaVersion: models.LatestSchemaVersion}, nil
	}

	revision, err := r.conn.HGet(ctx, fetchMetaKey, "Revision").Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HGet Revision. err: %w", err)
	}

	verstr, err := r.conn.HGet(ctx, fetchMetaKey, "SchemaVersion").Result()
	if err != nil {
		return nil, xerrors.Errorf("Failed to HGet SchemaVersion. err: %w", err)
	}
	version, err := strconv.ParseUint(verstr, 10, 8)
	if err != nil {
		return nil, xerrors.Errorf("Failed to ParseUint. err: %w", err)
	}

	datestr, err := r.conn.HGet(ctx, fetchMetaKey, "LastFetchedAt").Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return nil, xerrors.Errorf("Failed to HGet LastFetchedAt. err: %w", err)
		}
		datestr = time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	}
	date, err := time.Parse(time.RFC3339, datestr)
	if err != nil {
		return nil, xerrors.Errorf("Failed to Parse date. err: %w", err)
	}

	return &models.FetchMeta{GoMsfdbRevision: revision, SchemaVersion: uint(version), LastFetchedAt: date}, nil
}

// UpsertFetchMeta upsert FetchMeta to Database
func (r *RedisDriver) UpsertFetchMeta(fetchMeta *models.FetchMeta) error {
	return r.conn.HSet(context.Background(), fetchMetaKey, map[string]interface{}{"Revision": config.Revision, "SchemaVersion": models.LatestSchemaVersion, "LastFetchedAt": fetchMeta.LastFetchedAt}).Err()
}

// InsertMetasploit :
func (r *RedisDriver) InsertMetasploit(records []models.Metasploit) (err error) {
	ctx := context.Background()
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"CVEID": {"HashSum(CVEJSON)": {"ExploitUniqueID": {}}}}
	newDeps := map[string]map[string]map[string]struct{}{}
	oldDepsStr, err := r.conn.Get(ctx, depKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return xerrors.Errorf("Failed to Get key: %s. err: %w", depKey, err)
		}
		oldDepsStr = "{}"
	}
	var oldDeps map[string]map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return xerrors.Errorf("Failed to unmarshal JSON. err: %w", err)
	}

	log15.Info("Inserting Modules having CVEs...")
	bar := pb.StartNew(len(records))
	for idx := range chunkSlice(len(records), batchSize) {
		pipe := r.conn.Pipeline()
		for _, record := range records[idx.From:idx.To] {
			j, err := json.Marshal(record)
			if err != nil {
				return xerrors.Errorf("Failed to marshal json. err: %w", err)
			}

			hash := fmt.Sprintf("%x", md5.Sum(j))
			_ = pipe.HSet(ctx, fmt.Sprintf(cveIDKeyFormat, record.CveID), hash, string(j))
			if _, ok := newDeps[record.CveID]; !ok {
				newDeps[record.CveID] = map[string]map[string]struct{}{}
			}
			if _, ok := newDeps[record.CveID][hash]; !ok {
				newDeps[record.CveID][hash] = map[string]struct{}{}
			}

			member := fmt.Sprintf(edbIDKeyMemberFormat, record.CveID, hash)
			if len(record.Edbs) > 0 {
				for _, edb := range record.Edbs {
					_ = pipe.SAdd(ctx, fmt.Sprintf(edbIDKeyFormat, edb.ExploitUniqueID), member)
					newDeps[record.CveID][hash][edb.ExploitUniqueID] = struct{}{}
					if _, ok := oldDeps[record.CveID]; ok {
						if _, ok := oldDeps[record.CveID][hash]; ok {
							delete(oldDeps[record.CveID][hash], edb.ExploitUniqueID)
							if len(oldDeps[record.CveID][hash]) == 0 {
								delete(oldDeps[record.CveID], hash)
							}
						}
					}
				}
			} else {
				newDeps[record.CveID][hash][""] = struct{}{}
				if _, ok := oldDeps[record.CveID]; ok {
					if _, ok := oldDeps[record.CveID][hash]; ok {
						delete(oldDeps[record.CveID][hash], "")
						delete(oldDeps[record.CveID], hash)
					}
				}
			}
			if _, ok := oldDeps[record.CveID]; ok {
				if len(oldDeps[record.CveID]) == 0 {
					delete(oldDeps, record.CveID)
				}
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	pipe := r.conn.Pipeline()
	for cveID, hashes := range oldDeps {
		for hash, edbs := range hashes {
			for edb := range edbs {
				if edb != "" {
					_ = pipe.SRem(ctx, fmt.Sprintf(edbIDKeyFormat, edb), fmt.Sprintf(edbIDKeyMemberFormat, cveID, hash))
				}
			}
			if _, ok := newDeps[cveID][hash]; !ok {
				_ = pipe.HDel(ctx, fmt.Sprintf(cveIDKeyFormat, cveID), hash)
			}
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return xerrors.Errorf("Failed to Marshal JSON. err: %w", err)
	}
	_ = pipe.Set(ctx, depKey, string(newDepsJSON), 0)
	if _, err := pipe.Exec(ctx); err != nil {
		return xerrors.Errorf("Failed to exec pipeline. err: %w", err)
	}

	log15.Info("CveID Metasploit Count", "count", len(records))
	return nil
}

// GetModuleByCveID :
func (r *RedisDriver) GetModuleByCveID(cveID string) ([]models.Metasploit, error) {
	ctx := context.Background()

	metasploits, err := r.conn.HGetAll(ctx, fmt.Sprintf(cveIDKeyFormat, cveID)).Result()
	if err != nil {
		return nil, err
	}

	modules := []models.Metasploit{}
	for _, metasploit := range metasploits {
		var module models.Metasploit
		if err := json.Unmarshal([]byte(metasploit), &module); err != nil {
			return nil, err
		}
		modules = append(modules, module)
	}
	return modules, nil
}

// GetModuleMultiByCveID :
func (r *RedisDriver) GetModuleMultiByCveID(cveIDs []string) (map[string][]models.Metasploit, error) {
	ctx := context.Background()

	if len(cveIDs) == 0 {
		return map[string][]models.Metasploit{}, nil
	}

	m := map[string]*redis.StringStringMapCmd{}
	pipe := r.conn.Pipeline()
	for _, cveID := range cveIDs {
		m[cveID] = pipe.HGetAll(ctx, fmt.Sprintf(cveIDKeyFormat, cveID))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}

	ms := map[string][]models.Metasploit{}
	for cveID, cmd := range m {
		results, err := cmd.Result()
		if err != nil {
			return nil, err
		}

		modules := []models.Metasploit{}
		for _, result := range results {
			var module models.Metasploit
			if err := json.Unmarshal([]byte(result), &module); err != nil {
				return nil, err
			}
			modules = append(modules, module)
		}
		ms[cveID] = modules
	}
	return ms, nil
}

// GetModuleByEdbID :
func (r *RedisDriver) GetModuleByEdbID(edbID string) ([]models.Metasploit, error) {
	ctx := context.Background()
	members, err := r.conn.SMembers(ctx, fmt.Sprintf(edbIDKeyFormat, edbID)).Result()
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return []models.Metasploit{}, nil
	}

	pipe := r.conn.Pipeline()
	for _, member := range members {
		ss := strings.Split(member, "#")
		if len(ss) != 2 {
			return nil, xerrors.Errorf("Failed to parse member. err: member(%s) is invalid format", member)
		}
		cveID := ss[0]
		hash := ss[1]
		_ = pipe.HGet(ctx, fmt.Sprintf(cveIDKeyFormat, cveID), hash)
	}
	cmders, err := pipe.Exec(ctx)
	if err != nil {
		return nil, err
	}

	modules := []models.Metasploit{}
	for _, cmder := range cmders {
		str, err := cmder.(*redis.StringCmd).Result()
		if err != nil {
			return nil, err
		}

		var module models.Metasploit
		if err := json.Unmarshal([]byte(str), &module); err != nil {
			return nil, err
		}

		modules = append(modules, module)
	}
	return modules, nil
}

// GetModuleMultiByEdbID :
func (r *RedisDriver) GetModuleMultiByEdbID(edbIDs []string) (map[string][]models.Metasploit, error) {
	ctx := context.Background()

	if len(edbIDs) == 0 {
		return map[string][]models.Metasploit{}, nil
	}

	m := map[string]*redis.StringSliceCmd{}
	pipe := r.conn.Pipeline()
	for _, edbID := range edbIDs {
		m[edbID] = pipe.SMembers(ctx, fmt.Sprintf(edbIDKeyFormat, edbID))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}

	ms := map[string][]models.Metasploit{}
	for edbID, cmd := range m {
		members, err := cmd.Result()
		if err != nil {
			return nil, err
		}

		pipe := r.conn.Pipeline()
		for _, member := range members {
			ss := strings.Split(member, "#")
			if len(ss) != 2 {
				return nil, xerrors.Errorf("Failed to parse member. err: member(%s) is invalid format", member)
			}
			cveID := ss[0]
			hash := ss[1]
			_ = pipe.HGet(ctx, fmt.Sprintf(cveIDKeyFormat, cveID), hash)
		}
		cmders, err := pipe.Exec(ctx)
		if err != nil {
			return nil, err
		}

		modules := []models.Metasploit{}
		for _, cmder := range cmders {
			str, err := cmder.(*redis.StringCmd).Result()
			if err != nil {
				return nil, err
			}

			var module models.Metasploit
			if err := json.Unmarshal([]byte(str), &module); err != nil {
				return nil, err
			}

			modules = append(modules, module)
		}
		ms[edbID] = modules
	}
	return ms, nil
}
