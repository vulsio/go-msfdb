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
  ┌───┬────────────────┬───────────────┬──────────────┬──────────────────────────────┐
  │NO │     KEY        │   FIELD       │     VALUE    │           PURPOSE            │
  └───┴────────────────┴───────────────┴──────────────┴──────────────────────────────┘
  ┌───┬────────────────┬───────────────┬──────────────┬──────────────────────────────┐
  │ 1 │ MSF#CVE#$CVEID │    MD5SUM     │ $MODULE JSON │ TO GET MODULE FROM CVEID     │
  ├───┼────────────────┼───────────────┼──────────────┼──────────────────────────────┤
  │ 2 │ MSF#FETCHMETA  │   Revision    │    string    │ GET Go-Msfdb Binary Revision │
  ├───┼────────────────┼───────────────┼──────────────┼──────────────────────────────┤
  │ 3 │ MSF#FETCHMETA  │ SchemaVersion │     uint     │ GET Go-Msfdb Schema Version  │
  └───┴────────────────┴───────────────┴──────────────┴──────────────────────────────┘
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
		keys, _, err := r.conn.Scan(ctx, 0, "MSF#*", 1).Result()
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
	ctx := context.Background()
	expire := viper.GetUint("expire")
	batchSize := viper.GetInt("batch-size")
	if batchSize < 1 {
		return fmt.Errorf("Failed to set batch-size. err: batch-size option is not set properly")
	}

	// newDeps, oldDeps: {"CVEID": {"HashSum(CVEJSON)": {"ExploitUniqueID": {}}}}
	newDeps := map[string]map[string]map[string]struct{}{}
	oldDepsStr, err := r.conn.Get(ctx, depKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return fmt.Errorf("Failed to Get key: %s. err: %s", depKey, err)
		}
		oldDepsStr = "{}"
	}
	var oldDeps map[string]map[string]map[string]struct{}
	if err := json.Unmarshal([]byte(oldDepsStr), &oldDeps); err != nil {
		return fmt.Errorf("Failed to unmarshal JSON. err: %s", err)
	}

	log15.Info("Inserting Modules having CVEs...")
	bar := pb.StartNew(len(records))
	for idx := range chunkSlice(len(records), batchSize) {
		pipe := r.conn.Pipeline()
		for _, record := range records[idx.From:idx.To] {
			j, err := json.Marshal(record)
			if err != nil {
				return fmt.Errorf("Failed to marshal json. err: %s", err)
			}

			hash := fmt.Sprintf("%x", md5.Sum(j))
			key := fmt.Sprintf(cveIDKeyFormat, record.CveID)
			if err := pipe.HSet(ctx, key, hash, string(j)).Err(); err != nil {
				return fmt.Errorf("Failed to HSet CVE. err: %s", err)
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

			if _, ok := newDeps[record.CveID]; !ok {
				newDeps[record.CveID] = map[string]map[string]struct{}{}
			}
			if _, ok := newDeps[record.CveID][hash]; !ok {
				newDeps[record.CveID][hash] = map[string]struct{}{}
			}

			member := fmt.Sprintf(edbIDKeyMemberFormat, record.CveID, hash)
			if len(record.Edbs) > 0 {
				for _, edb := range record.Edbs {
					key := fmt.Sprintf(edbIDKeyFormat, edb.ExploitUniqueID)
					if err := pipe.SAdd(ctx, key, member).Err(); err != nil {
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
		if _, err = pipe.Exec(ctx); err != nil {
			return fmt.Errorf("Failed to exec pipeline. err: %s", err)
		}
		bar.Add(idx.To - idx.From)
	}
	bar.Finish()

	pipe := r.conn.Pipeline()
	for cveID, hashes := range oldDeps {
		for hash, edbs := range hashes {
			for edb := range edbs {
				if edb != "" {
					if err := pipe.SRem(ctx, fmt.Sprintf(edbIDKeyFormat, edb), fmt.Sprintf(edbIDKeyMemberFormat, cveID, hash)).Err(); err != nil {
						return fmt.Errorf("Failed to SRem. err: %s", err)
					}
				}
			}
			if err := pipe.HDel(ctx, fmt.Sprintf(cveIDKeyFormat, cveID), hash).Err(); err != nil {
				return fmt.Errorf("Failed to HDel. err: %s", err)
			}
		}
	}
	newDepsJSON, err := json.Marshal(newDeps)
	if err != nil {
		return fmt.Errorf("Failed to Marshal JSON. err: %s", err)
	}
	if err := pipe.Set(ctx, depKey, string(newDepsJSON), time.Duration(expire*uint(time.Second))).Err(); err != nil {
		return fmt.Errorf("Failed to Set depkey. err: %s", err)
	}
	if _, err = pipe.Exec(ctx); err != nil {
		return fmt.Errorf("Failed to exec pipeline. err: %s", err)
	}

	log15.Info("CveID Metasploit Count", "count", len(records))
	return nil
}

// GetModuleByCveID :
func (r *RedisDriver) GetModuleByCveID(cveID string) []models.Metasploit {
	ctx := context.Background()

	metasploits, err := r.conn.HGetAll(ctx, fmt.Sprintf(cveIDKeyFormat, cveID)).Result()
	if err != nil {
		log15.Error("Failed to get metasploit by CVEID.", "err", err)
		return nil
	}
	if len(metasploits) == 0 {
		return []models.Metasploit{}
	}

	modules := []models.Metasploit{}
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

// GetModuleMultiByCveID :
func (r *RedisDriver) GetModuleMultiByCveID(cveIDs []string) map[string][]models.Metasploit {
	ctx := context.Background()

	if len(cveIDs) == 0 {
		return map[string][]models.Metasploit{}
	}

	m := map[string]*redis.StringStringMapCmd{}
	pipe := r.conn.Pipeline()
	for _, cveID := range cveIDs {
		m[cveID] = pipe.HGetAll(ctx, fmt.Sprintf(cveIDKeyFormat, cveID))
	}
	_, err := pipe.Exec(ctx)
	if err != nil {
		log15.Error("Failed to exec pipeline", "err", err)
		return nil
	}

	ms := map[string][]models.Metasploit{}
	for cveID, cmd := range m {
		results, err := cmd.Result()
		if err != nil {
			log15.Error("Failed to get metasploit by CVEID.", "err", err)
			return nil
		}

		modules := []models.Metasploit{}
		for _, result := range results {
			var module models.Metasploit
			if err := json.Unmarshal([]byte(result), &module); err != nil {
				log15.Error("Failed to Unmarshal json.", "err", err)
				return nil
			}
			modules = append(modules, module)
		}
		ms[cveID] = modules
	}
	return ms
}

// GetModuleByEdbID :
func (r *RedisDriver) GetModuleByEdbID(edbID string) []models.Metasploit {
	ctx := context.Background()
	members, err := r.conn.SMembers(ctx, fmt.Sprintf(edbIDKeyFormat, edbID)).Result()
	if err != nil {
		log15.Error("Failed to get metasploit by EDBID.", "err", err)
		return nil
	}
	if len(members) == 0 {
		return []models.Metasploit{}
	}

	pipe := r.conn.Pipeline()
	for _, member := range members {
		ss := strings.Split(member, "#")
		if len(ss) != 2 {
			log15.Error("Failed to parse member.", "err", "invalid format")
			return nil
		}
		cveID := ss[0]
		hash := ss[1]
		_ = pipe.HGet(ctx, fmt.Sprintf(cveIDKeyFormat, cveID), hash)
	}
	cmders, err := pipe.Exec(ctx)
	if err != nil {
		log15.Error("Failed to exec pipeline.", "err", err)
		return nil
	}

	modules := []models.Metasploit{}
	for _, cmder := range cmders {
		str, err := cmder.(*redis.StringCmd).Result()
		if err != nil {
			log15.Error("Failed to HGet.", "err", err)
			return nil
		}

		var module models.Metasploit
		if err := json.Unmarshal([]byte(str), &module); err != nil {
			log15.Error("Failed to Unmarshal json.", "err", err)
			return nil
		}

		modules = append(modules, module)
	}
	return modules
}

// GetModuleMultiByEdbID :
func (r *RedisDriver) GetModuleMultiByEdbID(edbIDs []string) map[string][]models.Metasploit {
	ctx := context.Background()

	if len(edbIDs) == 0 {
		return map[string][]models.Metasploit{}
	}

	m := map[string]*redis.StringSliceCmd{}
	pipe := r.conn.Pipeline()
	for _, edbID := range edbIDs {
		m[edbID] = pipe.SMembers(ctx, fmt.Sprintf(edbIDKeyFormat, edbID))
	}
	_, err := pipe.Exec(ctx)
	if err != nil {
		log15.Error("Failed to exec pipeline", "err", err)
		return nil
	}

	ms := map[string][]models.Metasploit{}
	for edbID, cmd := range m {
		members, err := cmd.Result()
		if err != nil {
			log15.Error("Failed to get metasploit by EdbID.", "err", err)
			return nil
		}

		pipe := r.conn.Pipeline()
		for _, member := range members {
			ss := strings.Split(member, "#")
			if len(ss) != 2 {
				log15.Error("Failed to parse member.", "err", "invalid format")
				return nil
			}
			cveID := ss[0]
			hash := ss[1]
			_ = pipe.HGet(ctx, fmt.Sprintf(cveIDKeyFormat, cveID), hash)
		}
		cmders, err := pipe.Exec(ctx)
		if err != nil {
			log15.Error("Failed to exec pipeline.", "err", err)
			return nil
		}

		modules := []models.Metasploit{}
		for _, cmder := range cmders {
			str, err := cmder.(*redis.StringCmd).Result()
			if err != nil {
				log15.Error("Failed to HGet.", "err", err)
				return nil
			}

			var module models.Metasploit
			if err := json.Unmarshal([]byte(str), &module); err != nil {
				log15.Error("Failed to Unmarshal json.", "err", err)
				return nil
			}

			modules = append(modules, module)
		}
		ms[edbID] = modules
	}
	return ms
}
