package fetcher

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"

	// "github.com/inconshreveable/log15"
	"github.com/takuzoo3868/go-msfdb/git"
	"github.com/takuzoo3868/go-msfdb/models"
	"github.com/takuzoo3868/go-msfdb/utils"
	"golang.org/x/xerrors"
)

const (
	// repoURL = "https://github.com/vulsio/msfdb-list.git"
	msfDir = "rapid7"
)

// Module : https://github.com/takuzoo3868/msfdb-list-updater
type Module struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	Description string   `json:"Discription,omitempty"`
	CveIDs      []string `json:"CveIDs"`
	EdbIDs      []string `json:"EdbIDs,omitempty"`
	References  []string `json:"References,omitempty"`
}

// Config : Config parameters used in Git.
type Config struct {
	GitClient git.Operations
}

// FetchMetasploitDB :
func (c Config) FetchMetasploitDB() (records []*models.Metasploit, err error) {
	// Clone vuln-list repository
	dir := filepath.Join(utils.CacheDir(), "msfdb-list")
	// updatedFiles, err := c.GitClient.CloneOrPull(repoURL, dir)
	// if err != nil {
	// 	return nil, err
	// }
	// log15.Info("Updated files", "count", len(updatedFiles))

	// // Only last_updated.json
	// if len(updatedFiles) <= 1 {
	// 	return nil, nil
	// }

	rootDir := filepath.Join(dir, msfDir)

	buffer := &bytes.Buffer{}
	err = utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		modules := []*Module{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return xerrors.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(buffer.Bytes(), &modules); err != nil {
			return xerrors.Errorf("failed to decode json: %w", err)
		}
		buffer.Reset()

		for _, item := range modules {
			record, err := convertToModel(path, item)
			if err != nil {
				return xerrors.Errorf("failed to convert model: %w", err)
			}
			records = append(records, record)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in msfdb-list walk: %w", err)
	}

	return records, nil
}

func convertToModel(path string, item *Module) (*models.Metasploit, error) {
	// cveID
	cveID := utils.FileNameWithoutExtension(path)

	// edbID
	edbIDs := []models.Edb{}
	for _, e := range item.EdbIDs {
		edbID := models.Edb{
			EdbID: e,
		}
		edbIDs = append(edbIDs, edbID)
	}

	// References
	refs := []models.Reference{}
	for _, r := range item.References {
		ref := models.Reference{
			Link: r,
		}
		refs = append(refs, ref)
	}

	return &models.Metasploit{
		Name:        item.Name,
		Title:       item.Title,
		Description: item.Description,
		CveID:       cveID,
		EdbIDs:      edbIDs,
		References:  refs,
	}, nil
}
