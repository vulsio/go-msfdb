package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"golang.org/x/xerrors"

	"github.com/vulsio/go-msfdb/utils"
)

// Operations :
type Operations interface {
	CloneRepo(string, string) (map[string]struct{}, error)
}

// Config :
type Config struct {
}

// CloneRepo :
func (gc Config) CloneRepo(url, repoPath string) (map[string]struct{}, error) {
	exists, err := utils.Exists(filepath.Join(repoPath, ".git"))
	if err != nil {
		return nil, err
	}

	updatedFiles := map[string]struct{}{}
	if exists {
		log15.Info("initializing", "repo", repoPath)
		pathNode := filepath.Base(repoPath)
		if pathNode != "msfdb-list" {
			return nil, fmt.Errorf("repoPath incorrect, %s", repoPath)
		}

		if err = os.RemoveAll(repoPath); err != nil {
			return nil, err
		}
	}

	log15.Info("git clone", "repo", repoPath)
	if err = os.MkdirAll(repoPath, 0700); err != nil {
		return nil, err
	}
	if err := clone(url, repoPath); err != nil {
		return nil, err
	}

	err = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		updatedFiles[path] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return updatedFiles, nil
}

func clone(url, repoPath string) error {
	commandAndArgs := []string{"clone", "--depth", "1", url, repoPath}
	cmd := exec.Command("git", commandAndArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("failed to clone: %w", err)
	}
	return nil
}

func generateGitArgs(repoPath string) []string {
	gitDir := filepath.Join(repoPath, ".git")
	return []string{"--git-dir", gitDir, "--work-tree", repoPath}
}
