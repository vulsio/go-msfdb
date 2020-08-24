package utils

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/k0kubun/pp"
	"golang.org/x/xerrors"
)

// CacheDir :
func CacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "go-msfdb")
}

// FileWalk :
func FileWalk(root string, walkFn func(r io.Reader, path string) error) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		if info.Size() == 0 {
			log15.Warn("invalid size", "path", path)
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("failed to open file: %w", err)
		}
		defer f.Close()

		if err = walkFn(f, path); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in file walk: %w", err)
	}
	return nil
}

// FileNameWithoutExtension :
func FileNameWithoutExtension(path string) string {
	basename := filepath.Base(path)
	return strings.TrimSuffix(basename, filepath.Ext(basename))
}

// GenWorkers :
func GenWorkers(num int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			for f := range tasks {
				f()
			}
		}()
	}
	return tasks
}

// Exists :
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// Exec :
func Exec(command string, args []string) (string, error) {
	cmd := exec.Command(command, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		log.Println(stderrBuf.String())
		return "", xerrors.Errorf("failed to exec: %w", err)
	}
	return stdoutBuf.String(), nil
}

// GetDefaultLogDir :
func GetDefaultLogDir() string {
	defaultLogDir := "/var/log/go-msfdb"
	if runtime.GOOS == "windows" {
		defaultLogDir = filepath.Join(os.Getenv("APPDATA"), "go-msfdb")
	}
	return defaultLogDir
}

// SetLogger :
func SetLogger(logDir string, quiet, debug, logJSON bool) {
	stderrHandler := log15.StderrHandler
	logFormat := log15.LogfmtFormat()
	if logJSON {
		logFormat = log15.JsonFormatEx(false, true)
		stderrHandler = log15.StreamHandler(os.Stderr, logFormat)
	}

	lvlHandler := log15.LvlFilterHandler(log15.LvlInfo, stderrHandler)
	if debug {
		lvlHandler = log15.LvlFilterHandler(log15.LvlDebug, stderrHandler)
	}
	if quiet {
		lvlHandler = log15.LvlFilterHandler(log15.LvlDebug, log15.DiscardHandler())
		pp.SetDefaultOutput(ioutil.Discard)
	}

	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.Mkdir(logDir, 0700); err != nil {
			log15.Error("Failed to create log directory", "err", err)
		}
	}
	var handler log15.Handler
	if _, err := os.Stat(logDir); err == nil {
		logPath := filepath.Join(logDir, "go-msfdb.log")
		if _, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err != nil {
			log15.Error("Failed to create a log file", "err", err)
			handler = lvlHandler
		} else {
			handler = log15.MultiHandler(
				log15.Must.FileHandler(logPath, logFormat),
				lvlHandler,
			)
		}
	} else {
		handler = lvlHandler
	}
	log15.Root().SetHandler(handler)
}

// DeleteNil :
func DeleteNil(errs []error) (new []error) {
	for _, err := range errs {
		if err != nil {
			new = append(new, err)
		}
	}
	return new
}
