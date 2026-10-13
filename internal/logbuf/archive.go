package logbuf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	archiveRetention = 7 * 24 * time.Hour
	maxArchivedLogs  = 64
	maxArchiveBytes  = maxRetainedBytes + (64 << 10)
)

type archivedLog struct {
	Version    int       `json:"version"`
	Sandbox    string    `json:"sandbox"`
	Workspace  string    `json:"workspace"`
	ArchivedAt time.Time `json:"archived_at"`
	Lines      []Line    `json:"lines"`
}

type archiveStore struct {
	mu  sync.Mutex
	dir string
}

func openArchiveStore(dir string) (*archiveStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("sandbox log archive directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox log archive: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect sandbox log archive directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("sandbox log archive path is not a directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure sandbox log archive: %w", err)
	}
	store := &archiveStore{dir: dir}
	if err := store.prune(time.Now().UTC()); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *archiveStore) path(name string) string {
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

func (s *archiveStore) Save(name, workspace string, lines []Line) error {
	if name == "" || workspace == "" {
		return fmt.Errorf("sandbox log archive requires a name and workspace")
	}
	copyLines := append([]Line(nil), lines...)
	for i := range copyLines {
		copyLines[i].Fields = cloneFields(copyLines[i].Fields)
	}
	entry := archivedLog{Version: 1, Sandbox: name, Workspace: workspace, ArchivedAt: time.Now().UTC(), Lines: copyLines}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode sandbox log archive: %w", err)
	}
	for len(data) > maxArchiveBytes && len(entry.Lines) > 0 {
		if len(entry.Lines) == 1 {
			return fmt.Errorf("sandbox log archive exceeds size limit")
		}
		drop := max(1, len(entry.Lines)*(len(data)-maxArchiveBytes)/len(data))
		if drop >= len(entry.Lines) {
			drop = len(entry.Lines) - 1
		}
		entry.Lines = entry.Lines[drop:]
		data, err = json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("encode sandbox log archive: %w", err)
		}
	}
	if len(data) > maxArchiveBytes {
		return fmt.Errorf("sandbox log archive exceeds size limit")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeArchiveAtomic(s.path(name), data); err != nil {
		return fmt.Errorf("persist sandbox log archive: %w", err)
	}
	return s.prune(time.Now().UTC())
}

func (s *archiveStore) Load(name string) (archivedLog, bool, error) {
	if name == "" {
		return archivedLog{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.path(name)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return archivedLog{}, false, nil
	}
	if err != nil {
		return archivedLog{}, false, fmt.Errorf("inspect sandbox log archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return archivedLog{}, false, fmt.Errorf("sandbox log archive is not a regular file")
	}
	if info.Size() > maxArchiveBytes {
		return archivedLog{}, false, fmt.Errorf("sandbox log archive exceeds size limit")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return archivedLog{}, false, fmt.Errorf("read sandbox log archive: %w", err)
	}
	var entry archivedLog
	if err := json.Unmarshal(data, &entry); err != nil || entry.Version != 1 || entry.Sandbox != name || entry.Workspace == "" || entry.ArchivedAt.IsZero() {
		return archivedLog{}, false, fmt.Errorf("sandbox log archive is invalid")
	}
	if time.Since(entry.ArchivedAt) > archiveRetention {
		_ = os.Remove(path)
		return archivedLog{}, false, nil
	}
	return entry, true, nil
}

func (s *archiveStore) Workspace(name string) (string, bool, error) {
	entry, ok, err := s.Load(name)
	if err != nil || !ok {
		return "", ok, err
	}
	return entry.Workspace, true, nil
}

func (s *archiveStore) Remove(name string) error {
	if name == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path(name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *archiveStore) prune(now time.Time) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("list sandbox log archives: %w", err)
	}
	type archiveFile struct {
		path    string
		modTime time.Time
	}
	var files []archiveFile
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".logs-archive-") {
			path := filepath.Join(s.dir, entry.Name())
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
				_ = os.Remove(path)
			}
			continue
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if now.Sub(info.ModTime()) > archiveRetention {
			_ = os.Remove(path)
			continue
		}
		files = append(files, archiveFile{path: path, modTime: info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })
	for len(files) > maxArchivedLogs {
		_ = os.Remove(files[0].path)
		files = files[1:]
	}
	return nil
}

func writeArchiveAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".logs-archive-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Rename replaces the previous archive in one filesystem operation, so a
	// reader never observes a gap while a sandbox is being deleted again.
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncArchiveDirectory(filepath.Dir(path))
}

func cloneFields(fields map[string]string) map[string]string {
	if fields == nil {
		return nil
	}
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}
