package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestValidateBrowserFilePath(t *testing.T) {
	tests := []struct {
		path      string
		allowRoot bool
		wantErr   bool
	}{
		{path: "", allowRoot: true},
		{path: "src/main.go"},
		{path: "", wantErr: true},
		{path: "../secret", wantErr: true},
		{path: "src/../secret", wantErr: true},
		{path: "/etc/passwd", wantErr: true},
		{path: "a//b", wantErr: true},
		{path: "a\\b", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			_, err := validateBrowserFilePath(tt.path, tt.allowRoot)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateBrowserFilePath(%q) error=%v, wantErr=%t", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestBrowserFileScriptsTransferFilesWithoutFollowingSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("workspace-file\x00bytes")
	upload := exec.Command("python3", "-c", browserFileUploadScript, root, "nested/result.bin", "1024")
	upload.Stdin = bytes.NewReader(content)
	if output, err := upload.CombinedOutput(); err != nil {
		t.Fatalf("upload script failed: %v: %s", err, output)
	}
	got, err := os.ReadFile(filepath.Join(root, "nested", "result.bin"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("uploaded content=%q err=%v", got, err)
	}

	download := exec.Command("python3", "-c", browserFileDownloadScript, root, "nested/result.bin", "1024")
	got, err = download.Output()
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("downloaded content=%q err=%v", got, err)
	}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	unsafeUpload := exec.Command("python3", "-c", browserFileUploadScript, root, "escape/overwrite", "1024")
	unsafeUpload.Stdin = bytes.NewReader([]byte("overwrite"))
	if output, err := unsafeUpload.CombinedOutput(); !hasPythonExitCode(err, 45) {
		t.Fatalf("symlink upload err=%v output=%q, want exit 45", err, output)
	}
	if contents, err := os.ReadFile(outside); err != nil || string(contents) != "untouched" {
		t.Fatalf("outside file changed: %q err=%v", contents, err)
	}
	unsafeDownload := exec.Command("python3", "-c", browserFileDownloadScript, root, "escape/outside", "1024")
	if output, err := unsafeDownload.Output(); !hasPythonExitCode(err, 45) {
		t.Fatalf("symlink download err=%v output=%q, want exit 45", err, output)
	}

	listing := exec.Command("python3", "-c", browserFileListScript, root, "", "1000")
	output, err := listing.Output()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Entries []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"entries"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode directory listing %q: %v", output, err)
	}
	if result.Truncated || len(result.Entries) != 2 || result.Entries[0].Name != "escape" || result.Entries[0].Kind != "symlink" {
		t.Fatalf("directory listing=%+v", result)
	}
}

func hasPythonExitCode(err error, code int) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == code
}
