package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	pathpkg "path"
	"strconv"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxBrowserFileBytes        = 16 << 20
	maxBrowserFileListBytes    = 2 << 20
	maxBrowserFileListEntries  = 1000
	browserFileConcurrentLimit = 8
	browserFileExecTimeout     = 60
)

var errBrowserFileOutputLimit = errors.New("sandbox file output exceeds gateway limit")

const browserFileListScript = `import json, os, stat, sys

def parts_for(raw):
    parts = raw.split("/") if raw else []
    if any(not p or p in (".", "..") or "\x00" in p for p in parts):
        raise ValueError("invalid relative path")
    return parts

def open_dir(root, raw):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in parts_for(raw):
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise

try:
    fd = open_dir(sys.argv[1], sys.argv[2])
    try:
        entries = []
        truncated = False
        with os.scandir(fd) as scan:
            for index, entry in enumerate(scan):
                if index >= int(sys.argv[3]):
                    truncated = True
                    break
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    kind = "symlink"
                elif stat.S_ISDIR(info.st_mode):
                    kind = "directory"
                elif stat.S_ISREG(info.st_mode):
                    kind = "file"
                else:
                    kind = "other"
                entries.append({"name": entry.name, "kind": kind, "sizeBytes": info.st_size if kind == "file" else 0, "modifiedAtUnixMs": int(info.st_mtime * 1000)})
        entries.sort(key=lambda item: item["name"].casefold())
        print(json.dumps({"entries": entries, "truncated": truncated}, separators=(",", ":")))
    finally:
        os.close(fd)
except FileNotFoundError:
    sys.exit(44)
except (OSError, ValueError, IndexError):
    sys.exit(45)
`

const browserFileUploadScript = `import os, secrets, stat, sys

def parts_for(raw):
    parts = raw.split("/") if raw else []
    if not parts or any(not p or p in (".", "..") or "\x00" in p for p in parts):
        raise ValueError("invalid relative path")
    return parts

def open_parent(root, raw):
    parts = parts_for(raw)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise

temp_name = None
try:
    root, rel, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])
    parent, name = open_parent(root, rel)
    try:
        try:
            existing = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode):
                sys.exit(45)
        except FileNotFoundError:
            pass
        temp_name = ".cautem-upload-" + secrets.token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        file_fd = os.open(temp_name, flags, 0o600, dir_fd=parent)
        try:
            with os.fdopen(file_fd, "wb") as output:
                total = 0
                while True:
                    chunk = sys.stdin.buffer.read(min(65536, limit + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        sys.exit(46)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_name, name, src_dir_fd=parent, dst_dir_fd=parent)
            temp_name = None
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=parent)
                except FileNotFoundError:
                    pass
    finally:
        os.close(parent)
except FileNotFoundError:
    sys.exit(44)
except (OSError, ValueError, IndexError):
    sys.exit(45)
`

const browserFileDownloadScript = `import os, stat, sys

def parts_for(raw):
    parts = raw.split("/") if raw else []
    if not parts or any(not p or p in (".", "..") or "\x00" in p for p in parts):
        raise ValueError("invalid relative path")
    return parts

def open_parent(root, raw):
    parts = parts_for(raw)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise

parent = -1
file_fd = -1
try:
    parent, name = open_parent(sys.argv[1], sys.argv[2])
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    file_fd = os.open(name, flags, dir_fd=parent)
    info = os.fstat(file_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > int(sys.argv[3]):
        sys.exit(46)
    with os.fdopen(file_fd, "rb") as source:
        file_fd = -1
        total = 0
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > int(sys.argv[3]):
                sys.exit(46)
            sys.stdout.buffer.write(chunk)
except FileNotFoundError:
    sys.exit(44)
except (OSError, ValueError, IndexError):
    sys.exit(45)
finally:
    if file_fd >= 0:
        os.close(file_fd)
    if parent >= 0:
        os.close(parent)
`

func mountBrowserFiles(mux *http.ServeMux, st *store.Store, runtime *grpcRuntime, opt Options) {
	slots := make(chan struct{}, browserFileConcurrentLimit)
	mux.HandleFunc("GET /v1/sandboxes/{sandbox}/files", func(w http.ResponseWriter, r *http.Request) {
		release, ok := acquireBrowserFileSlot(w, slots)
		if !ok {
			return
		}
		defer release()
		sandbox, relative, err := browserFileRequestAccess(r, st, false, true)
		if err != nil {
			writeBrowserFileError(w, err)
			return
		}
		output, exitCode, err := runBrowserFileCommand(r.Context(), runtime, opt, sandbox.Name, relative, browserFileListScript, []string{strconv.Itoa(maxBrowserFileListEntries)}, nil, maxBrowserFileListBytes)
		if err != nil || exitCode != 0 {
			writeBrowserFileCommandError(w, err, exitCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(output)
	})
	mux.HandleFunc("PUT /v1/sandboxes/{sandbox}/files", func(w http.ResponseWriter, r *http.Request) {
		release, ok := acquireBrowserFileSlot(w, slots)
		if !ok {
			return
		}
		defer release()
		sandbox, relative, err := browserFileRequestAccess(r, st, true, false)
		if err != nil {
			writeBrowserFileError(w, err)
			return
		}
		if r.ContentLength > maxBrowserFileBytes {
			http.Error(w, "file exceeds the 16 MiB upload limit", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBrowserFileBytes))
		if err != nil {
			http.Error(w, "file exceeds the 16 MiB upload limit", http.StatusRequestEntityTooLarge)
			return
		}
		_, exitCode, err := runBrowserFileCommand(r.Context(), runtime, opt, sandbox.Name, relative, browserFileUploadScript, []string{strconv.Itoa(maxBrowserFileBytes)}, body, 0)
		if err != nil || exitCode != 0 {
			writeBrowserFileCommandError(w, err, exitCode)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/sandboxes/{sandbox}/files/download", func(w http.ResponseWriter, r *http.Request) {
		release, ok := acquireBrowserFileSlot(w, slots)
		if !ok {
			return
		}
		defer release()
		sandbox, relative, err := browserFileRequestAccess(r, st, false, false)
		if err != nil {
			writeBrowserFileError(w, err)
			return
		}
		output, exitCode, err := runBrowserFileCommand(r.Context(), runtime, opt, sandbox.Name, relative, browserFileDownloadScript, []string{strconv.Itoa(maxBrowserFileBytes)}, nil, maxBrowserFileBytes)
		if err != nil || exitCode != 0 {
			writeBrowserFileCommandError(w, err, exitCode)
			return
		}
		filename := pathpkg.Base(relative)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Length", strconv.Itoa(len(output)))
		_, _ = w.Write(output)
	})
}

func acquireBrowserFileSlot(w http.ResponseWriter, slots chan struct{}) (func(), bool) {
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		http.Error(w, "file transfer capacity reached", http.StatusServiceUnavailable)
		return nil, false
	}
}

func browserFileRequestAccess(r *http.Request, st *store.Store, write, allowRoot bool) (store.Sandbox, string, error) {
	name := r.PathValue("sandbox")
	if !validDNSLabel(name) {
		return store.Sandbox{}, "", status.Error(codes.NotFound, "sandbox not found")
	}
	sandbox, ok := st.GetSandbox(name)
	if !ok {
		return store.Sandbox{}, "", status.Error(codes.NotFound, "sandbox not found")
	}
	principal := PrincipalFrom(r.Context())
	workspace := defaultWorkspace(sandbox.Workspace)
	if write {
		if err := (&openShellRPC{runtime: &grpcRuntime{st: st}}).requireSandboxWrite(withPrincipal(r.Context(), principal), workspace); err != nil {
			return store.Sandbox{}, "", err
		}
	} else if err := requireSandboxReadWorkspace(withPrincipal(r.Context(), principal), st, workspace); err != nil {
		return store.Sandbox{}, "", err
	}
	if !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") {
		return store.Sandbox{}, "", status.Error(codes.FailedPrecondition, "sandbox is not running")
	}
	values := r.URL.Query()["path"]
	if len(values) > 1 {
		return store.Sandbox{}, "", status.Error(codes.InvalidArgument, "path must be provided once")
	}
	relative := ""
	if len(values) == 1 {
		relative = values[0]
	}
	clean, err := validateBrowserFilePath(relative, allowRoot)
	if err != nil {
		return store.Sandbox{}, "", status.Error(codes.InvalidArgument, "invalid workspace relative path")
	}
	return sandbox, clean, nil
}

func validateBrowserFilePath(raw string, allowRoot bool) (string, error) {
	if raw == "" {
		if allowRoot {
			return "", nil
		}
		return "", errors.New("file path required")
	}
	if len(raw) > 4096 || strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\\x00") || pathpkg.Clean(raw) != raw {
		return "", errors.New("path must be relative and clean")
	}
	parts := strings.Split(raw, "/")
	if len(parts) > 128 {
		return "", errors.New("path has too many components")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return "", errors.New("invalid path component")
		}
	}
	return raw, nil
}

func runBrowserFileCommand(ctx context.Context, runtime *grpcRuntime, _ Options, sandbox, relative, script string, extraArgs []string, stdin []byte, outputLimit int) ([]byte, int32, error) {
	if runtime == nil || runtime.relay == nil {
		return nil, 0, status.Error(codes.Unavailable, "sandbox relay is unavailable")
	}
	args := []string{"python3", "-c", script, "/workspace", relative}
	args = append(args, extraArgs...)
	req := &openshellv1.ExecSandboxRequest{SandboxId: sandbox, Command: args, Workdir: "/workspace", Stdin: stdin, TimeoutSeconds: browserFileExecTimeout, NoLoginShell: true}
	commandCtx, cancel := context.WithTimeout(ctx, browserFileExecTimeout*time.Second)
	defer cancel()
	var output bytes.Buffer
	send := func(event *openshellv1.ExecSandboxEvent) error {
		var data []byte
		switch payload := event.GetPayload().(type) {
		case *openshellv1.ExecSandboxEvent_Stdout:
			data = payload.Stdout.GetData()
		case *openshellv1.ExecSandboxEvent_Stderr:
			return nil
		default:
			return nil
		}
		if len(data) > outputLimit-output.Len() {
			return errBrowserFileOutputLimit
		}
		_, _ = output.Write(data)
		return nil
	}
	code, err := execSandboxOverRelay(commandCtx, runtime.relay, sandbox, req, send)
	return output.Bytes(), code, err
}

func writeBrowserFileError(w http.ResponseWriter, err error) {
	switch status.Code(err) {
	case codes.Unauthenticated:
		http.Error(w, "authentication required", http.StatusUnauthorized)
	case codes.PermissionDenied:
		http.Error(w, "workspace file access denied", http.StatusForbidden)
	case codes.NotFound:
		http.Error(w, "sandbox not found", http.StatusNotFound)
	case codes.FailedPrecondition:
		http.Error(w, "sandbox must be running", http.StatusServiceUnavailable)
	case codes.InvalidArgument:
		http.Error(w, "invalid workspace relative path", http.StatusBadRequest)
	default:
		http.Error(w, "workspace file service is unavailable", http.StatusBadGateway)
	}
}

func writeBrowserFileCommandError(w http.ResponseWriter, err error, exitCode int32) {
	if errors.Is(err, errBrowserFileOutputLimit) || exitCode == 46 {
		http.Error(w, "file or directory listing exceeds gateway limit", http.StatusRequestEntityTooLarge)
		return
	}
	if exitCode == 44 {
		http.Error(w, "workspace path not found", http.StatusNotFound)
		return
	}
	if exitCode == 45 {
		http.Error(w, "workspace path is not a regular file or safe directory", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "sandbox file operation failed", http.StatusBadGateway)
		return
	}
	http.Error(w, fmt.Sprintf("sandbox file operation exited with status %d", exitCode), http.StatusBadGateway)
}
