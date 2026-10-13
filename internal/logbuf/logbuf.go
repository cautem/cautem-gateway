// Package logbuf is an in-memory ring buffer of sandbox observation log lines
// (OpenShell-style gateway-buffered WatchSandbox / SSE).
package logbuf

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	maxResidentBuffers = 64
	maxRetainedBytes   = 1 << 20
	maxLineBytes       = 64 << 10
	maxLineFields      = 128
)

// Line is one observation log entry.
type Line struct {
	Sequence uint64            `json:"sequence"`
	TS       time.Time         `json:"ts"`
	Source   string            `json:"source"` // proxy | sandbox | proc | gateway
	Level    string            `json:"level"`  // INFO | MED | HIGH | OCSF | …
	Target   string            `json:"target,omitempty"`
	Text     string            `json:"text"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// Buffer is a bounded per-sandbox ring (drop oldest under load).
type Buffer struct {
	mu       sync.Mutex
	max      int
	lines    []Line
	waiters  []chan struct{}
	watchers map[chan struct{}]struct{}
	sequence uint64
	retained int
}

// Hub maps sandbox name → Buffer.
type Hub struct {
	mu       sync.Mutex
	appendMu sync.Mutex
	max      int
	buffers  map[string]*Buffer
	clock    uint64
	used     map[string]uint64
	archive  *archiveStore
}

// NewHub creates a hub with per-sandbox capacity max (default 4096).
func NewHub(max int) *Hub {
	if max <= 0 {
		max = 4096
	}
	return &Hub{max: max, buffers: map[string]*Buffer{}, used: map[string]uint64{}}
}

// NewPersistentHub creates a bounded live log hub with an on-disk archive for
// deleted managed sandboxes. Archives are retained separately from the live
// ring so sandbox cleanup does not erase the operator's final log tail.
func NewPersistentHub(max int, archiveDir string) (*Hub, error) {
	h := NewHub(max)
	archive, err := openArchiveStore(archiveDir)
	if err != nil {
		return nil, err
	}
	h.archive = archive
	return h, nil
}

func (h *Hub) buf(name string) *Buffer {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.buffers[name]
	if !ok {
		h.evictOldestLocked()
		b = &Buffer{max: h.max, watchers: map[chan struct{}]struct{}{}}
		h.buffers[name] = b
	}
	h.clock++
	h.used[name] = h.clock
	return b
}

// evictOldestLocked bounds resident rings. Call with h.mu held.
func (h *Hub) evictOldestLocked() {
	if len(h.buffers) < maxResidentBuffers {
		return
	}
	var oldest string
	var oldestAt uint64
	foundOldest := false
	for candidate, at := range h.used {
		if !foundOldest || at < oldestAt {
			oldest, oldestAt = candidate, at
			foundOldest = true
		}
	}
	if evicted := h.buffers[oldest]; evicted != nil {
		evicted.mu.Lock()
		for ch := range evicted.watchers {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		evicted.mu.Unlock()
	}
	delete(h.buffers, oldest)
	delete(h.used, oldest)
}

// Append adds lines for a sandbox.
func (h *Hub) Append(sandbox string, lines []Line) {
	if sandbox == "" || len(lines) == 0 {
		return
	}
	h.appendMu.Lock()
	defer h.appendMu.Unlock()
	b := h.buf(sandbox)
	b.append(lines)
}

// Retain archives the latest bounded log tail before a sandbox registry entry
// is deleted, then releases the live ring from memory.
func (h *Hub) Retain(sandbox, workspace string) error {
	if h == nil || h.archive == nil || sandbox == "" || workspace == "" {
		return fmt.Errorf("sandbox log archive is unavailable")
	}
	h.appendMu.Lock()
	defer h.appendMu.Unlock()
	h.mu.Lock()
	b := h.buffers[sandbox]
	h.mu.Unlock()
	var lines []Line
	if b != nil {
		lines, _ = b.tail(0)
	} else {
		previous, ok, err := h.archive.Load(sandbox)
		if err != nil {
			return err
		}
		if ok {
			if previous.Workspace != workspace {
				return fmt.Errorf("sandbox log archive belongs to another workspace")
			}
			h.Remove(sandbox)
			return nil
		}
	}
	if err := h.archive.Save(sandbox, workspace, lines); err != nil {
		return err
	}
	h.Remove(sandbox)
	return nil
}

// RestoreArchive loads retained logs into the live ring and returns their
// owning workspace. The caller must still authorize that workspace.
func (h *Hub) RestoreArchive(sandbox string) (string, bool, error) {
	if h == nil || h.archive == nil || sandbox == "" {
		return "", false, nil
	}
	h.appendMu.Lock()
	defer h.appendMu.Unlock()
	h.mu.Lock()
	if h.buffers[sandbox] != nil {
		h.mu.Unlock()
		workspace, ok, err := h.archive.Workspace(sandbox)
		return workspace, ok, err
	}
	h.mu.Unlock()
	archived, ok, err := h.archive.Load(sandbox)
	if err != nil || !ok {
		return "", ok, err
	}
	b := &Buffer{max: h.max, watchers: map[chan struct{}]struct{}{}}
	b.restore(archived.Lines)
	h.mu.Lock()
	if h.buffers[sandbox] == nil {
		h.evictOldestLocked()
		h.buffers[sandbox] = b
		h.clock++
		h.used[sandbox] = h.clock
	}
	h.mu.Unlock()
	return archived.Workspace, true, nil
}

// ClearArchive drops an old sandbox-name archive before the name is reused.
func (h *Hub) ClearArchive(sandbox string) error {
	if h == nil || sandbox == "" {
		return nil
	}
	h.appendMu.Lock()
	defer h.appendMu.Unlock()
	if h.archive == nil {
		h.Remove(sandbox)
		return nil
	}
	if err := h.archive.Remove(sandbox); err != nil {
		return err
	}
	h.Remove(sandbox)
	return nil
}

// Snapshot returns a copy of recent lines (optionally filtered).
func (h *Hub) Snapshot(sandbox string, since time.Time, source, level string, limit int) []Line {
	return h.buf(sandbox).snapshot(since, source, level, limit)
}

// Subscribe returns a channel closed when new lines arrive; call again after drain.
func (h *Hub) Subscribe(sandbox string) <-chan struct{} {
	return h.buf(sandbox).subscribe()
}

// Watch subscribes to persistent edge notifications. The returned cancel
// function must be called when the consumer exits.
func (h *Hub) Watch(sandbox string) (<-chan struct{}, func()) {
	b := h.buf(sandbox)
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.watchers[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.watchers, ch)
		b.mu.Unlock()
	}
}

// Tail returns the newest lines and the current sequence cursor atomically.
func (h *Hub) Tail(sandbox string, limit int) ([]Line, uint64) {
	return h.buf(sandbox).tail(limit)
}

// TailFiltered returns the newest matching lines and the current buffer cursor
// from one atomic snapshot.
func (h *Hub) TailFiltered(sandbox string, limit int, since time.Time, source, level string) ([]Line, uint64) {
	return h.buf(sandbox).tailFiltered(limit, since, source, level)
}

// After returns buffered lines appended after sequence.
func (h *Hub) After(sandbox string, sequence uint64) []Line {
	return h.buf(sandbox).after(sequence)
}

// ReadAfter reports whether a cursor has fallen outside the retained ring.
// Lines, latest cursor and gap status are read under one buffer lock.
func (h *Hub) ReadAfter(sandbox string, sequence uint64) ([]Line, uint64, bool) {
	b := h.buf(sandbox)
	b.mu.Lock()
	defer b.mu.Unlock()
	expired := sequence > b.sequence || (len(b.lines) > 0 && sequence < b.lines[0].Sequence-1)
	if expired {
		return nil, b.sequence, true
	}
	var out []Line
	for _, line := range b.lines {
		if line.Sequence > sequence {
			out = append(out, line)
		}
	}
	return out, b.sequence, false
}

// Names returns sandboxes that have any buffered lines.
func (h *Hub) Names() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.buffers))
	for k := range h.buffers {
		out = append(out, k)
	}
	return out
}

// Remove drops the ring buffer for a sandbox (call on sandbox delete).
// OpenShell TracingLogBus.remove cleans the same way; without this, deleted
// names keep up to max lines in gateway RSS until process restart.
func (h *Hub) Remove(sandbox string) {
	if h == nil || sandbox == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.buffers, sandbox)
	delete(h.used, sandbox)
}

func (b *Buffer) append(lines []Line) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ln := range lines {
		ln = boundLine(ln)
		b.sequence++
		ln.Sequence = b.sequence
		if ln.TS.IsZero() {
			ln.TS = time.Now().UTC()
		}
		b.lines = append(b.lines, ln)
		b.retained += lineSize(ln)
	}
	for len(b.lines) > b.max || b.retained > maxRetainedBytes {
		b.retained -= lineSize(b.lines[0])
		b.lines[0] = Line{}
		b.lines = b.lines[1:]
	}
	for _, ch := range b.waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	b.waiters = nil
	for ch := range b.watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (b *Buffer) restore(lines []Line) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, line := range lines {
		line = boundLine(line)
		if line.Sequence == 0 {
			b.sequence++
			line.Sequence = b.sequence
		} else if line.Sequence > b.sequence {
			b.sequence = line.Sequence
		}
		if line.TS.IsZero() {
			line.TS = time.Now().UTC()
		}
		b.lines = append(b.lines, line)
		b.retained += lineSize(line)
	}
	for len(b.lines) > b.max || b.retained > maxRetainedBytes {
		b.retained -= lineSize(b.lines[0])
		b.lines[0] = Line{}
		b.lines = b.lines[1:]
	}
}

func boundLine(line Line) Line {
	// Keep metadata and field payloads within one fixed budget. Sorting makes
	// which fields survive deterministic when an entry is oversized.
	budget := maxLineBytes - 64
	line.Source = truncate(line.Source, 64)
	line.Level = truncate(line.Level, 32)
	line.Target = truncate(line.Target, 256)
	used := len(line.Source) + len(line.Level) + len(line.Target)
	if used > budget {
		line.Target = truncate(line.Target, budget-len(line.Source)-len(line.Level))
		used = len(line.Source) + len(line.Level) + len(line.Target)
	}
	line.Text = truncate(line.Text, budget-used)
	used += len(line.Text)
	keys := make([]string, 0, len(line.Fields))
	for key := range line.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fields := make(map[string]string, len(keys))
	for _, key := range keys {
		if len(fields) == maxLineFields {
			break
		}
		value := line.Fields[key]
		if used+len(key)+len(value) > maxLineBytes {
			continue
		}
		fields[key] = value
		used += len(key) + len(value)
	}
	line.Fields = fields
	return line
}

func truncate(value string, limit int) string {
	if limit < 0 {
		return ""
	}
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func lineSize(line Line) int {
	size := len(line.Source) + len(line.Level) + len(line.Target) + len(line.Text) + 64
	for key, value := range line.Fields {
		size += len(key) + len(value)
	}
	return size
}

func (b *Buffer) tail(limit int) ([]Line, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	start := 0
	if limit > 0 && len(b.lines) > limit {
		start = len(b.lines) - limit
	}
	return append([]Line(nil), b.lines[start:]...), b.sequence
}

func (b *Buffer) tailFiltered(limit int, since time.Time, source, level string) ([]Line, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Line
	for _, line := range b.lines {
		if Matches(line, since, source, level) {
			out = append(out, line)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return append([]Line(nil), out...), b.sequence
}

func (b *Buffer) after(sequence uint64) []Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Line
	for _, line := range b.lines {
		if line.Sequence > sequence {
			out = append(out, line)
		}
	}
	return out
}

func (b *Buffer) subscribe() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan struct{}, 1)
	b.waiters = append(b.waiters, ch)
	return ch
}

func (b *Buffer) snapshot(since time.Time, source, level string, limit int) []Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Line
	for _, ln := range b.lines {
		if !Matches(ln, since, source, level) {
			continue
		}
		out = append(out, ln)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return append([]Line{}, out...)
}

// Matches reports whether a line satisfies the same filters as Snapshot.
func Matches(line Line, since time.Time, source, level string) bool {
	if !since.IsZero() && line.TS.Before(since) {
		return false
	}
	if source != "" && line.Source != source {
		return false
	}
	return level == "" || levelMatch(line.Level, level)
}

func levelMatch(got, want string) bool {
	if got == want {
		return true
	}
	// warn matches MED/HIGH style shorthand
	switch want {
	case "warn", "warning":
		return got == "MED" || got == "WARN" || got == "HIGH"
	case "error":
		return got == "HIGH" || got == "CRIT" || got == "FATAL" || got == "ERROR"
	case "debug", "info":
		return got == "INFO" || got == "LOW" || got == "OCSF" || got == ""
	}
	return false
}
