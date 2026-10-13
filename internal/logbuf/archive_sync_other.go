//go:build !unix

package logbuf

// Directory handles cannot be synced portably on every supported OS. The
// archive file itself is synced before the atomic rename.
func syncArchiveDirectory(string) error { return nil }
