//go:build windows

package recon

import "os"

// fileOwner has no Unix owner to report on Windows. Callers treat that as
// "not root owned", so no binary is ever trusted for root execution there.
func fileOwner(os.FileInfo) (uid, gid uint32, ok bool) {
	return 0, 0, false
}
