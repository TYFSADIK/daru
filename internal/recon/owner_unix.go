//go:build !windows

package recon

import (
	"os"
	"syscall"
)

// fileOwner returns the owning user and group IDs of fi.
func fileOwner(fi os.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
