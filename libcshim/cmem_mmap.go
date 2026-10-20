//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package libcshim

import "syscall"

// offHeap reports whether C memory lives outside the Go heap on this
// platform. It does here: every region is an anonymous private mapping.
const offHeap = true

// osAlloc maps n zeroed bytes outside the Go heap. The garbage collector
// neither scans nor moves nor frees this memory, so a uintptr into it is a
// plain address — exactly what the transpiled C code assumes — and the
// runtime's checkptr instrumentation (enabled by -race) accepts it.
func osAlloc(n int) ([]byte, error) {
	return syscall.Mmap(-1, 0, n, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
}

// osFree unmaps a region returned by osAlloc.
func osFree(b []byte) {
	_ = syscall.Munmap(b)
}
