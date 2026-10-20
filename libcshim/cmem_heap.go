//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package libcshim

// offHeap is false here: there is no portable anonymous mapping, so C memory
// is a Go byte slice kept reachable from the TLS. Go's collector does not
// move heap objects, so the addresses stay valid; what is lost is checkptr
// cleanliness (-race reports the uintptr conversions as invalid).
const offHeap = false

func osAlloc(n int) ([]byte, error) { return make([]byte, n), nil }

func osFree([]byte) {}
