package opus

import (
	"errors"
	"unsafe"

	libc "github.com/vAudience/opus-go/libcshim"
)

// cBuf is scratch memory the transpiled libopus code can safely be handed
// a uintptr to. A caller's slice can't be: converting it to uintptr hides
// the pointer from escape analysis, so the slice may live on the goroutine
// stack, and the transpiled code's deep call chains can grow - move - that
// stack mid-call. Go fixes up real pointers when it moves a stack, but not
// uintptrs, so libopus would read from and write to the stack's old copy
// (observed as encoded packets left all-zero). cBuf memory comes from the
// shim's malloc, which keeps it reachable from the TLS and never moves it.
type cBuf struct {
	p uintptr
	n int
}

// ensure makes the buffer at least n bytes and returns its address. It
// fails when the shim cannot map memory (C's malloc returning NULL), and then
// records nothing, so a later call retries rather than reusing a NULL buffer.
func (b *cBuf) ensure(tls *libc.TLS, n int) (uintptr, error) {
	if n > b.n {
		b.free(tls)
		p := libc.Xmalloc(tls, uint64(n))
		if p == 0 {
			return 0, ErrOutOfMemory
		}
		b.p, b.n = p, n
	}
	return b.p, nil
}

func (b *cBuf) free(tls *libc.TLS) {
	if b.p != 0 {
		libc.Xfree(tls, b.p)
	}
	b.p, b.n = 0, 0
}

// cSlice views n elements of T at p - memory from a cBuf.
func cSlice[T any](p uintptr, n int) []T {
	return unsafe.Slice((*T)(unsafe.Pointer(p)), n)
}

// copyIn copies src into b (growing it as needed) and returns its
// address, or 0 for an empty src (libopus's "no packet" / packet-loss
// convention). ⚠ An allocation failure is an ERROR, never 0: 0 means "packet
// lost" to the decoder, so returning it would turn out-of-memory into
// silently concealed audio.
func copyIn[T any](tls *libc.TLS, b *cBuf, src []T) (uintptr, error) {
	if len(src) == 0 {
		return 0, nil
	}
	var zero T
	p, err := b.ensure(tls, len(src)*int(unsafe.Sizeof(zero)))
	if err != nil {
		return 0, err
	}
	copy(cSlice[T](p, len(src)), src)
	return p, nil
}

// ErrOutOfMemory reports that the C-runtime shim could not map memory.
var ErrOutOfMemory = errors.New("opus: out of memory")
