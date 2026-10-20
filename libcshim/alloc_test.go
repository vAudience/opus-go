package libcshim

import (
	"strings"
	"testing"
	"unsafe"
)

// TestAllocNeverMoves is the use-after-free regression: the stack used to grow
// by copying, abandoning every address already handed out. Fill it to within
// one allocation of capacity and the first address must still be the stack.
func TestAllocNeverMoves(t *testing.T) {
	tls := NewTLS()
	defer tls.Close()
	first := tls.Alloc(16)
	*(*uint64)(unsafe.Pointer(first)) = 0xfeedface
	for tls.sp+4096 <= pseudoStackSize {
		tls.Alloc(4096)
	}
	if got := uintptr(unsafe.Pointer(unsafe.SliceData(tls.stack))); got != first {
		t.Fatalf("stack base moved: %#x -> %#x", first, got)
	}
	if v := *(*uint64)(unsafe.Pointer(first)); v != 0xfeedface {
		t.Fatalf("first allocation lost its contents: %#x", v)
	}
}

func TestAllocOverflowPanicsInsteadOfMoving(t *testing.T) {
	tls := NewTLS()
	defer tls.Close()
	defer func() {
		r := recover()
		if s, _ := r.(string); !strings.Contains(s, "pseudo-stack exhausted") {
			t.Fatalf("want an exhaustion panic, got %v", r)
		}
	}()
	tls.Alloc(pseudoStackSize + 1)
}

func TestXmallocIsAlignedZeroedAndFreeable(t *testing.T) {
	tls := NewTLS()
	defer tls.Close()
	for _, size := range []uint64{1, 15, 16, 100, dedicatedThreshold, dedicatedThreshold + 1, 1 << 20} {
		p := Xmalloc(tls, size)
		if p == 0 {
			t.Fatalf("Xmalloc(%d) returned NULL", size)
		}
		if p%cAlign != 0 {
			t.Fatalf("Xmalloc(%d) = %#x is not %d-aligned", size, p, cAlign)
		}
		b := unsafe.Slice((*byte)(unsafe.Pointer(p)), int(size))
		for i, v := range b {
			if v != 0 {
				t.Fatalf("Xmalloc(%d) byte %d = %d, want zeroed", size, i, v)
			}
		}
		for i := range b {
			b[i] = 0xAB
		}
		Xfree(tls, p)
		if _, still := tls.heap[p]; still {
			t.Fatalf("Xfree(%#x) left the allocation registered", p)
		}
	}
}

// TestXmallocSmallAllocationsDoNotOverlap — arena carving must hand out
// disjoint regions across a chunk boundary.
func TestXmallocSmallAllocationsDoNotOverlap(t *testing.T) {
	tls := NewTLS()
	defer tls.Close()
	const size = 1000
	var ps []uintptr
	for i := 0; i < 3*arenaChunkSize/size; i++ {
		p := Xmalloc(tls, size)
		*(*int32)(unsafe.Pointer(p)) = int32(i)
		ps = append(ps, p)
	}
	for i, p := range ps {
		if v := *(*int32)(unsafe.Pointer(p)); v != int32(i) {
			t.Fatalf("allocation %d overwritten (holds %d)", i, v)
		}
	}
	if len(tls.chunks) < 3 {
		t.Fatalf("expected several arena chunks, got %d", len(tls.chunks))
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	tls := NewTLS()
	Xmalloc(tls, 10)
	Xmalloc(tls, dedicatedThreshold*2)
	tls.Close()
	tls.Close()
	if tls.stack != nil || tls.heap != nil || tls.chunks != nil {
		t.Fatal("Close left regions referenced")
	}
}

// TestMemoryIsOffHeap: on mapped platforms the addresses must not belong to
// the Go heap — that is what makes them invisible-and-irrelevant to the
// collector and acceptable to checkptr.
func TestMemoryIsOffHeap(t *testing.T) {
	if !offHeap {
		t.Skip("this platform uses the Go-heap fallback")
	}
	tls := NewTLS()
	defer tls.Close()
	p := Xmalloc(tls, 64)
	// checkptr (enabled by -race) throws on a uintptr->Pointer conversion into
	// a Go heap object with no originating pointer. Surviving these
	// conversions under -race is the assertion.
	_ = *(*byte)(unsafe.Pointer(p))
	_ = *(*byte)(unsafe.Pointer(tls.Alloc(16)))
}
