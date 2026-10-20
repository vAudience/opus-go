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

// TestArenaMemoryIsReclaimed: a long-lived TLS doing malloc/free pairs must
// hold its live allocations plus one chunk — not every chunk it ever carved.
func TestArenaMemoryIsReclaimed(t *testing.T) {
	tls := NewTLS()
	defer tls.Close()
	keep := Xmalloc(tls, 100)
	*(*byte)(unsafe.Pointer(keep)) = 7
	for i := 0; i < 50*arenaChunkSize/1000; i++ {
		p := Xmalloc(tls, 1000)
		b := unsafe.Slice((*byte)(unsafe.Pointer(p)), 1000)
		for j := range b {
			if b[j] != 0 {
				t.Fatalf("iteration %d: reused memory not zeroed at %d", i, j)
			}
			b[j] = 0xCD
		}
		Xfree(tls, p)
	}
	if len(tls.chunks) > 2 {
		t.Fatalf("arena grew to %d chunks for one live allocation", len(tls.chunks))
	}
	if *(*byte)(unsafe.Pointer(keep)) != 7 {
		t.Fatal("a live allocation was clobbered by reuse")
	}
}

// TestArenaChunkReleasedWhenItsLastAllocationIsFreed — a non-current chunk
// that empties is unmapped.
func TestArenaChunkReleasedWhenItsLastAllocationIsFreed(t *testing.T) {
	tls := NewTLS()
	defer tls.Close()
	first := Xmalloc(tls, 1000)
	firstChunk := tls.heap[first].chunk
	for tls.arena == firstChunk {
		Xmalloc(tls, 1000)
	}
	// Free everything in the first chunk.
	for p, a := range tls.heap {
		if a.chunk == firstChunk {
			Xfree(tls, p)
		}
	}
	if _, still := tls.chunks[firstChunk]; still {
		t.Fatal("an emptied, non-current chunk is still mapped")
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

// TestClosedTLSMapsNothing: after Close, Xmalloc fails like a NULL malloc and
// Xfree is inert — a closed TLS must never map memory nobody will unmap.
func TestClosedTLSMapsNothing(t *testing.T) {
	tls := NewTLS()
	p := Xmalloc(tls, 32)
	tls.Close()
	if q := Xmalloc(tls, 32); q != 0 {
		t.Fatalf("Xmalloc on a closed TLS returned %#x, want 0", q)
	}
	Xfree(tls, p) // must not panic or unmap anything
	if tls.heap != nil || tls.chunks != nil {
		t.Fatal("a closed TLS grew new regions")
	}
}
