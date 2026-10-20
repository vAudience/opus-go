package libcshim

import (
	"fmt"
	"math"
	"math/bits"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

// This package implements the minimal C-runtime-like surface that the
// ccgo-generated Opus bindings rely on.
//
// It is stdlib-only and intentionally small; it is not a general-purpose libc.

type Tpthread_key_t = uint32

const (
	// pseudoStackSize is the fixed size of a TLS's Alloc/Free region. It is
	// reserved, not committed: an anonymous mapping costs only the pages the
	// code touches. The deepest measured use is ~19 KiB (a 10-minute encode at
	// complexity 10), so this is ~50x headroom.
	pseudoStackSize = 1 << 20
	// arenaChunkSize is the unit small Xmalloc requests are carved from.
	arenaChunkSize = 64 << 10
	// dedicatedThreshold: a request larger than this gets its own mapping, so
	// one large allocation cannot strand most of a chunk and Xfree can return
	// it immediately.
	dedicatedThreshold = arenaChunkSize / 4
	// cAlign is the alignment every allocation is given (malloc's max_align_t).
	cAlign = 16
)

// TLS is a per-decoder state object used by ccgo-generated code.
//
// It provides:
// - a simple LIFO "stack" allocator (Alloc/Free) for temporary scratch
// - a very small malloc/free implementation for long-lived allocations
// - pthread-specific storage emulation for the ccgo TLS pseudostack
//
// ⚠ The generated code holds addresses into all of this memory as plain
// uintptrs, which the Go runtime does not track. Two rules follow, and the
// allocator below exists to keep them:
//
//   - memory must NEVER MOVE while an address into it may be live. The stack
//     used to grow by copying into a larger slice, leaving every outstanding
//     address pointing into the old one — which nothing then kept alive, so
//     the collector could free and reuse it (a use-after-free). The stack is
//     now fixed-size and an overflow panics.
//   - memory should live OUTSIDE the Go heap (osAlloc). A uintptr into a Go
//     object is invisible to the collector and is refused by checkptr under
//     -race; a uintptr into an anonymous mapping is just an address.
//
// All memory is released by Close (also run by a finalizer as a backstop,
// since mapped memory is not reclaimed by the collector).
type TLS struct {
	stack []byte
	sp    int

	heapMu sync.Mutex
	heap   map[uintptr]*heapAlloc
	// arena is the chunk small allocations are currently carved from. A chunk
	// is unmapped as soon as its last allocation is freed (or rewound, if it
	// is the current one), so a long-lived TLS doing malloc/free pairs holds
	// only its live allocations plus one chunk — never its whole history.
	arena    *arenaChunk
	arenaOff int
	chunks   map[*arenaChunk]struct{}

	keysMu sync.Mutex
	keys   map[Tpthread_key_t]uintptr
}

type heapAlloc struct {
	buf []byte
	// chunk is the arena chunk an allocation was carved from, or nil for an
	// allocation with its own mapping (unmapped by Xfree).
	chunk *arenaChunk
}

// arenaChunk is one mapping small allocations are carved from, with the count
// of its allocations not yet freed.
type arenaChunk struct {
	buf  []byte
	live int
}

// NewTLS returns a TLS, or nil if its pseudo-stack cannot be mapped.
//
//go:nocheckptr
func NewTLS() *TLS {
	stack, err := osAlloc(pseudoStackSize)
	if err != nil {
		return nil
	}
	t := &TLS{
		stack: stack,
		heap:  make(map[uintptr]*heapAlloc),
		keys:  make(map[Tpthread_key_t]uintptr),
	}
	runtime.SetFinalizer(t, (*TLS).Close)
	return t
}

// Close releases every region the TLS owns. It is idempotent; using memory
// obtained from a closed TLS is a use-after-free, exactly as in C.
//
//go:nocheckptr
func (t *TLS) Close() {
	if t == nil {
		return
	}
	t.heapMu.Lock()
	for _, a := range t.heap {
		if a.chunk == nil {
			osFree(a.buf)
		}
	}
	for c := range t.chunks {
		osFree(c.buf)
	}
	if t.stack != nil {
		osFree(t.stack)
	}
	t.heap, t.chunks, t.arena, t.arenaOff = nil, nil, nil, 0
	t.stack, t.sp = nil, 0
	t.heapMu.Unlock()

	t.keysMu.Lock()
	t.keys = nil
	t.keysMu.Unlock()
}

//go:nocheckptr
func align16(n int) int { return (n + 15) &^ 15 }

//go:nocheckptr
func ptrAdd(p unsafe.Pointer, off uintptr) unsafe.Pointer { return unsafe.Add(p, off) }

// Alloc returns a pointer to at least n bytes of temporary memory.
// The memory is 16-byte aligned and valid until the matching Free.
//
// ⛔ It never grows: growing means moving, and moving invalidates every
// address already handed out. Exhaustion is a bug in this package's sizing,
// reported as a panic rather than as silent corruption.
//
//go:nocheckptr
func (t *TLS) Alloc(n int) uintptr {
	if t == nil {
		return 0
	}
	if n <= 0 {
		return 0
	}
	n = align16(n)
	if t.sp+n > len(t.stack) {
		panic(fmt.Sprintf("libcshim: pseudo-stack exhausted: need %d bytes, %d of %d in use", n, t.sp, len(t.stack)))
	}
	base := unsafe.Pointer(unsafe.SliceData(t.stack))
	p := uintptr(ptrAdd(base, uintptr(t.sp)))
	t.sp += n
	return p
}

// Free releases the last Alloc(n) region.
//
//go:nocheckptr
func (t *TLS) Free(n int) {
	if t == nil {
		return
	}
	if n <= 0 {
		return
	}
	n = align16(n)
	if t.sp < n {
		panic("libcshim: TLS.Free underflow")
	}
	t.sp -= n
}

// ---- Varargs helpers (very small va_list model) ----

const ptrSize = int(unsafe.Sizeof(uintptr(0)))

// PtrSize is the size of a pointer in bytes for the current architecture.
const PtrSize = ptrSize

// VaList writes args into memory starting at p (as uintptr-sized slots) and
// returns p. This is sufficient for Opus' use of ctl varargs.
//
//go:nocheckptr
func VaList(p uintptr, args ...interface{}) uintptr {
	base := unsafe.Pointer(p)
	for i, a := range args {
		slot := ptrAdd(base, uintptr(i*ptrSize))
		switch v := a.(type) {
		case int32:
			*(*uintptr)(slot) = uintptr(uint32(v))
		case uint32:
			*(*uintptr)(slot) = uintptr(v)
		case uintptr:
			*(*uintptr)(slot) = v
		case int:
			*(*uintptr)(slot) = uintptr(v)
		default:
			panic(fmt.Sprintf("libcshim: unsupported VaList arg type %T", a))
		}
	}
	return p
}

// VaUintptr reads one uintptr argument and advances ap.
//
//go:nocheckptr
func VaUintptr(ap *uintptr) uintptr {
	v := *(*uintptr)(unsafe.Pointer(*ap))
	*ap += uintptr(ptrSize)
	return v
}

// VaInt32 reads one int32 argument (stored as a uintptr slot) and advances ap.
//
//go:nocheckptr
func VaInt32(ap *uintptr) int32 {
	v := *(*uintptr)(unsafe.Pointer(*ap))
	*ap += uintptr(ptrSize)
	return int32(uint32(v))
}

// ---- Memory allocation / libc-ish primitives ----

// Xmalloc allocates size zeroed bytes and returns a 16-byte aligned pointer,
// or 0 when the memory cannot be mapped (C's malloc returning NULL).
//
//go:nocheckptr
func Xmalloc(tls *TLS, size uint64) uintptr {
	if tls == nil {
		return 0
	}
	if size == 0 {
		size = 1
	}
	if size > uint64(^uint(0)>>1)-cAlign {
		panic("libcshim: Xmalloc too large")
	}
	n := align16(int(size))

	tls.heapMu.Lock()
	defer tls.heapMu.Unlock()
	if tls.heap == nil {
		tls.heap = make(map[uintptr]*heapAlloc)
	}
	if n > dedicatedThreshold {
		buf, err := osAlloc(n + cAlign)
		if err != nil {
			return 0
		}
		p := alignedAddr(buf)
		tls.heap[p] = &heapAlloc{buf: buf}
		return p
	}
	if tls.arena == nil || tls.arenaOff+n > len(tls.arena.buf) {
		mapped, err := osAlloc(arenaChunkSize)
		if err != nil {
			return 0
		}
		c := &arenaChunk{buf: mapped}
		if tls.chunks == nil {
			tls.chunks = make(map[*arenaChunk]struct{})
		}
		tls.chunks[c] = struct{}{}
		// The chunk it replaces stays mapped only while something in it is
		// live.
		if old := tls.arena; old != nil && old.live == 0 {
			tls.releaseChunkLocked(old)
		}
		// A mapping is page-aligned, so every offset that is a multiple of
		// 16 stays 16-byte aligned, and fresh mapped memory is zero.
		tls.arena, tls.arenaOff = c, 0
	}
	buf := tls.arena.buf[tls.arenaOff : tls.arenaOff+n : tls.arenaOff+n]
	tls.arenaOff += n
	tls.arena.live++
	p := uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
	tls.heap[p] = &heapAlloc{buf: buf, chunk: tls.arena}
	return p
}

func (tls *TLS) releaseChunkLocked(c *arenaChunk) {
	delete(tls.chunks, c)
	osFree(c.buf)
}

// alignedAddr returns the first 16-byte aligned address inside buf.
//
//go:nocheckptr
func alignedAddr(buf []byte) uintptr {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
	return (base + cAlign - 1) &^ (cAlign - 1)
}

//go:nocheckptr
func Xfree(tls *TLS, p uintptr) {
	if tls == nil || p == 0 {
		return
	}
	tls.heapMu.Lock()
	defer tls.heapMu.Unlock()
	a := tls.heap[p]
	if a == nil {
		return
	}
	delete(tls.heap, p)
	c := a.chunk
	if c == nil {
		osFree(a.buf)
		return
	}
	c.live--
	if c.live > 0 {
		return
	}
	if c != tls.arena {
		tls.releaseChunkLocked(c)
		return
	}
	// The current chunk is empty: rewind it. Xmalloc promises zeroed memory,
	// so the carved prefix is cleared before it is handed out again.
	clear(c.buf[:tls.arenaOff])
	tls.arenaOff = 0
}

//go:nocheckptr
func Xmemset(_ *TLS, s uintptr, c int32, n uint64) uintptr {
	if s == 0 || n == 0 {
		return s
	}
	if n > uint64(^uint(0)>>1) {
		panic("libcshim: Xmemset too large")
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(s)), int(n))
	fill := byte(c)
	for i := range b {
		b[i] = fill
	}
	return s
}

//go:nocheckptr
func Xmemcpy(_ *TLS, dst, src uintptr, n uint64) uintptr {
	if dst == 0 || src == 0 || n == 0 {
		return dst
	}
	if n > uint64(^uint(0)>>1) {
		panic("libcshim: Xmemcpy too large")
	}
	d := unsafe.Slice((*byte)(unsafe.Pointer(dst)), int(n))
	s := unsafe.Slice((*byte)(unsafe.Pointer(src)), int(n))
	copy(d, s)
	return dst
}

//go:nocheckptr
func Xmemmove(_ *TLS, dst, src uintptr, n uint64) uintptr {
	// Go's copy is memmove-safe.
	return Xmemcpy(nil, dst, src, n)
}

// ---- pthread TLS emulation (per *TLS instance) ----

//go:nocheckptr
func Xpthread_getspecific(tls *TLS, key uint32) uintptr {
	if tls == nil {
		return 0
	}
	tls.keysMu.Lock()
	defer tls.keysMu.Unlock()
	if tls.keys == nil {
		return 0
	}
	return tls.keys[Tpthread_key_t(key)]
}

//go:nocheckptr
func Xpthread_setspecific(tls *TLS, key uint32, value uintptr) int32 {
	if tls == nil {
		return -1
	}
	tls.keysMu.Lock()
	if tls.keys == nil {
		tls.keys = make(map[Tpthread_key_t]uintptr)
	}
	tls.keys[Tpthread_key_t(key)] = value
	tls.keysMu.Unlock()
	return 0
}

// ---- Fatal/assert/debug ----

var Xstderr uintptr = 0

//go:nocheckptr
func Xfprintf(_ *TLS, _ uintptr, format uintptr, ap uintptr) int32 {
	// Best-effort debug printing. Used by Opus_celt_fatal.
	_ = ap
	fmtStr := GoString(format)
	_, _ = fmt.Fprintf(os.Stderr, "%s", fmtStr)
	return 0
}

//go:nocheckptr
func Xabort(_ *TLS) { panic("libcshim: abort") }

//go:nocheckptr
func X__assert_fail(_ *TLS, assertion, file uintptr, line int32, _ uintptr) {
	panic(fmt.Sprintf("assertion failed: %s (%s:%d)", GoString(assertion), GoString(file), line))
}

// ---- Math/bit helpers ----

//go:nocheckptr
func Xabs(_ *TLS, x int32) int32 {
	if x < 0 {
		return -x
	}
	return x
}

//go:nocheckptr
func Xfabs(_ *TLS, x float64) float64 { return math.Abs(x) }

//go:nocheckptr
func Xfloor(_ *TLS, x float64) float64 { return math.Floor(x) }

//go:nocheckptr
func Xsqrt(_ *TLS, x float64) float64 { return math.Sqrt(x) }

//go:nocheckptr
func Xcos(_ *TLS, x float64) float64 { return math.Cos(x) }

//go:nocheckptr
func Xsin(_ *TLS, x float64) float64 { return math.Sin(x) }

//go:nocheckptr
func Xlog(_ *TLS, x float64) float64 { return math.Log(x) }

//go:nocheckptr
func Xlog10(_ *TLS, x float64) float64 { return math.Log10(x) }

//go:nocheckptr
func Xacos(_ *TLS, x float64) float64 { return math.Acos(x) }

//go:nocheckptr
func Xexp(_ *TLS, x float64) float64 { return math.Exp(x) }

//go:nocheckptr
func Xpow(_ *TLS, x, y float64) float64 { return math.Pow(x, y) }

// Xlrintf rounds to the nearest integer value, using ties-to-even.
//
//go:nocheckptr
func Xlrintf(_ *TLS, x float32) int64 { return int64(math.RoundToEven(float64(x))) }

// X__builtin_clz returns the number of leading 0-bits in x.
// C's __builtin_clz is undefined for 0; we return 32 for 0.
//
//go:nocheckptr
func X__builtin_clz(_ *TLS, x uint32) int32 {
	if x == 0 {
		return 32
	}
	return int32(bits.LeadingZeros32(x))
}

// ---- Conversions/helpers used by the generated bindings ----

//go:nocheckptr
func Bool(v bool) bool { return v }

//go:nocheckptr
func BoolInt32(v bool) int32 {
	if v {
		return 1
	}
	return 0
}

//go:nocheckptr
func BoolInt8(v bool) int8 {
	if v {
		return 1
	}
	return 0
}

//go:nocheckptr
func BoolInt64(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

//go:nocheckptr
func BoolUint32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}

//go:nocheckptr
func BoolUint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

//go:nocheckptr
func BoolUintptr(v bool) uintptr {
	if v {
		return 1
	}
	return 0
}

//go:nocheckptr
func Float32FromFloat32(v float32) float32 { return v }

//go:nocheckptr
func Float32FromFloat64(v float64) float32 { return float32(v) }

//go:nocheckptr
func Float32FromInt32(v int32) float32 { return float32(v) }

//go:nocheckptr
func Float64FromFloat32(v float32) float64 { return float64(v) }

//go:nocheckptr
func Float64FromFloat64(v float64) float64 { return v }

//go:nocheckptr
func Float64FromInt32(v int32) float64 { return float64(v) }

//go:nocheckptr
func Int16FromInt32(v int32) int16 { return int16(v) }

//go:nocheckptr
func Int16FromUint8(v uint8) int16 { return int16(v) }

//go:nocheckptr
func Int32FromInt32(v int32) int32 { return v }

//go:nocheckptr
func Int32FromInt64(v int64) int32 { return int32(v) }

//go:nocheckptr
func Int32FromUint16(v uint16) int32 { return int32(v) }

//go:nocheckptr
func Int32FromUint32(v uint32) int32 { return int32(v) }

//go:nocheckptr
func Int32FromUint64(v uint64) int32 { return int32(v) }

//go:nocheckptr
func Int32FromUint8(v uint8) int32 { return int32(v) }

//go:nocheckptr
func Int64FromInt32(v int32) int64 { return int64(v) }

//go:nocheckptr
func Uint16FromInt32(v int32) uint16 { return uint16(v) }

//go:nocheckptr
func Uint16FromInt16(v int16) uint16 { return uint16(v) }

//go:nocheckptr
func Uint32FromInt16(v int16) uint32 { return uint32(v) }

//go:nocheckptr
func Uint32FromInt32(v int32) uint32 { return uint32(v) }

//go:nocheckptr
func Uint32FromInt8(v int8) uint32 { return uint32(v) }

//go:nocheckptr
func Uint32FromUint32(v uint32) uint32 { return v }

//go:nocheckptr
func Uint64FromInt16(v int16) uint64 { return uint64(v) }

//go:nocheckptr
func Uint64FromInt32(v int32) uint64 { return uint64(v) }

//go:nocheckptr
func Uint64FromInt64(v int64) uint64 { return uint64(v) }

//go:nocheckptr
func Uint64FromUint64(v uint64) uint64 { return v }

//go:nocheckptr
func Uint8FromInt16(v int16) uint8 { return uint8(uint16(v)) }

//go:nocheckptr
func Uint8FromInt32(v int32) uint8 { return uint8(v) }

//go:nocheckptr
func UintptrFromInt32(v int32) uintptr { return uintptr(v) }

// GoString reads a NUL-terminated C string from p.
//
//go:nocheckptr
func GoString(p uintptr) string {
	if p == 0 {
		return ""
	}
	const max = 1 << 20
	buf := make([]byte, 0, 64)
	base := unsafe.Pointer(p)
	for i := 0; i < max; i++ {
		b := *(*byte)(ptrAdd(base, uintptr(i)))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

// ---- Pointer helpers for higher-level packages (to reduce unsafe usage there) ----

//go:nocheckptr
func PtrUint8(s []uint8) uintptr {
	if len(s) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(s)))
}

//go:nocheckptr
func PtrInt16(s []int16) uintptr {
	if len(s) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(s)))
}

//go:nocheckptr
func PtrByte(s []byte) uintptr {
	if len(s) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(s)))
}

//go:nocheckptr
func PtrFloat32(s []float32) uintptr {
	if len(s) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(s)))
}

//go:nocheckptr
func LoadInt32(p uintptr) int32 {
	if p == 0 {
		return 0
	}
	return *(*int32)(unsafe.Pointer(p))
}

//go:nocheckptr
func StoreInt32(p uintptr, v int32) {
	if p == 0 {
		return
	}
	*(*int32)(unsafe.Pointer(p)) = v
}

//go:nocheckptr
func LoadUintptr(p uintptr) uintptr {
	if p == 0 {
		return 0
	}
	return *(*uintptr)(unsafe.Pointer(p))
}

//go:nocheckptr
func StoreUintptr(p uintptr, v uintptr) {
	if p == 0 {
		return
	}
	*(*uintptr)(unsafe.Pointer(p)) = v
}

//go:nocheckptr
func LoadUintptrAt(base uintptr, off uintptr) uintptr {
	return LoadUintptr(base + off)
}

//go:nocheckptr
func StoreUintptrAt(base uintptr, off uintptr, v uintptr) {
	StoreUintptr(base+off, v)
}
