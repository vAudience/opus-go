package unsafeaudit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDirFindsALaunderedLocal is the positive control: a guard that reports
// zero must be shown able to report one.
func TestDirFindsALaunderedLocal(t *testing.T) {
	dir := t.TempDir()
	src := `package p

import "unsafe"

var table [4]int32

func use(uintptr) {}

func bad() {
	var local [4]int32
	use(uintptr(unsafe.Pointer(&local[0])))
}

func fine() {
	use(uintptr(unsafe.Pointer(&table[0])))
}
`
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Dir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Local != "local" || got[0].Function != "bad" {
		t.Fatalf("want exactly the local in bad(), got %v", got)
	}
}
