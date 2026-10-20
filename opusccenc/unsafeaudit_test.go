package opusccenc

import (
	"testing"

	"github.com/vAudience/opus-go/internal/unsafeaudit"
)

// TestEncoderLaundersNoLocalAddress holds the encoder at zero laundered local
// addresses (see package unsafeaudit for why one is a use-after-move). The
// decoder package (opuscc) does NOT meet this bar — see README "Fork notes".
func TestEncoderLaundersNoLocalAddress(t *testing.T) {
	got, err := unsafeaudit.Dir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		t.Errorf("laundered local address: %s", f)
	}
}
