//go:build !race

package opuscc

const raceBuild = false

// decoderLaundersLocalsUnderRace documents why two decoder tests are skipped
// under -race: the decoder (unlike opusccenc) passes uintptr(unsafe.Pointer(&local))
// into deep call chains. -race changes stack sizes, the goroutine stack moves
// mid-call, and the callee reads the abandoned copy — the tests then observe
// WRONG VALUES, which is the defect itself, not test flakiness. Tracked
// upstream; see README "Fork notes".
const decoderLaundersLocalsUnderRace = "decoder launders local addresses through uintptr; wrong under a moving stack (README: Fork notes)"
