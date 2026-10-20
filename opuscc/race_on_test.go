//go:build race

package opuscc

// raceBuild is true under -race; see decoderLaundersLocalsUnderRace.
const raceBuild = true

const decoderLaundersLocalsUnderRace = "decoder launders local addresses through uintptr; wrong under a moving stack (README: Fork notes)"
