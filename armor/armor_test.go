package armor

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// maxLegacyWindow records the fixed 128-byte detection window that the old
// implementation used. Tests pin behavior around this boundary to prove the
// window limit is gone.
const maxLegacyWindow = 128

const armoredTestMessage = "-----BEGIN PGP MESSAGE-----\n\nabcdef\n-----END PGP MESSAGE-----\n"

// readAll drains the returned reader, asserting that it replays the complete
// original input regardless of the detection result.
func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	out, err := io.ReadAll(r)
	assert.NoError(t, err)
	return out
}

// TestIsPGPArmoredNoPreamble guards the no-preamble baseline: an armored
// message starting at byte zero is still detected.
func TestIsPGPArmoredNoPreamble(t *testing.T) {
	r, armored := IsPGPArmored(strings.NewReader(armoredTestMessage))
	assert.True(t, armored, "armored message without preamble must be detected")
	assert.Equal(t, armoredTestMessage, string(readAll(t, r)))
}

// TestIsPGPArmoredPureBinary guards the pure-binary baseline: input without an
// armor header is classified as binary and replayed unchanged.
func TestIsPGPArmoredPureBinary(t *testing.T) {
	binary := []byte{0x84, 0x00, 0x09, 0x03, 0xff, 0x10, 0x00, 0x5a}
	r, armored := IsPGPArmored(bytes.NewReader(binary))
	assert.False(t, armored, "pure binary input must not be classified as armored")
	assert.Equal(t, binary, readAll(t, r))
}

// TestIsPGPArmoredPreambleBelowLegacyWindow covers the old 128-byte window
// boundary: a preamble that fit into the legacy window still works.
func TestIsPGPArmoredPreambleBelowLegacyWindow(t *testing.T) {
	preamble := strings.Repeat("quoted line\n", 8) // 96 bytes, below 128
	input := preamble + armoredTestMessage
	r, armored := IsPGPArmored(strings.NewReader(input))
	assert.True(t, armored)
	assert.Equal(t, input, string(readAll(t, r)))
}

// TestIsPGPArmoredPreambleAtLegacyWindow pins the exact legacy window edge:
// the armor header line starts right after a 128-byte preamble.
func TestIsPGPArmoredPreambleAtLegacyWindow(t *testing.T) {
	preamble := strings.Repeat("a", maxLegacyWindow) + "\n"
	input := preamble + armoredTestMessage
	r, armored := IsPGPArmored(strings.NewReader(input))
	assert.True(t, armored)
	assert.Equal(t, input, string(readAll(t, r)))
}

// TestIsPGPArmoredPreambleHeaderOnSameLine documents that an armor marker
// embedded in a longer non-header line is not treated as armor: only a line
// whose trimmed content is a full header line qualifies.
func TestIsPGPArmoredPreambleHeaderOnSameLine(t *testing.T) {
	input := strings.Repeat("a", maxLegacyWindow) + armoredTestMessage
	r, armored := IsPGPArmored(bytes.NewReader([]byte(input)))
	assert.False(t, armored, "marker glued to a preceding line is not a header line")
	assert.Equal(t, input, string(readAll(t, r)))
}

// TestIsPGPArmoredPreambleBeyondLegacyWindow is the reported failure: the
// armor header starts well beyond the old 128-byte window and must now be
// found because detection no longer uses a fixed window.
func TestIsPGPArmoredPreambleBeyondLegacyWindow(t *testing.T) {
	preamble := strings.Repeat("On 2026-11-18 someone wrote:\n> forwarded quote line\n", 20)
	assert.Greater(t, len(preamble), maxLegacyWindow)
	input := preamble + armoredTestMessage
	r, armored := IsPGPArmored(strings.NewReader(input))
	assert.True(t, armored, "armor header beyond the legacy 128-byte window must be detected")
	assert.Equal(t, input, string(readAll(t, r)))
}

// TestIsPGPArmoredLongPreambleWithoutNewline ensures detection also works when
// the preamble contains long lines without relying on any length cap.
func TestIsPGPArmoredLongPreambleWithoutNewline(t *testing.T) {
	preamble := strings.Repeat("x", 4096) + "\n"
	input := preamble + armoredTestMessage
	r, armored := IsPGPArmored(strings.NewReader(input))
	assert.True(t, armored)
	assert.Equal(t, input, string(readAll(t, r)))
}

// TestIsPGPArmoredBinaryMarkerNoHeaderLine is the false-positive direction:
// binary data containing the raw armor marker bytes but not a full armor
// header line must not be classified as armored.
func TestIsPGPArmoredBinaryMarkerNoHeaderLine(t *testing.T) {
	binary := append([]byte{0x84, 0x00}, []byte(armorPrefix)...)
	binary = append(binary, 0x01, 0x02, 0xff)
	r, armored := IsPGPArmored(bytes.NewReader(binary))
	assert.False(t, armored, "a bare marker inside binary data is not an armor header line")
	assert.Equal(t, binary, readAll(t, r))
}

// TestIsPGPArmoredMarkerOnlyFallback checks that a marker followed by a newline
// but without the closing dashes is not treated as a complete header line.
func TestIsPGPArmoredIncompleteHeaderLine(t *testing.T) {
	input := []byte("-----BEGIN PGP MESSAGE\nrest of binary-ish data")
	r, armored := IsPGPArmored(bytes.NewReader(input))
	assert.False(t, armored, "header line missing the trailing dashes is not armor")
	assert.Equal(t, input, readAll(t, r))
}

// TestIsPGPArmoredRestart verifies the replayable reader rewinds to the first
// byte after detection, which underpins the binary fallback in the crypto
// package.
func TestIsPGPArmoredRestart(t *testing.T) {
	input := strings.Repeat("preamble text\n", 16) + armoredTestMessage
	r, armored := IsPGPArmored(strings.NewReader(input))
	assert.True(t, armored)

	restarter, ok := r.(interface{ Restart() })
	assert.True(t, ok, "detected reader should expose Restart")

	first := readAll(t, r)
	assert.Equal(t, input, string(first))
	restarter.Restart()
	second := readAll(t, r)
	assert.Equal(t, first, second, "restarted reader must replay the full input")
}

// TestIsPGPArmoredAllArmorTypes checks each supported armor block type.
func TestIsPGPArmoredAllArmorTypes(t *testing.T) {
	headers := []string{
		"-----BEGIN PGP MESSAGE-----",
		"-----BEGIN PGP SIGNATURE-----",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"-----BEGIN PGP PRIVATE KEY BLOCK-----",
	}
	for _, header := range headers {
		input := "preamble\n" + header + "\n\nAA==\n-----END X-----\n"
		r, armored := IsPGPArmored(strings.NewReader(input))
		assert.True(t, armored, header)
		assert.Equal(t, input, string(readAll(t, r)))
	}
}
