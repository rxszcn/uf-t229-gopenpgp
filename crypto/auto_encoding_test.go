package crypto

import (
	"bytes"
	"io"
	"strings"
	"testing"

	armorHelper "github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// longPreamble is a mail-gateway style quote longer than the legacy 128-byte
// fixed detection window.
var longPreamble = "---------- Forwarded message ----------\n" +
	strings.Repeat("> this is a quoted line from the mail gateway\n", 12)

func requireGreaterThanLegacyWindow(t *testing.T, s string) {
	t.Helper()
	assert.Greater(t, len(s), 128, "preamble must exceed the legacy 128-byte detection window")
}

// malformedArmor is detected as armored (it opens with a full armor header
// line) but fails armor.Decode because a header line is missing the required
// "key: value" colon. It is a deterministic false-positive / corrupt-armor
// fixture for the binary fallback logic.
const malformedArmor = "-----BEGIN PGP SIGNATURE-----\n" +
	"badheaderwithoutcolon\n" +
	"\n\n-----END PGP SIGNATURE-----\n"

// --- Leading preamble: armored key parsing ---

func TestAutoArmoredKeyWithLongPreamble(t *testing.T) {
	requireGreaterThanLegacyWindow(t, longPreamble)
	referenceKey := keyRingTestPrivate.GetKeys()[0]
	armoredKey, err := referenceKey.Armor()
	require.NoError(t, err)

	withPreamble := []byte(longPreamble + armoredKey)

	// Auto detection must skip the preamble and parse the key.
	autoKey, err := NewKeyFromReader(bytes.NewReader(withPreamble))
	require.NoError(t, err, "Auto parse of an armored key behind a long preamble must succeed")
	assert.Equal(t, referenceKey.GetFingerprint(), autoKey.GetFingerprint())

	// Explicit Armor behaves the same because the decoder skips leading garbage.
	explicitKey, err := NewKeyFromReaderExplicit(bytes.NewReader(withPreamble), Armor)
	require.NoError(t, err)
	assert.Equal(t, referenceKey.GetFingerprint(), explicitKey.GetFingerprint())
}

// --- Leading preamble: armored message decryption ---

func TestAutoArmoredMessageWithLongPreambleDecrypts(t *testing.T) {
	encHandle, err := testPGP.Encryption().
		Recipients(keyRingTestPublic).
		New()
	require.NoError(t, err)
	decHandle, err := testPGP.Decryption().
		DecryptionKeys(keyRingTestPrivate).
		New()
	require.NoError(t, err)

	binMessage, err := encHandle.Encrypt([]byte(testMessage))
	require.NoError(t, err)
	armoredMessage, err := binMessage.ArmorBytes()
	require.NoError(t, err)
	withPreamble := append([]byte(longPreamble), armoredMessage...)

	// Auto: preamble beyond the legacy window must no longer break the chain.
	autoResult, err := decHandle.Decrypt(withPreamble, Auto)
	require.NoError(t, err)
	assert.Equal(t, testMessage, string(autoResult.Bytes()))

	// Explicit Armor remains the reference behavior.
	explicitResult, err := decHandle.Decrypt(withPreamble, Armor)
	require.NoError(t, err)
	assert.Equal(t, testMessage, string(explicitResult.Bytes()))
}

// --- Leading preamble: armored detached signature verification ---

func TestAutoArmoredSignatureWithLongPreambleVerifies(t *testing.T) {
	data := []byte(signedPlainText)
	signature, err := testSigner().Sign(data, Armor)
	require.NoError(t, err)
	withPreamble := append([]byte(longPreamble), signature...)

	autoResult, err := testVerifier().VerifyDetached(data, withPreamble, Auto)
	require.NoError(t, err)
	assert.NoError(t, autoResult.SignatureError())

	explicitResult, err := testVerifier().VerifyDetached(data, withPreamble, Armor)
	require.NoError(t, err)
	assert.NoError(t, explicitResult.SignatureError())
}

// --- Binary fallback: unit level ---

// TestDecodeArmorAutoFallsBack proves the false-positive direction: when the
// structural detector reports armored but armor.Decode rejects the content,
// Auto mode rewinds the reader and returns a nil block so the binary parser
// takes over, rather than returning a hard error.
func TestDecodeArmorAutoFallsBack(t *testing.T) {
	r, detected := armorHelper.IsPGPArmored(strings.NewReader(malformedArmor))
	require.True(t, detected, "fixture must trip the structural detector")
	replay, ok := r.(restartable)
	require.True(t, ok, "detected reader must support restart for fallback")

	block, err := decodeArmor(r, replay, Auto, "gopenpgp: unarmor failed")
	require.NoError(t, err, "Auto mode must fall back instead of hard-erroring")
	assert.Nil(t, block, "nil block signals the caller to parse as binary")

	// The reader must have been rewound to the first byte for the binary parser.
	replay.Restart()
	rest, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, malformedArmor, string(rest))
}

// TestDecodeArmorExplicitHardError proves explicit Armor keeps the strict
// behavior: a decode failure is surfaced as an error, never silently retried.
func TestDecodeArmorExplicitHardError(t *testing.T) {
	r, _ := armorHelper.IsPGPArmored(strings.NewReader(malformedArmor))
	replay, _ := r.(restartable)

	block, err := decodeArmor(r, replay, Armor, "gopenpgp: unarmor failed")
	require.Error(t, err)
	assert.Nil(t, block)
}

// TestKeyAutoFallsBackToBinary is the key-parsing side of the fallback. It
// feeds input detected as armored that cannot be an armored key ring; Auto must
// rewind and retry the binary reader. Because the malformed content is not a
// valid binary key either, both Auto and Bytes fail — but Auto must fail with
// the binary parser's error rather than the armor hard error, proving the
// fallback branch was taken.
func TestKeyAutoFallsBackToBinary(t *testing.T) {
	_, autoErr := NewKeyFromReaderExplicit(strings.NewReader(malformedArmor), Auto)
	require.Error(t, autoErr)
	assert.Contains(t, autoErr.Error(), "error in reading key ring")

	_, bytesErr := NewKeyFromReaderExplicit(strings.NewReader(malformedArmor), Bytes)
	require.Error(t, bytesErr)
	// Auto and Bytes now reach the same binary parser, so their errors match.
	assert.Equal(t, bytesErr.Error(), autoErr.Error())

	// Explicit Armor must still surface the armor decode hard error.
	_, armorErr := NewKeyFromReaderExplicit(strings.NewReader(malformedArmor), Armor)
	require.Error(t, armorErr)
}

// --- Binary fallback: end-to-end parity for a valid binary signature ---

// TestAutoBinarySignatureParity is the false-positive acceptance case at the
// behavioral level. A real binary detached signature (whose bytes may contain
// arbitrary octets, including ASCII substrings) verifies identically under Auto
// and explicit Bytes, and Auto never routes it through the armor decoder.
func TestAutoBinarySignatureParity(t *testing.T) {
	data := []byte(signedPlainText)
	binSig, err := testSigner().Sign(data, Bytes)
	require.NoError(t, err)

	_, detected := armorHelper.IsPGPArmored(bytes.NewReader(append([]byte{}, binSig...)))
	assert.False(t, detected, "a real binary signature has no armor header line")

	autoResult, err := testVerifier().VerifyDetached(data, binSig, Auto)
	require.NoError(t, err)
	assert.NoError(t, autoResult.SignatureError())

	bytesResult, err := testVerifier().VerifyDetached(data, binSig, Bytes)
	require.NoError(t, err)
	assert.NoError(t, bytesResult.SignatureError())
}

// TestAutoBinarySignatureContainingArmorWord keeps the word "armor"/marker
// inside a non-header line: detection stays binary and Auto matches Bytes even
// though the literal marker bytes are present.
func TestAutoBinarySignatureContainingArmorWord(t *testing.T) {
	data := []byte(signedPlainText)
	binSig, err := testSigner().Sign(data, Bytes)
	require.NoError(t, err)

	// A line containing the marker but missing the closing "-----" is not a
	// valid header line, so detection stays binary.
	payload := append([]byte("binary prefix -----BEGIN PGP SIGNATURE garbage\n"), binSig...)
	_, detected := armorHelper.IsPGPArmored(bytes.NewReader(payload))
	assert.False(t, detected, "marker without a full header line must not be detected as armor")

	_, autoErr := testVerifier().VerifyDetached(data, payload, Auto)
	_, bytesErr := testVerifier().VerifyDetached(data, payload, Bytes)
	// The leading text makes this invalid binary too; the contract is parity
	// between Auto and Bytes, not that arbitrary garbage parses.
	assert.Equal(t, bytesErr != nil, autoErr != nil)
}

// --- Baselines: no preamble and pure binary must not regress ---

func TestAutoBaselinesNoRegression(t *testing.T) {
	data := []byte(signedPlainText)

	// Baseline 1: plain armored key with no preamble.
	referenceKey := keyRingTestPrivate.GetKeys()[0]
	armoredKey, err := referenceKey.Armor()
	require.NoError(t, err)
	keyFromArmored, err := NewKeyFromReader(bytes.NewReader([]byte(armoredKey)))
	require.NoError(t, err)
	assert.Equal(t, referenceKey.GetFingerprint(), keyFromArmored.GetFingerprint())

	// Baseline 2: pure binary detached signature under Auto and Bytes agree.
	binSig, err := testSigner().Sign(data, Bytes)
	require.NoError(t, err)
	autoResult, err := testVerifier().VerifyDetached(data, binSig, Auto)
	require.NoError(t, err)
	assert.NoError(t, autoResult.SignatureError())

	bytesResult, err := testVerifier().VerifyDetached(data, binSig, Bytes)
	require.NoError(t, err)
	assert.NoError(t, bytesResult.SignatureError())

	// Baseline 3: pure binary encrypted message under Auto decrypts.
	encHandle, err := testPGP.Encryption().
		Recipients(keyRingTestPublic).
		New()
	require.NoError(t, err)
	binMessage, err := encHandle.Encrypt([]byte(testMessage))
	require.NoError(t, err)
	decHandle, err := testPGP.Decryption().
		DecryptionKeys(keyRingTestPrivate).
		New()
	require.NoError(t, err)
	decrypted, err := decHandle.Decrypt(binMessage.Bytes(), Auto)
	require.NoError(t, err)
	assert.Equal(t, testMessage, string(decrypted.Bytes()))
}
