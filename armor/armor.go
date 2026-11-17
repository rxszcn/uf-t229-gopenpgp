// Package armor contains a set of helper methods for armoring and unarmoring
// data.
package armor

import (
	"bufio"
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
)

// ArmorKey armors input as a public key.
func ArmorKey(input []byte) (string, error) {
	return ArmorWithType(input, constants.PublicKeyHeader)
}

// ArmorWriterWithType returns a io.WriteCloser which, when written to, writes
// armored data to w with the given armorType.
func ArmorWriterWithType(w io.Writer, armorType string) (io.WriteCloser, error) {
	return armor.EncodeWithChecksumOption(w, armorType, internal.ArmorHeaders, constants.ArmorChecksumEnabled)
}

// ArmorWriterWithTypeChecksum returns a io.WriteCloser which, when written to, writes
// armored data to w with the given armorType.
// The checksum determines if an armor checksum is written at the end.
func ArmorWriterWithTypeChecksum(w io.Writer, armorType string, checksum bool) (io.WriteCloser, error) {
	return armor.EncodeWithChecksumOption(w, armorType, internal.ArmorHeaders, checksum)
}

// ArmorWriterWithTypeAndCustomHeaders returns a io.WriteCloser,
// which armors input with the given armorType and headers.
func ArmorWriterWithTypeAndCustomHeaders(w io.Writer, armorType, version, comment string) (io.WriteCloser, error) {
	headers := make(map[string]string)
	if version != "" {
		headers["Version"] = version
	}
	if comment != "" {
		headers["Comment"] = comment
	}
	return armor.EncodeWithChecksumOption(w, armorType, headers, constants.ArmorChecksumEnabled)
}

// ArmorWithType armors input with the given armorType.
func ArmorWithType(input []byte, armorType string) (string, error) {
	return ArmorWithTypeChecksum(input, armorType, constants.ArmorChecksumEnabled)
}

// ArmorWithTypeChecksum armors input with the given armorType.
// The checksum option determines if an armor checksum is written at the end.
func ArmorWithTypeChecksum(input []byte, armorType string, checksum bool) (string, error) {
	buffer, err := armorWithTypeAndHeaders(input, armorType, internal.ArmorHeaders, checksum)
	if err != nil {
		return "", err
	}
	return buffer.String(), err
}

// ArmorWithTypeBytes armors input with the given armorType.
func ArmorWithTypeBytes(input []byte, armorType string) ([]byte, error) {
	return ArmorWithTypeBytesChecksum(input, armorType, constants.ArmorChecksumEnabled)
}

// ArmorWithTypeBytesChecksum armors input with the given armorType and checksum option.
func ArmorWithTypeBytesChecksum(input []byte, armorType string, checksum bool) ([]byte, error) {
	buffer, err := armorWithTypeAndHeaders(input, armorType, internal.ArmorHeaders, checksum)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), err
}

// ArmorWithTypeAndCustomHeaders armors input with the given armorType and
// headers.
func ArmorWithTypeAndCustomHeaders(input []byte, armorType, version, comment string) (string, error) {
	return ArmorWithTypeAndCustomHeadersChecksum(input, armorType, version, comment, constants.ArmorChecksumEnabled)
}

// ArmorWithTypeAndCustomHeadersChecksum armors input with the given armorType and
// headers and checksum option.
func ArmorWithTypeAndCustomHeadersChecksum(input []byte, armorType, version, comment string, checksum bool) (string, error) {
	headers := make(map[string]string)
	if version != "" {
		headers["Version"] = version
	}
	if comment != "" {
		headers["Comment"] = comment
	}
	buffer, err := armorWithTypeAndHeaders(input, armorType, headers, checksum)
	if err != nil {
		return "", err
	}
	return buffer.String(), err
}

// ArmorWithTypeAndCustomHeadersBytes armors input with the given armorType and
// headers.
func ArmorWithTypeAndCustomHeadersBytes(input []byte, armorType, version, comment string) ([]byte, error) {
	headers := make(map[string]string)
	if version != "" {
		headers["Version"] = version
	}
	if comment != "" {
		headers["Comment"] = comment
	}
	buffer, err := armorWithTypeAndHeaders(input, armorType, headers, constants.ArmorChecksumEnabled)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), err
}

// ArmorReader returns a io.Reader which, when read, reads
// unarmored data from in.
func ArmorReader(in io.Reader) (io.Reader, error) {
	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}
	return block.Body, nil
}

// Unarmor unarmors an armored input into a byte array.
func Unarmor(input string) ([]byte, error) {
	b, err := internal.Unarmor(input)
	if err != nil {
		return nil, fmt.Errorf("armor: unable to unarmor: %w", err)
	}
	return io.ReadAll(b.Body)
}

// UnarmorBytes unarmors an armored input into a byte array.
func UnarmorBytes(input []byte) ([]byte, error) {
	b, err := internal.UnarmorBytes(input)
	if err != nil {
		return nil, fmt.Errorf("armor: unable to unarmor: %w", err)
	}
	return io.ReadAll(b.Body)
}

func ArmorPGPSignatureBinary(signature []byte) ([]byte, error) {
	return ArmorWithTypeBytes(signature, constants.PGPSignatureHeader)
}

func ArmorPGPSignature(signature []byte) (string, error) {
	return ArmorWithType(signature, constants.PGPSignatureHeader)
}

func ArmorPGPMessageBytes(signature []byte) ([]byte, error) {
	return ArmorWithTypeBytes(signature, constants.PGPMessageHeader)
}

func ArmorPGPMessage(signature []byte) (string, error) {
	return ArmorWithType(signature, constants.PGPMessageHeader)
}

func ArmorPGPMessageBytesChecksum(signature []byte, checksum bool) ([]byte, error) {
	return ArmorWithTypeBytesChecksum(signature, constants.PGPMessageHeader, checksum)
}

func ArmorPGPMessageChecksum(signature []byte, checksum bool) (string, error) {
	return ArmorWithTypeChecksum(signature, constants.PGPMessageHeader, checksum)
}

// armorPrefix is the opening of an OpenPGP armor header line,
// e.g. "-----BEGIN PGP SIGNATURE-----".
const armorPrefix = "-----BEGIN PGP"
const armorSuffix = "-----"

// replayableReader replays every byte that has already been consumed from the
// wrapped reader before serving further bytes from it. Restart rewinds to the
// very first byte, which allows a failed armor decoding to be retried as a
// binary parse without consuming the underlying reader twice.
//
// pos always tracks the logical read position. Bytes read ahead by the
// buffering scanner are already stored in buf, so they are replayed correctly
// after a Restart.
type replayableReader struct {
	in io.Reader
	// buf holds every byte read so far, including bytes read ahead by the
	// buffering scanner. pos is the logical read position within buf.
	buf []byte
	pos int
}

func (r *replayableReader) Read(p []byte) (int, error) {
	// Replay buffered bytes first, including data read ahead before Restart.
	if r.pos < len(r.buf) {
		n := copy(p, r.buf[r.pos:])
		r.pos += n
		return n, nil
	}
	n, err := r.in.Read(p)
	if n > 0 {
		r.buf = append(r.buf, p[:n]...)
		r.pos += n
	}
	return n, err
}

// Restart makes subsequent reads start again from the first byte of the stream.
func (r *replayableReader) Restart() {
	r.pos = 0
}

// IsPGPArmored inspects the reader and checks whether it carries a PGP armored
// message, tolerating an arbitrary-length leading preamble (e.g. mail gateway
// quote text) before the armor header.
//
// Detection is structural rather than a fixed-window substring search: it scans
// line by line for a full "-----BEGIN PGP ...-----" header line, mirroring the
// parsing rule of the underlying armor decoder. This both removes the previous
// 128-byte preamble limit and avoids misclassifying binary data that merely
// happens to contain the armor marker bytes.
//
// It returns an io.Reader that yields the complete, unconsumed input, and a bool
// that indicates if an armor header was found. If the returned reader was
// produced by this function, it additionally implements
//
//	interface{ Restart() }
//
// which rewinds it to the first byte so that callers can fall back to binary
// parsing after a failed armor decode. If reading from the reader fails, the
// returned bool is set to false.
func IsPGPArmored(in io.Reader) (io.Reader, bool) {
	replay := &replayableReader{in: in}
	scanner := bufio.NewReader(replay)
	for {
		line, err := scanner.ReadBytes('\n')
		if len(line) > 0 && isArmorHeaderLine(line) {
			// Rewind the logical position: the buffering scanner has read
			// ahead into replay.buf, and the caller must see the full input
			// from its first byte. Restart can rewind again later.
			replay.Restart()
			return replay, true
		}
		if err != nil {
			// No armor header before EOF (or a read error): treat the whole
			// input as binary. The buffered bytes are still replayed verbatim.
			replay.Restart()
			return replay, false
		}
	}
}

// isArmorHeaderLine reports whether line, a single line including its trailing
// newline, is a full OpenPGP armor header line such as
// "-----BEGIN PGP MESSAGE-----\n".
func isArmorHeaderLine(line []byte) bool {
	line = bytes.TrimSpace(line)
	return bytes.HasPrefix(line, []byte(armorPrefix)) &&
		bytes.HasSuffix(line, []byte(armorSuffix)) &&
		len(line) > len(armorPrefix)+len(armorSuffix)
}

func armorWithTypeAndHeaders(input []byte, armorType string, headers map[string]string, writeChecksum bool) (*bytes.Buffer, error) {
	var b bytes.Buffer

	w, err := armor.EncodeWithChecksumOption(&b, armorType, headers, writeChecksum)

	if err != nil {
		return nil, fmt.Errorf("armor: unable to encode armoring: %w", err)
	}
	if _, err = w.Write(input); err != nil {
		return nil, fmt.Errorf("armor: unable to write armored to buffer: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("armor: unable to close armor buffer: %w", err)
	}
	return &b, nil
}
