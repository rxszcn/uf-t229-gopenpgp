package crypto

import (
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	armorHelper "github.com/ProtonMail/gopenpgp/v3/armor"
)

type PGPEncoding int8

// PGPEncoding determines the message encoding.
// The type is int8 for compatibility with gomobile.
const (
	Armor int8 = 0
	Bytes int8 = 1 // Default for other int8 values.
	Auto  int8 = 2
)

func armorOutput(e int8) bool {
	return e == Armor
}

// restartable is implemented by the reader returned from automatic armor
// detection. Restart rewinds it to the first byte of the original input.
type restartable interface {
	Restart()
}

// unarmorInput decides whether the input is armored.
//
// For Auto encoding the reader is produced by armor detection and, when
// detection matched, additionally supports Restart. This lets the caller fall
// back to a binary parse when the data looked armored structurally but the
// armor decoder rejects it, instead of returning a hard error.
func unarmorInput(e int8, input io.Reader) (reader Reader, unarmor bool, replay restartable) {
	reader = input
	switch e {
	case Armor:
		unarmor = true
	case Auto:
		reader, unarmor = armorHelper.IsPGPArmored(input)
		if unarmor {
			// IsPGPArmored documents that the reader it returns implements
			// Restart when it detects an armor header.
			replay, _ = reader.(restartable)
		}
	}
	return
}

// decodeArmor decodes an armor block from input.
//
// In Auto mode a failed armor decode is treated as a detection false positive:
// the reader is rewound and (nil, nil) is returned so that the caller retries
// with the binary parser, matching the behavior of explicitly selecting Bytes.
// In explicit Armor mode a decode failure is genuine corrupt armor data and is
// returned as an error. errContext prefixes the error message.
func decodeArmor(input Reader, replay restartable, encoding int8, errContext string) (*armor.Block, error) {
	block, err := armor.Decode(input)
	if err == nil {
		return block, nil
	}
	if encoding != Auto || replay == nil {
		return nil, fmt.Errorf("%s: %w", errContext, err)
	}
	// False-positive armor detection: the binary data merely looked like an
	// armor header. Rewind and let the binary parser handle the original input.
	replay.Restart()
	return nil, nil
}
