// Package fingerprint defines types to define a certificate fingerprint for certgraph
package fingerprint

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Fingerprint represents a SHA-256 hash of certificate bytes.
// Used as a unique identifier for certificates throughout certgraph.
type Fingerprint [sha256.Size]byte

// HexString returns the fingerprint as an uppercase hexadecimal string.
// Used for display and comparison purposes.
func (fp *Fingerprint) HexString() string {
	return fmt.Sprintf("%X", *fp)
}

// FromHashBytes creates a Fingerprint from raw hash bytes.
// Copies up to Fingerprint length bytes from the provided data.
func FromHashBytes(data []byte) Fingerprint {
	var fp Fingerprint
	// if len(data) != len(fp) {
	// 	// TODO this should error....
	// }
	for i := 0; i < len(data) && i < len(fp); i++ {
		fp[i] = data[i]
	}
	return fp
}

// FromRawCertBytes computes a SHA-256 fingerprint from raw certificate bytes.
// This is the primary method for generating fingerprints from certificates.
func FromRawCertBytes(data []byte) Fingerprint {
	fp := sha256.Sum256(data)
	return fp
}

// FromB64Hash creates a Fingerprint from a base64-encoded hash string.
// Returns an error if the base64 decoding fails.
func FromB64Hash(hash string) (Fingerprint, error) {
	data, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return Fingerprint{}, err
	}
	return FromHashBytes(data), nil
}

// FromHexHash creates a Fingerprint from a hexadecimal-encoded hash string.
// Returns an error if the hex decoding fails.
func FromHexHash(hash string) (Fingerprint, error) {
	decoded, err := hex.DecodeString(hash)
	if err != nil {
		return Fingerprint{}, err
	}
	return FromHashBytes(decoded), nil
}

// B64Encode returns the fingerprint as a base64-encoded string.
// Used for API communication and storage where base64 encoding is preferred.
func (fp *Fingerprint) B64Encode() string {
	return base64.StdEncoding.EncodeToString(fp[:])
}
