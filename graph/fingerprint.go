package graph

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type Fingerprint [sha256.Size]byte

// print fingerprint as hex
func (fp *Fingerprint) HexString() string {
	return fmt.Sprintf("%X", fp)
}

func FingerprintFromB64(hash string) Fingerprint {
	var fp Fingerprint
	data, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		v(err)
	}
	if len(data) != sha256.Size {
		v("Hash is not correct SHA256 size", hash)
	}
	for i := 0; i < len(data) && i < len(fp); i++ {
		fp[i] = data[i]
	}
	return fp
}

func (fp *Fingerprint) B64Encode() string {
	return base64.StdEncoding.EncodeToString(fp[:])
}
