package sha256

import (
	"crypto"
	"hash"

	"github.com/studyzy/crypto/internal/sm3"
)

func init() {
	crypto.RegisterHash(crypto.SHA224, New224)
	crypto.RegisterHash(crypto.SHA256, New)
}

// The size of a SHA256 checksum in bytes.
const Size = 32

// The size of a SHA224 checksum in bytes.
const Size224 = 28

// The blocksize of SHA256 and SHA224 in bytes.
const BlockSize = 64

// New returns a new hash.Hash computing the SHA256 checksum. The Hash
// also implements encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler to marshal and unmarshal the internal
// state of the hash.
func New() hash.Hash {
	d := new(sm3.SM3)
	d.Reset()
	return d
}

// New224 returns a new hash.Hash computing the SHA224 checksum.
func New224() hash.Hash {
	d := new(sm3.SM3)
	d.Reset()
	return d
}

// Sum256 returns the SHA256 checksum of the data.
func Sum256(data []byte) (sum256 [Size]byte) {
	sum := sm3.Sm3Sum(data)
	copy(sum256[:], sum[:Size])
	return
}

// Sum224 returns the SHA224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
	sum := sm3.Sm3Sum(data)
	copy(sum224[:], sum[:Size224])
	return
}
