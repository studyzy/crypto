package ecdsa

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/studyzy/crypto/elliptic"
	"github.com/studyzy/crypto/internal/sm2"
)

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

type ecdsaSignature struct {
	R, S *big.Int
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Sign signs digest with priv, reading randomness from rand. The opts argument
// is not currently used but, in keeping with the crypto.Signer interface,
// should be the hash function used to digest the message.
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses should use the Sign function in this package directly.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sign(rand, priv, digest)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

func (priv *PrivateKey) ToGmPrivateKey() *sm2.PrivateKey {
	return &sm2.PrivateKey{
		*priv.PublicKey.ToGmPublicKey(),
		priv.D,
	}
}
func (pub *PublicKey) ToGmPublicKey() *sm2.PublicKey {
	return &sm2.PublicKey{
		pub.Curve, pub.X, pub.Y,
	}
}

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	key, err := sm2.GenerateKey()
	return &PrivateKey{
		PublicKey: PublicKey{c, key.X, key.Y},
		D:         key.D,
	}, err
}

var errZeroParam = errors.New("zero parameter")

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	return sm2.Sign(priv.ToGmPrivateKey(), hash)
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	return sm2.Verify(pub.ToGmPublicKey(), hash, r, s)
}

//
//type zr struct {
//	io.Reader
//}
//
//// Read replaces the contents of dst with zeros.
//func (z *zr) Read(dst []byte) (n int, err error) {
//	for i := range dst {
//		dst[i] = 0
//	}
//	return len(dst), nil
//}
//
//var zeroReader = &zr{}
