package rsapkcs1v15

import (
	"bytes"
	"crypto/rand"
	stdsha1 "crypto/sha1"
	"math/big"

	"github.com/pkg/errors"
)

// PublicKey represents an RSA public key.
type PublicKey struct {
	N *big.Int
	E int
}

// PrivateKey represents an RSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
	P *big.Int
	Q *big.Int
}

// GenerateKey generates an RSA private key with the given modulus size (in bits).
func GenerateKey(bits int) (*PrivateKey, error) {
	if bits < RSAKeyBitsMin {
		return nil, errors.Wrapf(ErrInvalidKey, "bits must be >= %d", RSAKeyBitsMin)
	}

	e := big.NewInt(RSADefaultPublicExponent)

	for {
		p, err := rand.Prime(rand.Reader, bits/intTwo)
		if err != nil {
			return nil, errors.Wrap(err, "generate prime p")
		}

		q, err := rand.Prime(rand.Reader, bits/intTwo)
		if err != nil {
			return nil, errors.Wrap(err, "generate prime q")
		}

		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		pMinus1 := new(big.Int).Sub(p, big.NewInt(int64One))
		qMinus1 := new(big.Int).Sub(q, big.NewInt(int64One))
		phi := new(big.Int).Mul(pMinus1, qMinus1)

		if new(big.Int).GCD(nil, nil, e, phi).Cmp(big.NewInt(int64One)) != 0 {
			continue
		}

		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}

		return &PrivateKey{
			PublicKey: PublicKey{
				N: n,
				E: RSADefaultPublicExponent,
			},
			D: d,
			P: p,
			Q: q,
		}, nil
	}
}

// SignSHA1 signs message using RSA PKCS#1 v1.5 with SHA-1.
// The signature length equals the modulus size in bytes.
func SignSHA1(priv *PrivateKey, message []byte) ([]byte, error) {
	if priv == nil || priv.N == nil || priv.D == nil || priv.E <= 0 {
		return nil, errors.Wrap(ErrInvalidKey, "nil or incomplete private key")
	}

	k := modulusSizeBytes(priv.N)
	h := stdsha1.Sum(message)

	em, err := emsaPKCS1v15EncodeSHA1(h[:], k)
	if err != nil {
		return nil, errors.Wrap(err, "encode message")
	}

	m := os2ip(em)
	s := new(big.Int).Exp(m, priv.D, priv.N)
	out, err := i2osp(s, k)
	return out, errors.Wrap(err, "serialize signature")
}

// VerifySHA1 verifies an RSA PKCS#1 v1.5 signature over message using SHA-1.
func VerifySHA1(pub *PublicKey, message, signature []byte) error {
	if pub == nil || pub.N == nil || pub.E <= 0 {
		return errors.Wrap(ErrInvalidKey, "nil or incomplete public key")
	}

	k := modulusSizeBytes(pub.N)
	if len(signature) != k {
		return errors.Wrapf(ErrInvalidSignature, "signature length mismatch: got %d want %d", len(signature), k)
	}

	s := os2ip(signature)
	if s.Cmp(pub.N) >= 0 {
		return errors.Wrap(ErrInvalidSignature, "signature representative out of range")
	}

	m := new(big.Int).Exp(s, big.NewInt(int64(pub.E)), pub.N)
	em, err := i2osp(m, k)
	if err != nil {
		return errors.Wrap(ErrInvalidSignature, "invalid encoded message size")
	}

	h := stdsha1.Sum(message)
	expected, err := emsaPKCS1v15EncodeSHA1(h[:], k)
	if err != nil {
		return errors.Wrap(err, "encode expected message")
	}

	if !bytes.Equal(em, expected) {
		return errors.Wrap(ErrInvalidSignature, "verification failed")
	}

	return nil
}

func emsaPKCS1v15EncodeSHA1(digest []byte, emLen int) ([]byte, error) {
	tLen := len(sha1DigestInfoPrefix) + len(digest)
	if emLen < tLen+pkcs1v15OverheadBytes+pkcs1v15MinPaddingLen {
		return nil, errors.Wrap(ErrInvalidKey, "intended encoded message length too short")
	}

	psLen := emLen - tLen - pkcs1v15OverheadBytes
	if psLen < pkcs1v15MinPaddingLen {
		return nil, errors.Wrap(ErrInvalidKey, "padding too short")
	}

	em := make([]byte, 0, emLen)
	em = append(em, pkcs1v15PrefixFirstByte, pkcs1v15PrefixSecondByte)

	for i := 0; i < psLen; i++ {
		em = append(em, pkcs1v15PaddingByte)
	}

	em = append(em, pkcs1v15SeparatorByte)
	em = append(em, sha1DigestInfoPrefix...)
	em = append(em, digest...)
	return em, nil
}

func modulusSizeBytes(n *big.Int) int {
	return (n.BitLen() + bitsInByte - intOne) / bitsInByte
}

func os2ip(in []byte) *big.Int {
	return new(big.Int).SetBytes(in)
}

func i2osp(x *big.Int, size int) ([]byte, error) {
	if x.Sign() < 0 {
		return nil, errors.Wrap(ErrInvalidSignature, "negative integer")
	}

	b := x.Bytes()
	if len(b) > size {
		return nil, errors.Wrap(ErrInvalidSignature, "integer too large")
	}

	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out, nil
}
